#include "ndnmps/initiator.hpp"
#include "ndnmps/crypto-helpers.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <utility>
#include <future>
#include <array>
#include <iostream>

namespace ndn {
namespace mps {

NDN_LOG_INIT(ndnmps.mpsinitiator);

void
onNack(const Interest& interest, const lp::Nack& nack, const SignatureFailureCallback& failureCb)
{
  NDN_LOG_ERROR("Received NACK with reason " << nack.getReason() << " for " << interest.getName());
  failureCb("Received NACK with reason " + std::to_string(static_cast<int>(nack.getReason())) + " for " +
            interest.getName().toUri());
}

void
onTimeout(const Interest& interest, const SignatureFailureCallback& failureCb)
{
  NDN_LOG_ERROR("interest time out for " << interest.getName());
  failureCb("interest time out for " + interest.getName().toUri());
}

MPSInitiator::MPSInitiator(const Name& prefix, KeyChain& keyChain, Face& face, Scheduler& scheduler)
  : m_prefix(prefix)
    , m_keyChain(keyChain)
    , m_face(face)
    , m_scheduler(scheduler)
    , m_interestSigner(m_keyChain)
{}

struct MultiSignGlobalState
{
  MpsSignerList m_signers;
  Data m_toBeSigned;
  Data m_signInfo;
  std::vector<Buffer> m_fetchedSignatures;
};

struct MultiSignPerSignerState
{
  ECDHState m_ecdh;
  std::promise<Data> m_paraDataPromise;
  std::array<uint8_t, 16> m_aesKey;
  security::SigningInfo m_hmacSigningInfo;
  Data m_paraData;
  Name m_nextResultName;
  RegisteredPrefixHandle m_paraPrefixHandle;
  scheduler::EventId m_resultFetchHandle;
  std::function<void()> m_resultFetchCallback;
};

std::tuple<Data, Data>
prepareUnfinishedDataAndInfoData(const Data& unsignedData, const Name& initiatorPrefix)
{
  auto keyLocatorRandomness = random::generateSecureWord64();
  Name keyLocatorName = initiatorPrefix;
  keyLocatorName.append("mps").appendNumber(keyLocatorRandomness);

  Data unfinishedData(unsignedData);
  unfinishedData.setSignatureInfo(
    SignatureInfo(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
                  KeyLocator(keyLocatorName)));
  unfinishedData.setSignatureValue(make_shared<Buffer>());  // placeholder sig value for wireEncode

  Data sigInfoData(keyLocatorName);
  return std::make_tuple(unfinishedData, sigInfoData);
}

Data
prepareParameterData(const Data& unfinishedData, const Name& initiatorPrefix)
{
  auto paraRandomness = random::generateSecureWord64();
  Name paraDataName = initiatorPrefix;
  paraDataName.append("mps").append("param").appendNumber(paraRandomness);
  Data paraData;  // /initiator/mps/para/[random]
  paraData.setName(paraDataName);
  paraData.setContent(unfinishedData.wireEncode());
  paraData.setFreshnessPeriod(time::seconds(4));
  return paraData;
}

Interest
prepareSignRequestInterest(const Name& signerPrefix, const Name& paraDataName, const std::vector<uint8_t>& selfPubKey)
{
  Interest signRequestInt;
  auto signRequestName = signerPrefix;
  signRequestName.append("mps").append("sign");
  signRequestInt.setName(signRequestName);
  Block appParam(ndn::tlv::ApplicationParameters);
  appParam.push_back(makeNestedBlock(tlv::ParameterDataName, paraDataName));
  appParam.push_back(makeBinaryBlock(tlv::EcdhPub, selfPubKey.data(), selfPubKey.size()));
  appParam.encode();
  signRequestInt.setApplicationParameters(appParam);
  signRequestInt.setCanBePrefix(false);
  signRequestInt.setMustBeFresh(true);
  return signRequestInt;
}

void
parseAckReply(const Data& data, std::string& ackCode, time::milliseconds& result_ms, Name& resultName,
              std::shared_ptr<MultiSignPerSignerState> perSignerState)
{
  std::vector<uint8_t> peerPub;
  std::array<uint8_t, 32> salt;
  auto contentBlock = data.getContent();
  contentBlock.parse();
  ackCode = readString(contentBlock.get(tlv::Status));
  if (ackCode == "102") {
    const auto& ecdhBlock = contentBlock.get(tlv::EcdhPub);
    peerPub.resize(ecdhBlock.value_size());
    std::memcpy(peerPub.data(), ecdhBlock.value(), ecdhBlock.value_size());

    const auto& saltBlock = contentBlock.get(tlv::Salt);
    std::memcpy(salt.data(), saltBlock.value(), saltBlock.value_size());
  }
  else {
    NDN_THROW(std::runtime_error("Rejected by the signer with Error code" + ackCode));
  }
  // ECDH and generate HMAC KEY and AES KEY
  auto dhSecret = perSignerState->m_ecdh.deriveSecret(peerPub);
  std::array<uint8_t, 48> aesAndHmac;
  hkdf(dhSecret.data(), dhSecret.size(), salt.data(), salt.size(), aesAndHmac.data(), aesAndHmac.size());
  std::memcpy(perSignerState->m_aesKey.data(), aesAndHmac.data(), 16);
  auto hmacKeyStr = base64EncodeFromBytes(aesAndHmac.data() + 16, 32, false);
  // HMAC
  perSignerState->m_hmacSigningInfo.setSigningHmacKey(hmacKeyStr);
  perSignerState->m_hmacSigningInfo.setDigestAlgorithm(DigestAlgorithm::SHA256);
  perSignerState->m_hmacSigningInfo.setSignedInterestFormat(security::SignedInterestFormat::V03);
  // Decrypt
  Block decrypteBlock(ndn::tlv::Content,
                      std::make_shared<Buffer>(decodeBlockWithAesGcm128(contentBlock,
                                                                        perSignerState->m_aesKey.data(),
                                                                        nullptr, 0)));
  decrypteBlock.parse();
  result_ms = time::milliseconds(readNonNegativeInteger(decrypteBlock.get(tlv::ResultAfter)));
  resultName.wireDecode(decrypteBlock.get(tlv::ResultName).blockFromValue());
  std::cout << "result name: " << resultName.toUri() << std::endl;
}

Block
parseResultData(const Data& data, std::shared_ptr<MultiSignPerSignerState> perSignerState)
{
  auto contentBlock = data.getContent();
  contentBlock.parse();
  auto decryptedBuf = decodeBlockWithAesGcm128(contentBlock, perSignerState->m_aesKey.data(), nullptr, 0);
  auto decryptedBlock = makeBinaryBlock(ndn::tlv::Content, decryptedBuf.data(), decryptedBuf.size());
  decryptedBlock.parse();
  return decryptedBlock;
}

void
MPSInitiator::performRPC(const Name& signerKeyName, const Name& signingKeyName,
                         const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb,
                         std::shared_ptr<MultiSignGlobalState> globalState)
{
  auto perSignerState = std::make_shared<MultiSignPerSignerState>();
  // prepare un-encrypted parameter data
  perSignerState->m_paraData = prepareParameterData(globalState->m_toBeSigned, m_prefix);
  // prepare a future for finalized parameter data
  std::shared_future<Data> paraDataFuture(perSignerState->m_paraDataPromise.get_future());
  // register prefix to answer future parameter data
  perSignerState->m_paraPrefixHandle = m_face.setInterestFilter(
    perSignerState->m_paraData.getName(),
    [paraDataFuture, this](const auto&,
                           const auto& interest) mutable
    {
      std::cout << "\n\nInitiator: Receive Interest for parameter Data from signer." << std::endl;
      paraDataFuture.wait();
      m_face.put(paraDataFuture.get());
    },
    nullptr,
    [](const Name& prefix, const std::string& reason)
    {
      NDN_LOG_ERROR("Fail to register prefix " << prefix.toUri() << " because " << reason);
    });
  // TODO: schedule an event for failure callback

  // send sign request Interest: /signer/mps/sign/hash
  auto signRequestInt = prepareSignRequestInterest(signerKeyName.getPrefix(-2),
                                                   perSignerState->m_paraData.getName(),
                                                   perSignerState->m_ecdh.getSelfPubKey());
  m_interestSigner.makeSignedInterest(signRequestInt, signingByKey(signingKeyName));
  std::cout << "\n\nInitiator: Send MPS Sign Interest to signer: " << signerKeyName.getPrefix(-2).toUri() << std::endl;
  m_face.expressInterest(
    signRequestInt,
    [=, &successCb, &failureCb, &signingKeyName](const auto&, const auto& ackData)
    {
      std::cout << "\n\nInitiator: Fetched ACK Data from signer: "
                << ackData.getName().getPrefix(-3).toUri()
                << std::endl << ackData;

      // parse ack content
      std::string ackCode;
      time::milliseconds result_ms;
      try {
        parseAckReply(ackData, ackCode, result_ms, perSignerState->m_nextResultName, perSignerState);
      }
      catch (const std::exception& e) {
        // should abort and change to another signer
        std::cout << e.what() << std::endl;
        return;
      }
      // update paraData to be ready to be fetched
      const auto& unencryptedBlock = perSignerState->m_paraData.getContent();
      auto encryptedBlock = encodeBlockWithAesGcm128(ndn::tlv::Content,
                                                     perSignerState->m_aesKey.data(),
                                                     unencryptedBlock.value(),
                                                     unencryptedBlock.value_size(),
                                                     nullptr, 0);
      perSignerState->m_paraData.setContent(encryptedBlock);
      m_keyChain.sign(perSignerState->m_paraData, perSignerState->m_hmacSigningInfo);
      perSignerState->m_paraDataPromise.set_value(perSignerState->m_paraData);
      std::cout << "Initiator: Register prefix for parameter data: "
                << perSignerState->m_paraData.getName().toUri() << std::endl;

      // set the scheduler to fetch the result
      perSignerState->m_resultFetchCallback = [=, &successCb, &failureCb, &signingKeyName]()
      {
        std::cout << "\n\nInitiator: Send Interest for result Data from signer: "
                  << perSignerState->m_nextResultName.getPrefix(-3).toUri() << std::endl;
        perSignerState->m_paraPrefixHandle.cancel();
        Interest resultFetchInt(perSignerState->m_nextResultName);
        resultFetchInt.setCanBePrefix(true);
        resultFetchInt.setMustBeFresh(true);
        m_interestSigner.makeSignedInterest(resultFetchInt, signingByKey(signingKeyName));
        m_face.expressInterest(
          resultFetchInt,
          [=, &successCb, &failureCb, &signingKeyName](const auto&, const auto& resultData)
          {
            auto signerPrefix = resultData.getName().getPrefix(-5);

            std::cout << "\n\nInitiator: Fetched result Data from signer: "
                      << signerPrefix.toUri() << std::endl << resultData;
            if (!security::verifySignature(resultData, m_keyChain.getTpm(),
                                          perSignerState->m_hmacSigningInfo.getSignerName(),
                                          DigestAlgorithm::SHA256)) {
              std::cout << "Initiator: HMAC verification failed" << std::endl;
              return;
            }
            auto resultContentBlock = parseResultData(resultData, perSignerState);
            auto code = readString(resultContentBlock.get(tlv::Status));
            if (code == "200") {
              auto sigBlock = resultContentBlock.get(tlv::BLSSigValue);
              globalState->m_fetchedSignatures.emplace_back(Buffer(sigBlock.value(), sigBlock.value_size()));
              if (globalState->m_fetchedSignatures.size() ==
                  globalState->m_signers.m_signers.size()) {
                // all signatures have been fetched
                auto aggSignature = std::make_shared<Buffer>(
                  ndnBLSAggregateSignature(globalState->m_fetchedSignatures));
                globalState->m_toBeSigned.setSignatureValue(aggSignature);
                globalState->m_toBeSigned.wireEncode();

                // prepare the signature info packet
                globalState->m_signInfo.setContent(globalState->m_signers.wireEncode());
                m_keyChain.sign(globalState->m_signInfo, signingByKey(signingKeyName));
                std::cout << "Initiator: info packet is ready" << std::endl;

                // end the multiparty signature
                successCb(globalState->m_toBeSigned, globalState->m_signInfo);
              }
            }
            else if (code != "102") {
              failureCb("Failure fetching signature value from the signer " + signerPrefix.toUri());
            }
            else {
              // processing
              auto result_ms = time::milliseconds(readNonNegativeInteger(resultContentBlock.get(tlv::ResultAfter)));
              Name newResultName(resultContentBlock.get(tlv::ResultName).blockFromValue());
              perSignerState->m_resultFetchHandle = m_scheduler.schedule(result_ms, perSignerState->m_resultFetchCallback);
            }
          },
          std::bind(&onNack, _1, _2, failureCb),
          std::bind(&onTimeout, _1, failureCb));
      };
      perSignerState->m_resultFetchHandle = m_scheduler.schedule(result_ms, perSignerState->m_resultFetchCallback);
    },
    std::bind(&onNack, _1, _2, failureCb),
    std::bind(&onTimeout, _1, failureCb));

}

void
MPSInitiator::multiPartySign(const Data& unsignedData, const MultipartySchema& schema, const Name& signingKeyName,
                             const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb)
{
  // init global state
  auto globalState = std::make_shared<MultiSignGlobalState>();
  // get signer list
  globalState->m_signers = m_schemaContainer.getAvailableSigners(schema);
  if (globalState->m_signers.m_signers.size() == 0) {
    failureCb("No sufficient number of known signers.");
  }
  // prepare the packet to be signed and the signature info packet
  std::tie(globalState->m_toBeSigned,
           globalState->m_signInfo) = prepareUnfinishedDataAndInfoData(unsignedData, m_prefix);

  for (const Name& signerKeyName : globalState->m_signers.m_signers) {
    // perform RPC with each signer
    performRPC(signerKeyName, signingKeyName, successCb, failureCb, globalState);
  }
}

}  // namespace mps
}  // namespace ndn