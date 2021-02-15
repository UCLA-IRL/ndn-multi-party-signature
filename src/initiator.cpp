#include "ndnmps/initiator.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <utility>
#include <future>
#include <iostream>

namespace ndn {
namespace mps {

NDN_LOG_INIT(ndnmps.mpsinitiator);

void
onNack(const Interest& interest, const lp::Nack& nack, const SignatureFailureCallback& failureCb)
{
  NDN_LOG_ERROR("Received NACK with reason " << nack.getReason() << " for " << interest.getName());
  failureCb("Received NACK with reason " + std::to_string(static_cast<int>(nack.getReason())) + " for " + interest.getName().toUri());
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

struct SignRequestState {
  int a;
};

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
prepareUnfinishedDataAndInfoData(const Data& unsignedData, const Name& initiatorPrefix)
{
  auto keyLocatorRandomness = random::generateSecureWord64();
  Name keyLocatorName = initiatorPrefix;
  keyLocatorName.append("mps").appendNumber(keyLocatorRandomness);

  auto unfinishedData = std::make_shared<Data>(unsignedData);
  unfinishedData->setSignatureInfo(
          SignatureInfo(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
                        KeyLocator(keyLocatorName)));
  unfinishedData->setSignatureValue(make_shared<Buffer>());  // placeholder sig value for wireEncode

  auto sigInfoData = std::make_shared<Data>(keyLocatorName);
  return std::make_tuple(unfinishedData, sigInfoData);
}

void
MPSInitiator::multiPartySign(const Data& unsignedData, const MultipartySchema& schema, const Name& signingKeyName,
                             const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb)
{
  auto signers = std::make_shared<MpsSignerList>(m_schemaContainer.getAvailableSigners(schema));
  // check if the schema can be satisfied with existing key storage
  if (signers->m_signers.size() == 0) {
    failureCb("Not sufficient number of known signers.");
  }

  // prepare unsigned packet and signature info packet
  std::shared_ptr<Data> unfinishedData, sigInfoData;
  std::tie(unfinishedData, sigInfoData) = prepareUnfinishedDataAndInfoData(unsignedData, m_prefix);

  // prepare cache for parameter packets and fetched signatures
  auto fetchedSignatures = std::make_shared<std::vector<Buffer>>();  // signer prefix, signature buffer
  auto finalized = std::make_shared<bool>(false);

  for (const Name& signer : signers->m_signers) {
    // prepare slot for parameter packet
    auto paraRandomness = random::generateSecureWord64();
    Name paraDataName = m_prefix;
    paraDataName.append("mps").append("param").appendNumber(paraRandomness);
    auto paraData = std::make_shared<Data>();  // /initiator/mps/para/[random]
    paraData->setName(paraDataName);
    paraData->setContent(unfinishedData->wireEncode());
    paraData->setFreshnessPeriod(time::seconds(4));
    auto isParamDataReady = std::make_shared<bool>(false);

    auto paraDataPromise = std::make_shared<std::promise<Data>>();
    std::shared_future<Data> paraDataFuture(paraDataPromise->get_future());

    auto handler = m_face.setInterestFilter(paraData->getName(),
                [paraDataFuture, this] (const auto&, const auto& interest) mutable {
                  std::cout << "\n\nInitiator: Receive Interest for parameter Data from signer." << std::endl;
                  paraDataFuture.wait();
                  m_face.put(paraDataFuture.get());
                },
                nullptr,
                [](const Name& prefix, const std::string& reason) {
                  NDN_LOG_ERROR("Fail to register prefix " << prefix.toUri() << " because " << reason);
                });
    // TODO: schedule an event for failure callback

    // send Interest
    Interest signRequestInt;
    auto signRequestName = signer.getPrefix(-2);
    signRequestName.append("mps").append("sign");
    signRequestInt.setName(signRequestName);
    Block appParam(ndn::tlv::ApplicationParameters);
    appParam.push_back(makeNestedBlock(tlv::ParameterDataName, paraDataName));
    appParam.encode();
    signRequestInt.setApplicationParameters(appParam);
    signRequestInt.setCanBePrefix(false);
    signRequestInt.setMustBeFresh(true);
    m_interestSigner.makeSignedInterest(signRequestInt, signingByKey(signingKeyName));

    std::cout << "\n\nInitiator: Send MPS Sign Interest to signer: " << signer.getPrefix(-2).toUri() << std::endl;
    m_face.expressInterest(
        signRequestInt,
        // [sigInfoData, signers, unfinishedData, paraDataPromise, paraData, fetchedSignatures, finalized, handler, this, &successCb, &failureCb, &signingKeyName](const auto&, const auto& ackData) mutable {  // after fetching the ACK data
        [=, &successCb, &failureCb, &signingKeyName] (const auto&, const auto& ackData) {
          // after fetching the ACK data
          // ack data: /signer/mps/sign/hash
          std::cout << "\n\nInitiator: Fetched ACK Data from signer: " << ackData.getName().getPrefix(-3).toUri() << std::endl;
          std::cout << ackData;

          // parse ack content
          // generate aes key and hmac key
          auto contentBlock = ackData.getContent();
          contentBlock.parse();
          time::milliseconds result_ms;
          const auto& resultAfterBlock = contentBlock.get(tlv::ResultAfter);
          if (resultAfterBlock.isValid()) {
            result_ms = time::milliseconds(readNonNegativeInteger(resultAfterBlock));
          }
          else {
            return;
          }
          Name resultName;
          resultName.wireDecode(contentBlock.get(tlv::ResultName).blockFromValue());

          // get paraData ready to be fetched
          m_keyChain.sign(*paraData, signingByKey(signingKeyName));
          paraDataPromise->set_value(*paraData);
          std::cout << "Initiator: Register prefix for parameter data: " << paraData->getName().toUri() << std::endl;

          // set the scheduler to fetch the result
          m_scheduler.schedule(result_ms,
                               // [sigInfoData, signers, unfinishedData, fetchedSignatures, finalized, resultName, handler, this, &successCb, &failureCb, &signingKeyName]() {
                              [=, &successCb, &failureCb, &signingKeyName]() {
                                 std::cout << "\n\nInitiator: Send Interest for result Data from signer: " << resultName.getPrefix(-4).toUri() << std::endl;
                                 handler.cancel();
                                 Interest resultFetchInt(resultName);
                                 resultFetchInt.setCanBePrefix(true);
                                 resultFetchInt.setMustBeFresh(true);
                                 m_interestSigner.makeSignedInterest(resultFetchInt, signingByKey(signingKeyName));
                                 m_face.expressInterest(
                                     resultFetchInt,
                                     // [sigInfoData, signers, unfinishedData, fetchedSignatures, finalized, this, &successCb, &failureCb, &signingKeyName](const auto&, const auto& resultData) {
                                       [=, &successCb, &failureCb, &signingKeyName](const auto&, const auto& resultData) {
                                       auto signerPrefix = resultData.getName().getPrefix(-5);

                                       std::cout << "\n\nInitiator: Fetched result Data from signer: " << signerPrefix.toUri() << std::endl;
                                       std::cout << resultData;

                                       auto resultContentBlock = resultData.getContent();
                                       resultContentBlock.parse();
                                       auto code = readString(resultContentBlock.get(tlv::Status));
                                       if (code == "200") {
                                         auto sigBlock = resultContentBlock.get(tlv::BLSSigValue);
                                         fetchedSignatures->emplace_back(Buffer(sigBlock.value(), sigBlock.value_size()));
                                         if (fetchedSignatures->size() == signers->m_signers.size()) {
                                           // all signatures have been fetched
                                           auto aggSignature = std::make_shared<Buffer>(ndnBLSAggregateSignature(*fetchedSignatures));
                                           unfinishedData->setSignatureValue(aggSignature);
                                           unfinishedData->wireEncode();

                                           // prepare the signature info packet
                                           sigInfoData->setContent(signers->wireEncode());
                                           m_keyChain.sign(*sigInfoData, signingByKey(signingKeyName));
                                           std::cout << "Initiator: info packet is ready" << std::endl;

                                           // end the multiparty signature
                                           successCb(*unfinishedData, *sigInfoData);
                                         }
                                       }
                                       else if (code != "102") {
                                         failureCb("Failure fetching signature value from the signer " + signerPrefix.toUri());
                                       }
                                       else {
                                         // processing
                                       }
                                     },
                                     std::bind(&onNack, _1, _2, failureCb),
                                     std::bind(&onTimeout, _1, failureCb));
                               });
        },
        std::bind(&onNack, _1, _2, failureCb),
        std::bind(&onTimeout, _1, failureCb));
  }
}

}  // namespace mps
}  // namespace ndn