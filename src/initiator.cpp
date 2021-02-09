#include "ndnmps/initiator.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <utility>

namespace ndn {
namespace mps {

NDN_LOG_INIT(ndnmps.mpsinitiator);

void
onNack(const Interest& interest, const lp::Nack& nack)
{
  NDN_LOG_ERROR("Received NACK with reason " << nack.getReason() << " for " << interest.getName());
}

void
onTimeout(const Interest& interest)
{
  NDN_LOG_ERROR("interest time out for " << interest.getName());
}

MPSInitiator::MPSInitiator(const Name& prefix, KeyChain& keyChain, Face& face, Scheduler& scheduler)
    : m_prefix(prefix)
    , m_keyChain(keyChain)
    , m_face(face)
    , m_scheduler(scheduler)
{
  Name parameterPrefix = m_prefix;
  parameterPrefix.append("mps").append("para");
  m_face.setInterestFilter(parameterPrefix,
                           std::bind(&MPSInitiator::onParameterFetch, this, _2),
                           nullptr,
                           [](const Name& prefix, const std::string& reason) {
                             NDN_LOG_ERROR("Fail to register prefix " << prefix.toUri() << " because " << reason);
                           });
}

void
MPSInitiator::multiPartySign(const Data& unsignedData, const MultipartySchema& schema, const Name& interestSigningKeyName,
                             const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb)
{
  auto signers = std::make_shared<MpsSignerList>(m_schemas.getAvailableSigners(schema));
  // check if the schema can be satisfied with existing key storage
  if (signers->m_signers.size() == 0) {
    failureCb("Not sufficient number of known signers.");
  }

  // prepare unsigned packet
  auto keyLocatorRandomness = random::generateSecureWord64();
  Name keyLocatorName = m_prefix;
  keyLocatorName.append("mps").appendNumber(keyLocatorRandomness);

  auto unfinishedData = std::make_shared<Data>(unsignedData);
  unfinishedData->setSignatureInfo(
      SignatureInfo(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
                    KeyLocator(keyLocatorName)));
  unfinishedData->setSignatureValue(make_shared<Buffer>());  // placeholder sig value for wireEncode

  // prepare cache for parameter packets and fetched signatures
  auto paraDataPackets = std::make_shared<std::vector<Data>>(); // parameter packet name, parameter Data packet
  auto fetchedSignatures = std::make_shared<std::vector<Buffer>>(); // signer prefix, signature buffer
  const size_t fetchCount = signers->m_signers.size();
  auto finalized = std::make_shared<bool>(false);

  for (const Name& signer : signers->m_signers) {
    // prepare slot for parameter packet
    auto paraRandomness = random::generateSecureWord64();
    Name paraDataName = m_prefix;
    paraDataName.append("mps").append("param").appendNumber(paraRandomness);
    Data paraData;  // /initiator/mps/para/[random]
    paraData.setName(paraDataName);
    paraData.setContent(unfinishedData->wireEncode());
    paraDataPackets->emplace_back(paraData);
    size_t offset = paraDataPackets->size() - 1;

    // send Interest
    Interest signRequestInt;
    auto signRequestName = signer.getPrefix(-2);
    signRequestName.append("mps").append("sign");
    signRequestInt.setName(signRequestName);
    Block appParam(ndn::tlv::ApplicationParameters);
    appParam.push_back(paraDataName.wireEncode());
    signRequestInt.setApplicationParameters(appParam);
    signRequestInt.setCanBePrefix(false);
    signRequestInt.setMustBeFresh(true);
    m_keyChain.sign(signRequestInt, signingByKey(interestSigningKeyName));

    m_face.expressInterest(
        signRequestInt,
        [keyLocatorName, signers, unfinishedData, paraDataPackets, fetchedSignatures, fetchCount, finalized, offset, this, &successCb, &failureCb, &interestSigningKeyName](const auto&, const auto& ackData) { // after fetching the ACK data
          auto signerName = ackData.getName().getPrefix(-3);
          auto contentBlock = ackData.getContent();
          contentBlock.parse();
          // parse ack content
          // generate aes key and hmac key
          auto& paraData = paraDataPackets->at(offset);
          // get paraData ready to be fetched
          // set the scheduler to fetch the result

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

          m_scheduler.schedule(result_ms,
            [keyLocatorName, signers, unfinishedData, fetchedSignatures, fetchCount, finalized, resultName, this, &successCb, &failureCb, &interestSigningKeyName]() {
            Interest resultFetchInt(resultName);
            resultFetchInt.setCanBePrefix(true);
            resultFetchInt.setMustBeFresh(true);
            m_keyChain.sign(resultFetchInt, signingByKey(interestSigningKeyName));
            m_face.expressInterest(
                resultFetchInt,
                [keyLocatorName, signers, unfinishedData, fetchedSignatures, fetchCount, finalized, this, &successCb, &failureCb, &interestSigningKeyName](const auto&, const auto& resultData) {
                  auto signerPrefix = resultData.getName().getPrefix(-4);
                    auto resultContentBlock = resultData.getContent();
                    resultContentBlock.parse();
                    auto sigBlock = resultContentBlock.get(ndn::tlv::SignatureValue);
                    sigBlock.parse();
                    fetchedSignatures->emplace_back(Buffer(sigBlock.value(), sigBlock.value_size()));
                    if (fetchedSignatures->size() == fetchCount) {
                      // all signatures have been fetched
                      auto aggSignature = std::make_shared<Buffer>(ndnBLSAggregateSignature(*fetchedSignatures));
                      unfinishedData->setSignatureValue(aggSignature);
                      unfinishedData->wireEncode();

                      // prepare the signature info packet
                      Data sigInfoData;
                      sigInfoData.setName(keyLocatorName);
                      sigInfoData.setContent(signers->wireEncode());
                      m_keyChain.sign(sigInfoData, signingByKey(interestSigningKeyName));

                      // end the multiparty signature
                      successCb(*unfinishedData, sigInfoData);
                    }
                },
                std::bind(&onNack, _1, _2),
                std::bind(&onTimeout, _1));
          });
        },
        std::bind(&onNack, _1, _2),
        std::bind(&onTimeout, _1));
  }
}

void
MPSInitiator::onParameterFetch(const Interest& interest)
{
}

// void
// MPSInitiator::fetchResult(const Name& resultName, std::map<Name, Buffer>& fetchedSignatures)
// {

// }

}  // namespace mps
}  // namespace ndn