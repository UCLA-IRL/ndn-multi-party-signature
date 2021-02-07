#include "ndnmps/signer.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <utility>

namespace ndn {
namespace mps {

NDN_LOG_INIT(ndnmps.blssigner);

const time::milliseconds TIMEOUT = time::seconds(4);
const time::milliseconds ESTIMATE_PROCESS_TIME = time::seconds(1);
const static Name HMAC_KEY_PREFIX("/ndn/mps/hmac"); // append request ID when being used

void
onRegisterFail(const Name& prefix, const std::string& reason)
{
  NDN_LOG_ERROR("Fail to register prefix " << prefix.toUri() << " because " << reason);
}

BLSSigner::BLSSigner(const Name& prefix, Face& face, const Name& keyName)
    : m_prefix(prefix)
    , m_keyName(keyName)
    , m_face(face)
{
  // generate default key randomly
  m_sk.init();
  m_sk.getPublicKey(m_pk);

  Name invocationPrefix = m_prefix;
  invocationPrefix.append("mps").append("sign");
  m_handles.push_back(m_face.setInterestFilter(
      invocationPrefix, std::bind(&BLSSigner::onSignRequest, this, _2), nullptr, onRegisterFail));

  Name resultPrefix = m_prefix;
  resultPrefix.append("mps").append("result");
  m_handles.push_back(m_face.setInterestFilter(
      resultPrefix, std::bind(&BLSSigner::onResultFetch, this, _2), nullptr, onRegisterFail));
}

BLSSigner::~BLSSigner()
{
  for (auto& i : m_handles) {
    i.unregister();
  }
}

void
BLSSigner::setDataVerifyCallback(const function<bool(const Data&)>& func)
{
  m_dataVerifyCallback = func;
}

void
BLSSigner::setSignatureVerifyCallback(const function<bool(const Interest&)>& func)
{
  m_interestVerifyCallback = func;
}

void
BLSSigner::onSignRequest(const Interest& interest)
{
  if (!m_interestVerifyCallback || !m_interestVerifyCallback(interest)) {
    m_face.put(generateAck(interest.getName(), ReplyCode::Unauthorized, 0));
    return;
  }
  // parse
  const auto& paramBlock = interest.getApplicationParameters();
  paramBlock.parse();
  Name wrapperName;
  try {
    if (paramBlock.get(tlv::UnsignedWrapperName).isValid()) {
      wrapperName.wireDecode(paramBlock.get(tlv::UnsignedWrapperName).blockFromValue());
      if (!wrapperName.at(-1).isImplicitSha256Digest()) {
        NDN_THROW(std::runtime_error("digest not found for data"));
      }
    }
    else {
      NDN_THROW(std::runtime_error("Block Element not found or Bad element type in signer's request"));
    }
    if (!interest.getName().get(m_prefix.size() + 2).isParametersSha256Digest()) {
      NDN_THROW(std::runtime_error("interest not end with parameter digest."));
    }
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Got error in decoding invocation request: " << e.what());
    m_face.put(generateAck(interest.getName(), ReplyCode::BadRequest, 0));
    return;
  }

  auto randomId = random::generateSecureWord64();
  RequestInstance instance;
  instance.code = ReplyCode::Processing;
  instance.version = 0;
  m_results.emplace(randomId, instance);
  m_face.put(generateAck(interest.getName(), ReplyCode::Processing, randomId));

  // fetch parameter
  Interest fetchInterest(wrapperName);
  fetchInterest.setCanBePrefix(false);
  fetchInterest.setMustBeFresh(true);
  fetchInterest.setInterestLifetime(TIMEOUT);
  m_face.expressInterest(
      fetchInterest,
      [&](auto& interest, auto& data) {
        // parse fetched data
        ReplyCode code = ReplyCode::OK;
        Data unsignedData;
        try {
          unsignedData.wireDecode(data.getContent().blockFromValue());
        }
        catch (const std::exception& e) {
          NDN_LOG_ERROR("Unsigned Data decoding error");
          code = ReplyCode::FailedDependency;
        }
        if (!m_dataVerifyCallback || !m_dataVerifyCallback(unsignedData)) {
          NDN_LOG_ERROR("Unsigned Data verification error");
          code = ReplyCode::Unauthorized;
        }
        // generate result
        m_results[randomId].code = code;
        if (code == ReplyCode::OK) {
          m_results[randomId].signatureValue = ndnGenBLSSignature(m_sk, unsignedData);
        }
      },
      [&](auto& interest, auto&) {
        // nack
        m_results[randomId].code = ReplyCode::FailedDependency;
      },
      [&](auto& interest) {
        // timeout
        m_results[randomId].code = ReplyCode::FailedDependency;
      });
}

void
BLSSigner::onResultFetch(const Interest& interest)
{
  // parse request
  if (interest.getName().size() != m_prefix.size() + 3) {
    NDN_LOG_ERROR("Bad result request name format");
    // bad request let it timeout
    return;
  }
  auto resultId = readNonNegativeInteger(interest.getName().get(m_prefix.size() + 2));
  auto it = m_results.find(resultId);
  if (it == m_results.end()) {
    // replayed or phishing request, let it timeout
    return;
  }
  auto requestInstance = it->second;

  // otherwise, reply
  Data result(interest.getName());
  Block contentBlock(ndn::tlv::Content);
  contentBlock.push_back(makeStringBlock(tlv::Status, std::to_string(static_cast<int>(requestInstance.code))));
  if (requestInstance.code == ReplyCode::Processing) {
    requestInstance.version += 1;
    it->second = requestInstance;
    contentBlock.push_back(makeNonNegativeIntegerBlock(tlv::ResultAfter, ESTIMATE_PROCESS_TIME.count()));
    Name newResultName = m_prefix;
    newResultName.append("mps").append("result").appendNumber(resultId).appendVersion(requestInstance.version);
    contentBlock.push_back(makeNestedBlock(tlv::ResultName, newResultName));
  }
  else if (requestInstance.code == ReplyCode::OK) {
    m_results.erase(it);
    contentBlock.push_back(Block(ndn::tlv::SignatureValue, std::make_shared<Buffer>(requestInstance.signatureValue)));
  }
  else {
    m_results.erase(it);
  }
  contentBlock.encode();
  result.setContent(contentBlock);
  result.setFreshnessPeriod(TIMEOUT);
  ndnBLSSign(m_sk, result, m_keyName);
  m_face.put(result);
}

Data
BLSSigner::generateAck(const Name& interestName, ReplyCode code, uint64_t requestId) const
{
  Data ack(interestName);
  Block contentBlock(ndn::tlv::Content);
  contentBlock.push_back(makeStringBlock(tlv::Status, std::to_string(static_cast<int>(ReplyCode::Processing))));
  if (code == ReplyCode::Processing) {
    contentBlock.push_back(makeNonNegativeIntegerBlock(tlv::ResultAfter, ESTIMATE_PROCESS_TIME.count()));
    Name newResultName = m_prefix;
    newResultName.append("mps").append("result").appendNumber(requestId);
    contentBlock.push_back(makeNestedBlock(tlv::ResultName, newResultName));
  }
  contentBlock.encode();
  ack.setContent(contentBlock);
  ack.setFreshnessPeriod(TIMEOUT);
  ndnBLSSign(m_sk, ack, m_keyName);
  return ack;
}

}  // namespace mps
}  // namespace ndn