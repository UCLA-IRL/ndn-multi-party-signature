#include "ndnmps/signer.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <utility>
#include <future>
#include <iostream>

namespace ndn {
namespace mps {

NDN_LOG_INIT(ndnmps.blssigner);

const time::milliseconds TIMEOUT = time::seconds(4);
const time::milliseconds ESTIMATE_PROCESS_TIME = time::seconds(1);
const static Name HMAC_KEY_PREFIX("/ndn/mps/hmac"); // append request ID when being used

struct SignRequestState
{
  ECDHState m_ecdh;
  std::array<uint8_t, 16> m_aesKey;
  ReplyCode m_code;
  Buffer m_signatureValue;
  size_t m_version;
  RegisteredPrefixHandle m_resultPrefixHandle;
  security::SigningInfo m_hmacSigningInfo;
};

/**
 * @brief Parse sign request Interest packet's application parameters.
 */
void
parseSignRequestPayload(const Interest& interest, Name& parameterDataName, std::vector<uint8_t>& peerPubKey)
{
  const auto& paramBlock = interest.getApplicationParameters();
  paramBlock.parse();
  parameterDataName.wireDecode(paramBlock.get(tlv::ParameterDataName).blockFromValue());
  const auto& ecdhBlock = paramBlock.get(tlv::EcdhPub);
  peerPubKey.resize(ecdhBlock.value_size());
  std::memcpy(peerPubKey.data(), ecdhBlock.value(), ecdhBlock.value_size());
}

/**
 * @brief Generate unsigned ACK data.
 */
Data
generateSignRequestAck(const Name& interestName, const Name& selfPrefix, ReplyCode code, uint64_t requestId = 0,
                       const uint8_t* salt = nullptr, const uint8_t* selfPub = nullptr, size_t selfPubSize = 0,
                       const uint8_t* aesKey = nullptr)
{
  Data ack(interestName);
  if (code != ReplyCode::Processing) {
    Block contentBlock(ndn::tlv::Content);
    contentBlock.push_back(makeStringBlock(tlv::Status, std::to_string(static_cast<int>(ReplyCode::Processing))));
    ack.setContent(contentBlock);
    ack.setFreshnessPeriod(TIMEOUT);
    return ack;
  }
  Block unencryptedBlock(tlv::EncryptedPayload);
  unencryptedBlock.push_back(makeNonNegativeIntegerBlock(tlv::ResultAfter, ESTIMATE_PROCESS_TIME.count()));
  Name newResultName = selfPrefix;
  newResultName.append("mps").append("result").appendNumber(requestId).appendVersion(0);
  unencryptedBlock.push_back(makeNestedBlock(tlv::ResultName, newResultName));
  unencryptedBlock.encode();
  auto encryptedBlock = encodeBlockWithAesGcm128(ndn::tlv::Content, aesKey,
                                                 unencryptedBlock.value(), unencryptedBlock.value_size(),
                                                 nullptr, 0);
  encryptedBlock.push_back(makeStringBlock(tlv::Status, std::to_string(static_cast<int>(ReplyCode::Processing))));
  encryptedBlock.push_back(makeBinaryBlock(tlv::Salt, salt, 32));
  encryptedBlock.push_back(makeBinaryBlock(tlv::EcdhPub, selfPub, selfPubSize));
  encryptedBlock.encode();
  ack.setContent(encryptedBlock);
  ack.setFreshnessPeriod(TIMEOUT);
  return ack;
}

Data
generateResultData(const Name& interestName, const Name& resultPrefix, std::shared_ptr<SignRequestState> statePtr)
{
  Data result(interestName);
  Block unencryptedBlock(tlv::EncryptedPayload);
  unencryptedBlock.push_back(makeStringBlock(tlv::Status, std::to_string(static_cast<int>(statePtr->m_code))));
  if (statePtr->m_code == ReplyCode::Processing) {
    statePtr->m_version += 1;
    unencryptedBlock.push_back(makeNonNegativeIntegerBlock(tlv::ResultAfter, ESTIMATE_PROCESS_TIME.count()));
    Name newResultName = resultPrefix;
    newResultName.appendVersion(statePtr->m_version);
    unencryptedBlock.push_back(makeNestedBlock(tlv::ResultName, newResultName));
  }
  else if (statePtr->m_code == ReplyCode::OK) {
    unencryptedBlock.push_back(makeBinaryBlock(tlv::BLSSigValue,
                                               statePtr->m_signatureValue.data(),
                                               statePtr->m_signatureValue.size()));
    std::cout << "signature value length: " << statePtr->m_signatureValue.size() << std::endl;
    statePtr->m_resultPrefixHandle.cancel();
  }
  else {
    statePtr->m_resultPrefixHandle.cancel();
  }
  unencryptedBlock.encode();
  auto encryptedBlock = encodeBlockWithAesGcm128(ndn::tlv::Content, statePtr->m_aesKey.data(),
                                                 unencryptedBlock.value(), unencryptedBlock.value_size(),
                                                 nullptr, 0);
  result.setContent(encryptedBlock);
  result.setFreshnessPeriod(TIMEOUT);
  return result;
}

Data
parseParameterData(const Data& data, std::shared_ptr<SignRequestState> statePtr)
{
  auto contentBlock = data.getContent();
  contentBlock.parse();
  Block dataBlock(std::make_shared<Buffer>(decodeBlockWithAesGcm128(contentBlock,
                                                                    statePtr->m_aesKey.data(),
                                                                    nullptr, 0)));
  Data unsignedData(dataBlock);
  return unsignedData;
}

void
onRegisterFail(const Name& prefix, const std::string& reason)
{
  NDN_LOG_ERROR("Fail to register prefix " << prefix.toUri() << " because " << reason);
}

BLSSigner::BLSSigner(const Name& prefix, Face& face, KeyChain& keyChain,
                     const Name& keyName,
                     const VerifyToBeSignedCallback& verifyToBeSignedCallback,
                     const VerifySignRequestCallback& verifySignRequestCallback)
  : m_prefix(prefix)
  , m_keyChain(keyChain)
    , m_keyName(keyName)
    , m_face(face)
    , m_verifyToBeSignedCallback(verifyToBeSignedCallback)
    , m_verifySignRequestCallback(verifySignRequestCallback)
{
  // generate default key randomly
  ndnBLSInit();
  m_sk.init();
  m_sk.getPublicKey(m_pk);
  if (m_keyName.empty()) {
    m_keyName = m_prefix;
    m_keyName.append("KEY").appendTimestamp();
  }

  Name invocationPrefix = m_prefix;
  invocationPrefix.append("mps").append("sign");
  m_signRequestHandle = m_face.setInterestFilter(invocationPrefix,
                                                 std::bind(&BLSSigner::onSignRequest, this, _2),
                                                 nullptr, onRegisterFail);
}

BLSSigner::~BLSSigner()
{
  m_signRequestHandle.unregister();
}

void
BLSSigner::onSignRequest(const Interest& interest)
{
  std::cout << "\n\nSigner: On sign request Interest: " << interest.getName().toUri() << std::endl;

  if (!m_verifySignRequestCallback(interest) || !interest.isParametersDigestValid()) {
    auto ack = generateSignRequestAck(interest.getName(), m_prefix, ReplyCode::Unauthorized);
    ndnBLSSign(m_sk, ack, m_keyName);
    m_face.put(ack);
    return;
  }
  // parse
  Name parameterDataName;
  std::vector<uint8_t> peerPubKey;
  try {
    parseSignRequestPayload(interest, parameterDataName, peerPubKey);
  }
  catch (const std::exception& e) {
    auto ack = generateSignRequestAck(interest.getName(), m_prefix,ReplyCode::Unauthorized);
    ndnBLSSign(m_sk, ack, m_keyName);
    m_face.put(ack);
    return;
  }
  // generate state for the request
  auto statePtr = std::make_shared<SignRequestState>();
  statePtr->m_code = ReplyCode::Processing;
  statePtr->m_version = 0;
  // ECDH
  auto dhSecret = statePtr->m_ecdh.deriveSecret(peerPubKey);
  std::array<uint8_t, 32> salt;
  random::generateSecureBytes(salt.data(), salt.size());
  std::array<uint8_t, 48> aesAndHmac;
  hkdf(dhSecret.data(), dhSecret.size(), salt.data(), salt.size(), aesAndHmac.data(), aesAndHmac.size());
  std::memcpy(statePtr->m_aesKey.data(), aesAndHmac.data(), 16);
  auto hmacKeyStr = base64EncodeFromBytes(aesAndHmac.data() + 16, 32, false);
  // HMAC
  statePtr->m_hmacSigningInfo.setSigningHmacKey(hmacKeyStr);
  statePtr->m_hmacSigningInfo.setDigestAlgorithm(DigestAlgorithm::SHA256);
  statePtr->m_hmacSigningInfo.setSignedInterestFormat(security::SignedInterestFormat::V03);

  auto requestId = random::generateSecureWord64();
  Name resultPrefix = m_prefix;
  resultPrefix.append("mps").append("result").appendNumber(requestId);
  statePtr->m_resultPrefixHandle = m_face.setInterestFilter(
    resultPrefix,
    [this, statePtr, resultPrefix](const auto&, const auto& interest)
    {
      std::cout << "\n\nSigner: received result fetch Interest: " << interest.getName().toUri() << std::endl;
      // parse request: /signer/mps/result/randomness/version/hash
      // TODO: signature verification
      if (interest.getName().size() != m_prefix.size() + 5) {
        NDN_LOG_INFO("Bad result request name format");
        return;
      }
      auto result = generateResultData(interest.getName(), resultPrefix, statePtr);
      m_keyChain.sign(result, statePtr->m_hmacSigningInfo);
      m_face.put(result);
    },
    nullptr, onRegisterFail);

  auto selfPubKey = statePtr->m_ecdh.getSelfPubKey();
  auto ack = generateSignRequestAck(interest.getName(), m_prefix, ReplyCode::Processing, requestId,
                                    salt.data(), selfPubKey.data(), selfPubKey.size(), statePtr->m_aesKey.data());
  ndnBLSSign(m_sk, ack, m_keyName);
  m_face.put(ack);

  // fetch parameter
  Interest fetchInterest(parameterDataName);
  fetchInterest.setCanBePrefix(true);
  fetchInterest.setMustBeFresh(true);
  fetchInterest.setInterestLifetime(TIMEOUT);
  std::cout << "\n\nSigner: send Interest to fetch parameter: " << parameterDataName.toUri() << std::endl;
  m_face.expressInterest(
    fetchInterest,
    [=](const auto& interest, const auto& data)
    {
      std::cout << "\n\nSigner: fetched parameter Data packet." << std::endl << data;
      // parse fetched data
      Data unsignedData;
      try {
        unsignedData = parseParameterData(data, statePtr);
      }
      catch (const std::exception& e) {
        NDN_LOG_ERROR("Unsigned Data decoding error");
        statePtr->m_code = ReplyCode::FailedDependency;
        return;
      }
      if (!m_verifyToBeSignedCallback(unsignedData)) {
        NDN_LOG_ERROR("Unsigned Data verification error");
        statePtr->m_code = ReplyCode::Unauthorized;
        return;
      }
      // generate result
      std::cout << "Signer: result status code is OK " << std::endl;
      statePtr->m_code = ReplyCode::OK;
      statePtr->m_signatureValue = ndnGenBLSSignature(m_sk, unsignedData);
      std::cout << "signature value length: " << statePtr->m_signatureValue.size() << std::endl;
    },
    [=](auto& interest, auto&)
    {
      // nack
      statePtr->m_code = ReplyCode::FailedDependency;
    },
    [=](auto& interest)
    {
      // timeout
      statePtr->m_code = ReplyCode::FailedDependency;
    });
}

}  // namespace mps
}  // namespace ndn