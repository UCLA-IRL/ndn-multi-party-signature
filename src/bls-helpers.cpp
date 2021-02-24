#include "ndnmps/bls-helpers.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace mps {

static bool HAS_BLS_INITIALIZED = false;
uint8_t encodingBuf[128];

void
ndnBLSInit()
{
  if (!HAS_BLS_INITIALIZED) {
    int err = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (err != 0) {
      NDN_THROW(std::runtime_error("Fail to call blsInit, error code: " + std::to_string(err)));
    }
    else {
      HAS_BLS_INITIALIZED = true;
    }
  }
}

Buffer
ndnGenBLSSignature(const BLSSecretKey& signingKey, const Data& dataWithInfo)
{
  BLSSignature sig;
  {
    EncodingBuffer encoder;
    dataWithInfo.wireEncode(encoder, true);
    blsSign(&sig, &signingKey, encoder.buf(), encoder.size());
  }
  auto sigSize = blsSignatureSerialize(encodingBuf, sizeof(encodingBuf), &sig);
  return Buffer(encodingBuf, sigSize);
}

Buffer
ndnGenBLSSignature(const BLSSecretKey& signingKey, const Data& data, const SignatureInfo& sigInfo)
{
  if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error("Signer got non-BLS signature type"));
  }
  auto dataWithInfo = data;
  dataWithInfo.setSignatureInfo(sigInfo);
  return ndnGenBLSSignature(signingKey, dataWithInfo);
}

Buffer
ndnGenBLSSignature(const BLSSecretKey& signingKey, const Interest& interest, const SignatureInfo& sigInfo)
{
  if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error("Signer got non-BLS signature type"));
  }
  auto interestWithInfo = interest;
  interestWithInfo.setSignatureInfo(sigInfo);
  return ndnGenBLSSignature(signingKey, interestWithInfo);
}

Buffer
ndnGenBLSSignature(const BLSSecretKey& signingKey, const Interest& interest)
{
  BLSSignature sig;
  {
    auto discontiguousBuf = interest.extractSignedRanges();
    Buffer contiguousBuf;
    for (const auto& bufPiece : discontiguousBuf) {
      contiguousBuf.insert(contiguousBuf.end(), bufPiece.first, bufPiece.first + bufPiece.second);
    }
    blsSign(&sig, &signingKey, contiguousBuf.data(), contiguousBuf.size());
  }
  auto sigSize = blsSignatureSerialize(encodingBuf, sizeof(encodingBuf), &sig);
  return Buffer(encodingBuf, sigSize);
}

void
ndnBLSSign(const BLSSecretKey& signingKey, Data& data, const Name& keyLocatorName)
{
  SignatureInfo info(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), keyLocatorName);
  ndnBLSSign(signingKey, data, info);
}

void
ndnBLSSign(const BLSSecretKey& signingKey, Data& data, const SignatureInfo& sigInfo)
{
  if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error("Bad signature type from signature info " +
                                 std::to_string(sigInfo.getSignatureType())));
  }
  data.setSignatureInfo(sigInfo);
  auto sigValue = std::make_shared<Buffer>(ndnGenBLSSignature(signingKey, data));
  data.setSignatureValue(sigValue);
  data.wireEncode();
}

void
ndnBLSSign(const BLSSecretKey& signingKey, Interest& interest, const Name& keyLocatorName)
{
  SignatureInfo info(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), keyLocatorName);
  ndnBLSSign(signingKey, interest, info);
}

void
ndnBLSSign(const BLSSecretKey& signingKey, Interest& interest, const SignatureInfo& sigInfo)
{
  if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error(
                      "Bad signature type from signature info " + std::to_string(sigInfo.getSignatureType())));
  }
  interest.setSignatureInfo(sigInfo);
  auto sigValue = std::make_shared<Buffer>(ndnGenBLSSignature(signingKey, interest));
  interest.setSignatureValue(sigValue);
  interest.wireEncode();
}

security::Certificate
genSelfSignedCertificate(const Name& keyName,
                         const BLSPublicKey& pubKey, const BLSSecretKey& signingKey,
                         const security::ValidityPeriod& period)
{
  security::Certificate newCert;
  Name certName = keyName;
  certName.append("self").append(std::to_string(random::generateSecureWord64()));
  newCert.setName(certName);
  auto pubKeySize = blsPublicKeySerialize(encodingBuf, sizeof(encodingBuf), &pubKey);
  newCert.setContentType(ndn::tlv::ContentType_Key);
  newCert.setContent(encodingBuf, pubKeySize);
  SignatureInfo signatureInfo(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
                              KeyLocator(keyName));
  signatureInfo.setValidityPeriod(period);
  ndnBLSSign(signingKey, newCert, signatureInfo);
  return newCert;
}

bool
ndnBLSVerify(const BLSPublicKey& pubKey, const Data& data)
{
  // get signature value
  const auto& sigValue = data.getSignatureValue();
  BLSSignature sig;
  blsSignatureDeserialize(&sig, sigValue.value(), sigValue.value_size());
  // verify
  auto discontiguousBuf = data.extractSignedRanges();
  Buffer contiguousBuf;
  for (const auto& bufPiece : discontiguousBuf) {
    contiguousBuf.insert(contiguousBuf.end(), bufPiece.first, bufPiece.first + bufPiece.second);
  }
  return blsVerify(&sig, &pubKey, contiguousBuf.data(), contiguousBuf.size()) == 1;
}

bool
ndnBLSVerify(const std::vector<BLSPublicKey>& pubKeys, const Data& data)
{
  BLSPublicKey aggKey = pubKeys[0];
  for (size_t i = 1; i < pubKeys.size(); i++) {
    blsPublicKeyAdd(&aggKey, &pubKeys[i]);
  }
  return ndnBLSVerify(aggKey, data);
}

bool
ndnBLSVerify(const BLSPublicKey& pubKey, const Interest& interest)
{
  if (!interest.isSigned()) {
    return false;
  }
  // get signature value
  const auto& sigValue = interest.getSignatureValue();
  BLSSignature sig;
  blsSignatureDeserialize(&sig, sigValue.value(), sigValue.value_size());
  // verify
  auto discontiguousBuf = interest.extractSignedRanges();
  Buffer contiguousBuf;
  for (const auto& bufPiece : discontiguousBuf) {
    contiguousBuf.insert(contiguousBuf.end(), bufPiece.first, bufPiece.first + bufPiece.second);
  }
  return blsVerify(&sig, &pubKey, contiguousBuf.data(), contiguousBuf.size()) == 1;
}

bool
ndnBLSVerify(const std::vector<BLSPublicKey>& pubKeys, const Interest& interest)
{
  BLSPublicKey aggKey = ndnBLSAggregatePublicKey(pubKeys);
  return ndnBLSVerify(aggKey, interest);
}

BLSPublicKey
ndnBLSAggregatePublicKey(const std::vector<BLSPublicKey>& pubKeys)
{
  BLSPublicKey aggKey = pubKeys[0];
  for (size_t i = 1; i < pubKeys.size(); i++) {
    blsPublicKeyAdd(&aggKey, &pubKeys[i]);
  }
  return aggKey;
}

Buffer
ndnBLSAggregateSignature(const std::vector<Buffer>& signatures)
{
  BLSSignature aggSig;
  blsSignatureDeserialize(&aggSig, signatures[0].data(), signatures[0].size());
  BLSSignature tempSig;
  for (size_t i = 1; i < signatures.size(); i++) {
    blsSignatureDeserialize(&tempSig, signatures[i].data(), signatures[i].size());
    blsSignatureAdd(&aggSig, &tempSig);
  }
  auto sigSize = blsSignatureSerialize(encodingBuf, sizeof(encodingBuf), &aggSig);
  return Buffer(encodingBuf, sigSize);
}

BLSSignature
ndnBLSAggregateSignature(const std::vector<BLSSignature>& signatures)
{
  BLSSignature aggSig = signatures[0];
  for (size_t i = 1; i < signatures.size(); i++) {
    blsSignatureAdd(&aggSig, &signatures[i]);
  }
  return aggSig;
}

}  // namespace mps
}  // namespace ndn
