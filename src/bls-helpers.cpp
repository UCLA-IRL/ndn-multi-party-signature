#include "ndnmps/bls-helpers.hpp"
#include <ndn-cxx/util/random.hpp>
#include <set>
#include <utility>

namespace ndn {
namespace mps {

static bool HAS_BLS_INITIALIZED = false;

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
    signingKey.sign(sig, encoder.buf(), encoder.size());
  }
  auto sigStr = sig.getStr();
  return Buffer(sigStr.data(), sigStr.size());
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
    NDN_THROW(std::runtime_error("Bad signature type from signature info " + std::to_string(sigInfo.getSignatureType())));
  }
  interest.setSignatureInfo(sigInfo);
  BLSSignature sig;
  {
    auto discontiguousBuf = interest.extractSignedRanges();
    Buffer contiguousBuf;
    for (const auto& bufPiece : discontiguousBuf) {
      contiguousBuf.insert(contiguousBuf.end(), bufPiece.first, bufPiece.first + bufPiece.second);
    }
    signingKey.sign(sig, contiguousBuf.data(), contiguousBuf.size());
  }
  auto sigStr = sig.getStr();
  auto sigBuf = make_shared<Buffer>(Buffer(sigStr.data(), sigStr.size()));
  interest.setSignatureValue(sigBuf);
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
  auto pubKeyStr = pubKey.getStr();
  newCert.setContentType(ndn::tlv::ContentType_Key);
  newCert.setContent(reinterpret_cast<const uint8_t*>(pubKeyStr.data()), pubKeyStr.size());
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
  std::string sigStr(reinterpret_cast<const char*>(sigValue.value()), sigValue.value_size());
  sig.setStr(sigStr);
  // verify
  auto discontiguousBuf = data.extractSignedRanges();
  Buffer contiguousBuf;
  for (const auto& bufPiece : discontiguousBuf) {
    contiguousBuf.insert(contiguousBuf.end(), bufPiece.first, bufPiece.first + bufPiece.second);
  }
  return sig.verify(pubKey, contiguousBuf.data(), contiguousBuf.size());
}

bool
ndnBLSVerify(const std::vector<BLSPublicKey>& pubKeys, const Data& data)
{
  BLSPublicKey aggKey = pubKeys[0];
  for (size_t i = 1; i < pubKeys.size(); i++) {
    aggKey.add(pubKeys[i]);
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
  std::string sigStr(reinterpret_cast<const char*>(sigValue.value()), sigValue.value_size());
  sig.setStr(sigStr);
  // verify
  auto discontiguousBuf = interest.extractSignedRanges();
  Buffer contiguousBuf;
  for (const auto& bufPiece : discontiguousBuf) {
    contiguousBuf.insert(contiguousBuf.end(), bufPiece.first, bufPiece.first + bufPiece.second);
  }
  return sig.verify(pubKey, contiguousBuf.data(), contiguousBuf.size());
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
    aggKey.add(pubKeys[i]);
  }
  return aggKey;
}

Buffer
ndnBLSAggregateSignature(const std::vector<Buffer>& signatures)
{
  BLSSignature aggSig;
  std::string sigStr(reinterpret_cast<const char*>(signatures[0].data()), signatures[0].size());
  aggSig.setStr(sigStr);
  BLSSignature tempSig;
  for (size_t i = 1; i < signatures.size(); i++) {
    sigStr = std::string(reinterpret_cast<const char*>(signatures[i].data()), signatures[i].size());
    tempSig.setStr(sigStr);
    aggSig.add(tempSig);
  }
  sigStr = aggSig.getStr();
  return Buffer(sigStr.data(), sigStr.size());
}

BLSSignature
ndnBLSAggregateSignature(const std::vector<BLSSignature>& signatures)
{
  BLSSignature aggSig = signatures[0];
  for (size_t i = 1; i < signatures.size(); i++) {
    aggSig.add(signatures[i]);
  }
  return aggSig;
}

}  // namespace mps
}  // namespace ndn
