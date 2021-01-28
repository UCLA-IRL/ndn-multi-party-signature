#include "ndnmps/crypto-players.hpp"

#include "ndnmps/common.hpp"
#include <set>
#include <utility>
#include <ndn-cxx/util/random.hpp>

namespace ndn {

static bool BLS_INITIALIZED = false;

void
bls_library_init()
{
  if (!BLS_INITIALIZED) {
    int err = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (err != 0) {
      printf("blsInit err %d\n", err);
      exit(1);
    }
    else {
      BLS_INITIALIZED = true;
    }
  }
}

MpsSigner::MpsSigner(const Name& signerName)
{
  m_signerName = signerName;
  bls_library_init();
  blsSecretKeySetByCSPRNG(&m_sk);
  blsGetPublicKey(&m_pk, &m_sk);
}

MpsSigner::MpsSigner(const Name& signerName, const Buffer& secretKeyBuf)
{
  m_signerName = signerName;
  bls_library_init();
  auto ret = blsSecretKeyDeserialize(&m_sk, secretKeyBuf.data(), secretKeyBuf.size());
  if (ret == 0) {
    NDN_THROW(std::runtime_error("Fail to read secret key in Signer::initKey()"));
  }
  blsGetPublicKey(&m_pk, &m_sk);
}

const Name&
MpsSigner::getSignerKeyName() const
{
  return m_signerName;
}

const blsPublicKey&
MpsSigner::getPublicKey() const
{
  return m_pk;
}

const blsSecretKey&
MpsSigner::getSecretKey() const
{
  return m_sk;
}

std::vector<uint8_t>
MpsSigner::getpublicKeyStr() const
{
  std::vector<uint8_t> outputBuf(blsGetSerializedPublicKeyByteSize());
  int written_size = blsPublicKeySerialize(outputBuf.data(), outputBuf.size(), &m_pk);
  if (written_size == 0) {
    NDN_THROW(std::runtime_error("Fail to write public key in Signer::getpublicKeyStr()"));
  }
  outputBuf.resize(written_size);
  return std::move(outputBuf);
}

Block
MpsSigner::getSignature(Data data, const SignatureInfo& sigInfo) const
{
  if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error("Signer got non-BLS signature type"));
  }
  data.setSignatureInfo(sigInfo);
  return getSignature(data);
}

Block
MpsSigner::getSignature(const Data& data) const
{
  if (!data.getSignatureInfo()) {
    return Block();
  }

  EncodingBuffer encoder;
  data.wireEncode(encoder, true);

  blsSignature sig;
  blsSign(&sig, &m_sk, encoder.buf(), encoder.size());
  auto signatureBuf = make_shared<Buffer>(blsGetSerializedSignatureByteSize());
  auto written_size = blsSignatureSerialize(signatureBuf->data(), signatureBuf->size(), &sig);
  if (written_size == 0) {
    NDN_THROW(std::runtime_error("Error on serializing signature"));
  }
  signatureBuf->resize(written_size);
  return Block(tlv::SignatureValue, signatureBuf);
}

void
MpsSigner::sign(Data& data, const Name& keyLocatorName) const
{
  SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
                     keyLocatorName.empty()? m_signerName : keyLocatorName);
  sign(data, info);
}

void
MpsSigner::sign(Interest& interest, const Name& keyLocatorName) const
{
  SignatureInfo info(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls),
                     keyLocatorName.empty()? m_signerName : keyLocatorName);

  sign(interest, info);
}

void
MpsSigner::sign(Data& data, const SignatureInfo& sigInfo) const
{
  if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error("Bad signature type from signature info " + std::to_string(sigInfo.getSignatureType())));
  }
  auto signature = getSignature(data, sigInfo);

  data.setSignatureInfo(sigInfo);
  auto value = make_shared<Buffer>(signature.value(), signature.value_size());
  data.setSignatureValue(value);
  data.wireEncode();
}

void
MpsSigner::sign(Interest& interest, const SignatureInfo& sigInfo) const
{
  if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error("Bad signature type from signature info " + std::to_string(sigInfo.getSignatureType())));
  }
  interest.setSignatureInfo(sigInfo);
  // Extract function will throw if not all necessary elements are present in Interest
  auto buf = interest.extractSignedRanges();

  blsSignature sig;
  if (buf.size() == 1) {
    blsSign(&sig, &m_sk, buf.at(0).first, buf.at(0).second);
  } else {
    EncodingBuffer encoder;
    for (const auto& arr : buf) {
      encoder.appendByteArray(arr.first, arr.second);
    }
    blsSign(&sig, &m_sk, encoder.buf(), encoder.size());
  }
  auto signatureBuf = make_shared<Buffer>(blsGetSerializedSignatureByteSize());
  auto written_size = blsSignatureSerialize(signatureBuf->data(), signatureBuf->size(), &sig);
  if (written_size == 0) {
    NDN_THROW(std::runtime_error("Error on serializing signature"));
  }
  signatureBuf->resize(written_size);

  interest.setSignatureValue(std::move(signatureBuf));
  interest.wireEncode();
}

security::Certificate
MpsSigner::getSelfSignCert(const security::ValidityPeriod& period) const
{
  security::Certificate newCert;

  Name certName = m_signerName;
  certName.append("self-sign").append(std::to_string(random::generateSecureWord64()));
  newCert.setName(certName);
  auto pubKey = getpublicKeyStr();
  newCert.setContentType(tlv::ContentType_Key);
  newCert.setContent(pubKey.data(), pubKey.size());
  SignatureInfo signatureInfo(static_cast<tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), KeyLocator(m_signerName));
  signatureInfo.setValidityPeriod(period);

  sign(newCert, signatureInfo);
  return newCert;
}


MpsVerifier::MpsVerifier()
{
  bls_library_init();
}

void
MpsVerifier::addCert(const Name& keyName, blsPublicKey pk)
{
  m_certs.emplace(keyName, pk);
}

void
MpsVerifier::addCert(const security::Certificate& cert)
{
  auto keyName = cert.getKeyName();
  const auto& content = cert.getContent();
  blsPublicKey pk;
  int ret = blsPublicKeyDeserialize(&pk, content.value(), content.value_size());
  if (ret == 0) {
    NDN_THROW(std::runtime_error("not a BLS key in the certificate"));
  }
  m_certs.emplace(keyName, pk);
}

void
MpsVerifier::addSignerList(const Name& listName, MpsSignerList list)
{
  m_signLists.emplace(listName, list);
}

std::map<Name, blsPublicKey>&
MpsVerifier::getCerts()
{
  return m_certs;
}

std::map<Name, MpsSignerList>&
MpsVerifier::getSignerLists()
{
  return m_signLists;
}

const std::map<Name, blsPublicKey>&
MpsVerifier::getCerts() const
{
  return m_certs;
}

const std::map<Name, MpsSignerList>&
MpsVerifier::getSignerLists() const
{
  return m_signLists;
}

bool
MpsVerifier::readyToVerify(const Data& data) const
{
  const auto& sigInfo = data.getSignatureInfo();
  if (sigInfo.hasKeyLocator() && sigInfo.getKeyLocator().getType() == tlv::Name) {
    if (m_certs.count(sigInfo.getKeyLocator().getName()) == 1)
      return true;
    if (m_signLists.count(sigInfo.getKeyLocator().getName()) == 0)
      return false;
    const auto& item = m_signLists.at(sigInfo.getKeyLocator().getName());
    for (const auto& signers : item) {
      if (m_certs.count(signers) == 0)
        return false;
    }
    return true;
  }
  else {
    return false;
  }
}

std::vector<Name>
MpsVerifier::itemsToFetch(const Data& data) const
{
  std::vector<Name> ans;
  const auto& sigInfo = data.getSignatureInfo();
  if (sigInfo.hasKeyLocator() && sigInfo.getKeyLocator().getType() == tlv::Name) {
    if (m_certs.count(sigInfo.getKeyLocator().getName()) == 1)
      return ans;
    if (m_signLists.count(sigInfo.getKeyLocator().getName()) == 0) {
      ans.emplace_back(sigInfo.getKeyLocator().getName());
      return ans;
    }
    const auto& item = m_signLists.at(sigInfo.getKeyLocator().getName());
    for (const auto& signers : item) {
      if (m_certs.count(signers) == 0) {
        ans.emplace_back(sigInfo.getKeyLocator().getName());
      }
    }
  }
  return ans;
}

bool
MpsVerifier::verifySignature(const Data& data, const MultipartySchema& schema) const
{
  const auto& sigInfo = data.getSignatureInfo();
  if (sigInfo.getCustomTlv(tlv::ValidityPeriod) && !sigInfo.getValidityPeriod().isValid()) {
    return false;
  }
  MpsSignerList locator;
  bool aggKeyInitialized = false;
  blsPublicKey aggKey;
  if (sigInfo.getKeyLocator().getType() == tlv::Name) {
    if (m_signLists.count(sigInfo.getKeyLocator().getName()) != 0) {
      locator = m_signLists.at(sigInfo.getKeyLocator().getName());
      if (m_aggregateKey.count(sigInfo.getKeyLocator().getName()) != 0) {
        aggKey = m_aggregateKey.at(sigInfo.getKeyLocator().getName());
        aggKeyInitialized = true;
      }
    }
    else if (m_certs.count(sigInfo.getKeyLocator().getName()) != 0) {
      locator.emplace_back(sigInfo.getKeyLocator().getName());
      aggKey = m_certs.at(sigInfo.getKeyLocator().getName());
      aggKeyInitialized = true;
    }
    else {
      return false;
    }
  }
  if (!schema.isSatisfied(locator))
    return false;

  //build public key if needed
  if (!aggKeyInitialized) {
    for (const auto& signer : locator) {
      auto it = m_certs.find(signer);
      if (it == m_certs.end())
        return false;
      if (aggKeyInitialized) {
        blsPublicKeyAdd(&aggKey, &it->second);
      }
      else {
        aggKey = it->second;
        aggKeyInitialized = true;
      }
    }
    //store?
    //TODO finish the cache implementation
    //m_aggregateKey.emplace(sigInfo.getKeyLocator().getName(), aggKey);
  }

  //get signature value
  const auto& sigValue = data.getSignatureValue();
  blsSignature sig;
  if (blsSignatureDeserialize(&sig, sigValue.value(), sigValue.value_size()) == 0)
    return false;

  //verify
  auto signedRanges = data.extractSignedRanges();
  if (signedRanges.size() == 1) {  // to avoid copying in current ndn-cxx impl
    const auto& it = signedRanges.begin();
    return blsVerify(&sig, &aggKey, it->first, it->second);
  }
  else {
    EncodingBuffer encoder;
    for (const auto& it : signedRanges) {
      encoder.appendByteArray(it.first, it.second);
    }
    return blsVerify(&sig, &aggKey, encoder.buf(), encoder.size());
  }
}

bool
MpsVerifier::verifySignature(const Interest& interest) const {
  const auto &sigInfo = interest.getSignatureInfo();
  if (!sigInfo || (sigInfo->getCustomTlv(tlv::ValidityPeriod) && !sigInfo->getValidityPeriod().isValid())) {
    return false;
  }
  if (sigInfo->getKeyLocator().getType() != tlv::Name ||
      m_certs.count(sigInfo->getKeyLocator().getName()) == 0) {
    return false;
  }
  blsPublicKey aggKey = m_certs.at(sigInfo->getKeyLocator().getName());

  //get signature value
  const auto &sigValue = interest.getSignatureValue();
  blsSignature sig;
  if (blsSignatureDeserialize(&sig, sigValue.value(), sigValue.value_size()) == 0)
    return false;

  //verify
  auto signedRanges = interest.extractSignedRanges();
  if (signedRanges.size() == 1) {  // to avoid copying in current ndn-cxx impl
    const auto &it = signedRanges.begin();
    return blsVerify(&sig, &aggKey, it->first, it->second);
  } else {
    EncodingBuffer encoder;
    for (const auto &it : signedRanges) {
      encoder.appendByteArray(it.first, it.second);
    }
    return blsVerify(&sig, &aggKey, encoder.buf(), encoder.size());
  }
}

bool
MpsVerifier::verifySignaturePiece(Data data, const SignatureInfo& sigInfo, const Name& signedBy, const Block& signaturePiece) const
{
  if (sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error("Signer got non-BLS signature type"));
  }

  data.setSignatureInfo(sigInfo);

  return verifySignaturePiece(data, signedBy, signaturePiece);
}

bool
MpsVerifier::verifySignaturePiece(const Data& dataWithInfo, const Name& signedBy, const Block& signaturePiece) const
{
  const auto& sigInfo = dataWithInfo.getSignatureInfo();
  if (sigInfo.getCustomTlv(tlv::ValidityPeriod) && !sigInfo.getValidityPeriod().isValid()) {
    return false;
  }
  if (!sigInfo || sigInfo.getSignatureType() != tlv::SignatureSha256WithBls) {
    NDN_THROW(std::runtime_error("Signer got non-BLS signature type"));
  }

  if (m_certs.count(signedBy) == 0)
    return false;
  blsPublicKey publicKey = m_certs.at(signedBy);
  blsSignature sig;
  if (blsSignatureDeserialize(&sig, signaturePiece.value(), signaturePiece.value_size()) == 0)
    return false;


    EncodingBuffer encoder;
    dataWithInfo.wireEncode(encoder, true);
    return blsVerify(&sig, &publicKey, encoder.buf(), encoder.size());
}

bool
MpsVerifier::verifySignature(const Data& data, const security::Certificate& cert)
{
  MpsVerifier verifier;
  verifier.addCert(cert);
  MultipartySchema schema;
  schema.signers.emplace_back(cert.getKeyName());
  return verifier.verifySignature(data, schema);
}

bool
MpsVerifier::verifySignature(const Interest& interest, const security::Certificate& cert)
{
  MpsVerifier verifier;
  verifier.addCert(cert);
  return verifier.verifySignature(interest);
}

MpsAggregator::MpsAggregator()
{
  bls_library_init();
}

void
MpsAggregator::buildMultiSignature(Data& data, const SignatureInfo& sigInfo,
                                   const std::vector<blsSignature>& collectedPiece) const
{
  data.setSignatureInfo(sigInfo);
  buildMultiSignature(data, collectedPiece);
}

void
MpsAggregator::buildMultiSignature(Data& dataWithInfo, const std::vector<blsSignature>& collectedPiece) const
{
  if (!dataWithInfo.getSignatureInfo()) {
    NDN_THROW(std::runtime_error("No signature info for the data"));
  }
  EncodingBuffer encoder;
  dataWithInfo.wireEncode(encoder, true);

  blsSignature outputSig;
  blsAggregateSignature(&outputSig, collectedPiece.data(), collectedPiece.size());
  auto sigBuffer = make_shared<Buffer>(blsGetSerializedSignatureByteSize());
  auto writtenSize = blsSignatureSerialize(sigBuffer->data(), sigBuffer->size(), &outputSig);
  if (writtenSize == 0) {
    NDN_THROW(std::runtime_error("Error on serializing"));
  }
  sigBuffer->resize(writtenSize);

  dataWithInfo.setSignatureValue(sigBuffer);
  dataWithInfo.wireEncode();
}

}  // namespace ndn