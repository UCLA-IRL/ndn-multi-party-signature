#include "ndnmps/verifier.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <utility>

namespace ndn {
namespace mps {

NDN_LOG_INIT(ndnmps.blsverifier);

BLSVerifier::BLSVerifier(Face& face)
    : m_face(face)
{
}

bool
BLSVerifier::verify(const Data& data, const Data& signatureInfoData)
{
  // check key locator matches infoData
  try {
    auto keyLocatorName = data.getSignatureInfo().getKeyLocator().getName();
    if (!keyLocatorName.isPrefixOf(signatureInfoData.getName())) {
      NDN_LOG_INFO("key locator name does not match signature info data");
      return false;
    }
  }
  catch (const std::exception& e) {
    NDN_LOG_INFO("key locator is not a name or does not exist");
    return false;
  }

  // check signer list
  MpsSignerList signerList;
  const auto& signerListBlock = signatureInfoData.getContent();
  signerListBlock.parse();
  if (signerListBlock.get(tlv::MpsSignerList).isValid()) {
    signerList.wireDecode(signerListBlock.get(tlv::MpsSignerList));
  }
  if (!m_schemaContainer.passSchema(data.getName(), signerList)) {
    NDN_LOG_INFO("signer list cannot pass the schema");
    return false;
  }

  // verify signature
  BLSPublicKey aggKey;
  aggKey = m_schemaContainer.aggregateKey(signerList);
  return ndnBLSVerify(aggKey, data);
}

void
BLSVerifier::asyncVerify(const Data& data, const VerifyFinishCallback& callback)
{
  Name keyLocatorName;
  try {
    keyLocatorName = data.getSignatureInfo().getKeyLocator().getName();
  }
  catch (const std::exception& e) {
    callback(false);
    return;
  }

  Interest interest(keyLocatorName);
  interest.setCanBePrefix(true);
  interest.setMustBeFresh(true);
  m_face.expressInterest(
      interest,
      [&](const auto&, const auto& signatureInfoData) {
        auto isValid = verify(data, signatureInfoData);
        callback(isValid);
      },
      [&](const auto&, const auto&) {
        callback(false);
      },
      [&](const auto&) {
        callback(false);
      });
}

}  // namespace mps
}  // namespace ndn