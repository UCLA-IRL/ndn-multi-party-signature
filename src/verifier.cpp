#include "ndnmps/verifier.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <utility>

namespace ndn {
namespace mps {

NDN_LOG_INIT(ndnmps.blsverifier);

BLSVerifier::BLSVerifier(Face& face, bool fetchKeys)
    : m_face(face)
{}

bool
BLSVerifier::verify(const Data& data, const Data& signatureInfoData)
{
  // check key locator matches infoData
  try {
    auto keyLocatorName = data.getSignatureInfo().getKeyLocator().getName();
    if (!keyLocatorName.isPrefixOf(signatureInfoData.getName())) {
      return false;
    }
  }
  catch (const std::exception& e) {
    return false;
  }

  // check signer list
  MpsSignerList signerList;
  const auto& signerListBlock = data.getContent();
  signerListBlock.parse();
  if (signerListBlock.get(tlv::MpsSignerList).isValid()) {
    signerList.wireDecode(signerListBlock.get(tlv::MpsSignerList));
  }
  // TODO: add trust anchors into m_schemas
  if (!m_schemas.isSatisfied(data.getName(), signerList)) {
    return false;
  }
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
      interest.setInterestLifetime(TIMEOUT);
      m_face.expressInterest(
          interest,
          [&](const auto&, const auto& signatureInfoData) {
            auto isValid = verify(data, signatureInfoData);
            callback(isValid);
          },
          std::bind(&BLSVerifier::onNack, this, _1, _2),
          std::bind(&BLSVerifier::onTimeout, this, _1)
          );
}

void
BLSVerifier::asyncVerifySignature(shared_ptr<const Data> data,
                               shared_ptr<const MultipartySchema> schema,
                               const VerifyFinishCallback& callback)
{
  uint32_t currentId = random::generateSecureWord32();
  if (m_verifier->readyToVerify(*data)) {
    callback(m_verifier->verifySignature(*data, *schema));
  }
  else {
    //store, fetch and wait
    VerificationRecord r{data, schema, callback, 0};
    for (const auto& item : m_verifier->itemsToFetch(*data)) {
      Interest interest(item);
      interest.setCanBePrefix(true);
      interest.setMustBeFresh(true);
      interest.setInterestLifetime(TIMEOUT);
      m_face.expressInterest(
          interest,
          std::bind(&BLSVerifier::onData, this, _1, _2),
          std::bind(&BLSVerifier::onNack, this, _1, _2),
          std::bind(&BLSVerifier::onTimeout, this, _1));
      m_index[item].insert(currentId);
      r.itemLeft++;
    }
    m_queue.emplace(currentId, r);
  }
}

}  // namespace mps
}  // namespace ndn