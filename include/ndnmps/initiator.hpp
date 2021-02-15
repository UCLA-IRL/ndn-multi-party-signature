#ifndef NDNMPS_INITIATOR_HPP
#define NDNMPS_INITIATOR_HPP

#include <iostream>
#include <map>
#include <tuple>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/security/interest-signer.hpp>

#include "bls-helpers.hpp"
#include "mps-signer-list.hpp"
#include "schema.hpp"

namespace ndn {
namespace mps {

typedef function<void(const Data& data, const Data& signerListData)> SignatureFinishCallback;
typedef function<void(const std::string& reason)> SignatureFailureCallback;

/**
 * The signer class class that handles functionality in the multi-signing protocol.
 * Note that it is different from MpsSigner, which only provides signing and packet encoding.
 */
class MPSInitiator {
private:
  KeyChain& m_keyChain;
  Face& m_face;
  Scheduler& m_scheduler;
  security::InterestSigner m_interestSigner;

public:
  const Name m_prefix;
  MultipartySchemaContainer m_schemaContainer;

public:
  MPSInitiator(const Name& prefix, KeyChain& keyChain, Face& face, Scheduler& scheduler);

  /**
   * Initiate the multi-party signing.
   * @param schema the schema to satisfy with the signature.
   * @param unfinishedData the unsigned data to be (multi-) signed, must containing signature info.
   * @param successCb the callback then the data finished signing. Also returns the signer list.
   * @param failureCb the callback then the data failed to be signed. the reason will be returned.
   */
  void
  multiPartySign(const Data& unsignedData, const MultipartySchema& schema, const Name& signingKeyName,
                 const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCb);

private:
  void
  performRPC(const Name& signerKeyName, std::shared_ptr<Data> unfinishedData);
};

}  // namespace mps
}  // namespace ndn

#endif  // NDNMPS_INITIATOR_HPP