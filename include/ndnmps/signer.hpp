#ifndef NDNMPS_SIGNER_HPP
#define NDNMPS_SIGNER_HPP

#include <iostream>
#include <map>
#include <tuple>
#include <ndn-cxx/face.hpp>

#include "ndnmps/bls-helpers.hpp"
#include "ndnmps/mps-signer-list.hpp"
#include "ndnmps/schema.hpp"

namespace ndn {
namespace mps {

/**
 * The signer class class that handles functionality in the multi-signing protocol.
 * Note that it is different from MpsSigner, which only provides signing and packet encoding.
 */
class BLSSigner {
private:
  Face& m_face;
  function<bool(const Data&)> m_dataVerifyCallback;
  function<bool(const Interest&)> m_interestVerifyCallback;
  std::list<RegisteredPrefixHandle> m_handles;

  // Key: RequestID, Code, SignatureBlock, version
  struct RequestInstance {
    // ECDH State: AES Key, HMAC Key
    ReplyCode code;
    Buffer signatureValue;
    size_t version;
  };
  std::map<uint64_t, RequestInstance> m_results;

  // Self key pair
  BLSSecretKey m_sk;
  BLSPublicKey m_pk;
  Name m_keyName;

public:
  const Name m_prefix;

public:
  /**
   * Construct the signer participant in the protocol
   * @param mpsSigner the signer that signs data
   * @param prefix the routable prefix to register prefix to
   * @param face the network interface.
   */
  BLSSigner(const Name& prefix, Face& face, const Name& keyName);

  /**
   * the destructor. Currently remove the prefix registration.
   */
  ~BLSSigner();

  /**
   * Set the behavior when verifying the unsigned data.
   * Default to returning false at all time.
   * @param func the function to be called when verifying a unsigned data for endorsement.
   */
  void
  setDataVerifyCallback(const function<bool(const Data&)>& func);

  /**
   * Set the behavior when verifying the signature from the initiator
   * @param func the function to verify the initiator signature.
   */
  void
  setSignatureVerifyCallback(const function<bool(const Interest&)>& func);

  const BLSPublicKey&
  getPublicKey() {
    return m_pk;
  }

private:
  void
  onSignRequest(const Interest&);

  void
  onResultFetch(const Interest&);

  Data
  generateAck(const Name& interestName, ReplyCode code, uint64_t requestId) const;
};

}  // namespace mps
}  // namespace ndn

#endif  // NDNMPS_SIGNER_HPP