#ifndef NDNMPS_SIGNER_HPP
#define NDNMPS_SIGNER_HPP

#include "ndnmps/bls-helpers.hpp"
#include "ndnmps/mps-signer-list.hpp"
#include "ndnmps/schema.hpp"
#include "ndnmps/crypto-helpers.hpp"
#include <ndn-cxx/face.hpp>
#include <iostream>
#include <map>
#include <tuple>

namespace ndn {
namespace mps {

using VerifyToBeSignedCallback = function<bool(const Data&)>;
using VerifySignRequestCallback = function<bool(const Interest&)>;

/**
 * The signer class class that handles functionality in the multi-signing protocol.
 * Note that it is different from MpsSigner, which only provides signing and packet encoding.
 */
class BLSSigner
{
private:
  Face& m_face;
  VerifyToBeSignedCallback m_verifyToBeSignedCallback;
  VerifySignRequestCallback m_verifySignRequestCallback;
  RegisteredPrefixHandle m_signRequestHandle;

  // Self key pair
  BLSSecretKey m_sk;
  BLSPublicKey m_pk;
  Name m_keyName;

public:
  const Name m_prefix;

public:
  /**
   * Construct the signer participant in the protocol
   * @param mpsSigner The signer that signs data
   * @param face The network interface.
   * @param verifyToBeSignedCallback The function to be called when verifying a unsigned data for endorsement.
   * @param verifySignRequestCallback The function to verify the initiator signature.
   * @param prefix The routable prefix to register prefix to. When empty, will automatically generate key name as
   *               /prefix/KEY/[timestamp]
   */
  BLSSigner(const Name& prefix, Face& face,
            const Name& keyName = Name(),
            const VerifyToBeSignedCallback& verifyToBeSignedCallback = [](auto) { return true; },
            const VerifySignRequestCallback& verifySignRequestCallback = [](auto) { return true; });

  ~BLSSigner();

  const BLSPublicKey&
  getPublicKey()
  {
    return m_pk;
  }

  Name
  getPublicKeyName()
  {
    return m_keyName;
  }

private:
  void
  onSignRequest(const Interest&);
};

}  // namespace mps
}  // namespace ndn

#endif  // NDNMPS_SIGNER_HPP