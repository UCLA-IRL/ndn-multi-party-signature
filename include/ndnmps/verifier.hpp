#ifndef NDNMPS_VERIFIER_HPP
#define NDNMPS_VERIFIER_HPP

#include <iostream>
#include <map>
#include <tuple>
#include <ndn-cxx/face.hpp>

#include "ndnmps/bls-helpers.hpp"
#include "ndnmps/mps-signer-list.hpp"
#include "ndnmps/schema.hpp"

namespace ndn {
namespace mps {

typedef function<void(bool)> VerifyFinishCallback;

/**
 * The class for verifier, which will fetch the unknown data.
 * Note that this is different from MpsVerifier, which will not fetch the data from network.
 */
class BLSVerifier {
private:
  Face& m_face;

public:
  // known schemas and identities
  MultipartySchemaContainer m_schemaContainer;

public:
  /**
   * Construct the verifier.
   * @param face the network interface.
   */
  BLSVerifier(Face& face);

  bool
  verify(const Data& data, const Data& signatureInfoData);

  void
  asyncVerify(const Data& data, const VerifyFinishCallback& callback);
};

}  // namespace mps
}  // namespace ndn

#endif  // NDNMPS_VERIFIER_HPP