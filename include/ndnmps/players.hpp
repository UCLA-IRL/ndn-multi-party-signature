#include <mcl/bn_c384_256.h>
#include <bls/bls.h>
#include <ndn-cxx/data.hpp>

#include <iostream>
#include <map>
#include "ndnmps/schema.hpp"

namespace ndn {

class Signer {
private:
  blsSecretKey m_sk;
  blsPublicKey m_pk;

public:
  /**
   * @brief Generate public and secret key pair.
   */
  Signer();

  /**
   * @brief Initialize public and secret key pair from secret key serialization.
   */
  Signer(Buffer secretKeyBuf);

  /**
   * @brief Get public key.
   */
  blsPublicKey
  getPublicKey();

  /**
   * @brief Generate public key for network transmission.
   */
  std::vector<uint8_t>
  getpublicKeyStr();
};

class Verifier {
private:
  std::map<std::string, blsPublicKey> m_certs;

public:

  Verifier();

  void
  addCert(const std::string& keyName, blsPublicKey pk);

  void
  verifySignature(const blsSignature& sig, const MultipartySchema& schema);
};

typedef function<void(const Data& signedData)> SignatureFinishCallback;
typedef function<void(const Data& unfinishedData, const std::string& reason)> SignatureFailureCallback;

class Initiator {
public:

  Initiator();

  void
  startSigningProcess(const MultipartySchema& schema, const Data& unfinishedData,
                      const SignatureFinishCallback& successCb, const SignatureFailureCallback& failureCab);

private:
  void
  onTimeout();

  void
  onNack();

  void
  onData();
};

}  // namespace ndn