#include <bls/bls384_256.h>
#include <ndn-cxx/data.hpp>

#include <iostream>
#include <map>
#include <schema.hpp>

namespace ndn {

class Signer {
private:
  blsSecretKey m_sk;
  blsPublicKey m_pk;

public:
  /**
   * @brief Generate public and secret key pair.
   */
  void
  initKey();

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
  void
  addCert(const std::string& keyName, blsPublicKey pk);

  void
  verifySignature(const blsSignature& sig, const MultipartySchema& schema);
};

typedef function<void()> onSignatureFinishCallback;

class Initiator {
public:
  void
  startSigningProcess(const MultipartySchema& schema, const std::string& content);

private:
  void
  onTimeout();

  void
  onNack();

  void
  onData();
};

}  // namespace ndn