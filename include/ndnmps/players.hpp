#include "ndnmps/schema.hpp"
#include "mps-signer-list.hpp"
#include <mcl/bn_c384_256.h>
#include <bls/bls.hpp>
#include <ndn-cxx/data.hpp>

#include <iostream>
#include <map>

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

  /**
   * Return the signature value for the packet.
   * @param data the unsigned data packet
   * @param sigInfo the signature info to be used
   * @return the signature value signed by this signer
   */
  Block
  getSignature(Data data, const SignatureInfo& sigInfo);

  /**
   * sign the packet for the packet (as the only signer).
   * @param data the unsigned data packet
   * @param sigInfo the signature info to be used
   * @return the signature value signed by this signer
   */
  void
  sign(Data& data, const Name& keyName);
};

class Verifier {
private:
  std::map<Name, blsPublicKey> m_certs;

public:

  Verifier();

  void
  addCert(const Name& keyName, blsPublicKey pk);

  bool
  verifySignature(const Data& data, const MultipartySchema& schema);

  bool
  verifySignaturePiece(Data data, const SignatureInfo& info, const Name& signedBy, const Block& signaturePiece);
};

typedef function<void(const Data& signedData)> SignatureFinishCallback;
typedef function<void(const Data& unfinishedData, const std::string& reason)> SignatureFailureCallback;

class Initiator {
public:

  Initiator();

  static void
  buildMultiSignature(Data& data, const SignatureInfo& sigInfo,
          const std::vector<blsSignature>& collectedPiece);

  static optional<SignatureInfo>
  getMinMPSignatureInfo(const MultipartySchema& schema, const std::vector<Name>& availableSingerKeys);

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