#ifndef NDNMPS_CRYPTO_PLAYERS_HPP
#define NDNMPS_CRYPTO_PLAYERS_HPP

#include "ndnmps/schema.hpp"
#include "mps-signer-list.hpp"
#include <mcl/bn_c384_256.h>
#include <bls/bls.hpp>
#include <ndn-cxx/data.hpp>

#include <iostream>
#include <map>

namespace ndn {

class MpsSigner {
private:
  Name m_signerName;
  blsSecretKey m_sk;
  blsPublicKey m_pk;

public:
  /**
   * @brief Generate public and secret key pair.
   */
  MpsSigner(Name signerName);

  /**
   * @brief Initialize public and secret key pair from secret key serialization.
   */
  MpsSigner(Name signerName, Buffer secretKeyBuf);

  /**
   * @brief Get identity name.
   */
  Name
  getSignerKeyName() const;

  /**
   * @brief Get public key.
   */
  blsPublicKey
  getPublicKey() const;

  /**
   * @brief Get secret key.
   * @warning The secret key SHOULD NEVER be transmitted over unsecured network
   */
  blsSecretKey
  getSecretKey() const;

  /**
   * @brief Generate public key for network transmission.
   */
  std::vector<uint8_t>
  getpublicKeyStr() const;

  /**
   * Return the signature value for the packet.
   * @param data the unsigned data packet
   * @param sigInfo the signature info to be used
   * @return the signature value signed by this signer
   */
  Block
  getSignature(Data data, const SignatureInfo& sigInfo) const;

  /**
   * sign the packet for the packet (as the only signer).
   * @param data the unsigned data packet
   * @param sigInfo the signature info to be used
   * @return the signature value signed by this signer
   */
  void
  sign(Data& data) const;
};

class MpsVerifier {
private:
  std::map<Name, blsPublicKey> m_certs;
  std::map<Name, MpsSignerList> m_signList;
  mutable std::map<Name, blsPublicKey> m_aggregateKey; //should be cache, not from network transmission for security reasons

public:

  MpsVerifier();

  void
  addCert(const Name& keyName, blsPublicKey pk);

  void
  addSignerList(const Name& listName, MpsSignerList list);

  bool
  readyToVerify(const Data& data) const;

  std::vector<Name>
  itemsToFetch(const Data& data) const;

  bool
  verifySignature(const Data& data, const MultipartySchema& schema) const;

  bool
  verifySignaturePiece(Data data, const SignatureInfo& info, const Name& signedBy, const Block& signaturePiece) const;
};

class MpsAggregater {
public:
    MpsAggregater();

    void
    buildMultiSignature(Data& data, const SignatureInfo& sigInfo,
                        const std::vector<blsSignature>& collectedPiece) const;
    static optional<SignatureInfo>
    getMinMPSignatureInfo(const MultipartySchema& schema, const std::vector<Name>& availableSingerKeys);

};

}  // namespace ndn

#endif // NDNMPS_CRYPTO_PLAYERS_HPP