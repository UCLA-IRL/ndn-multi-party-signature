#ifndef NDNMPS_CRYPTO_PLAYERS_HPP
#define NDNMPS_CRYPTO_PLAYERS_HPP

#define BLS_ETH
#include <bls/bls384_256.h>
#include <iostream>
#include <map>
#include <ndn-cxx/data.hpp>

#include "mps-signer-list.hpp"
#include "ndnmps/schema.hpp"

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
  MpsSigner(const Name& signerName);

  /**
   * @brief Initialize public and secret key pair from secret key serialization.
   */
  MpsSigner(const Name& signerName, const Buffer& secretKeyBuf);

  /**
   * @brief Get identity name.
   */
  const Name&
  getSignerKeyName() const;

  /**
   * @brief Get public key.
   */
  const blsPublicKey&
  getPublicKey() const;

  /**
   * @brief Get secret key.
   * @warning The secret key SHOULD NEVER be transmitted over unsecured network
   */
  const blsSecretKey&
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
     * Return the signature value for the packet with signature info already in the data
     * @param data the unsigned data packet with info
     * @return the signature value signed by this signer
     */
  Block
  getSignature(const Data& dataWithInfo) const;

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
  std::map<Name, MpsSignerList> m_signLists;
  mutable std::map<Name, blsPublicKey> m_aggregateKey;  //should be cache, not from network transmission for security reasons

public:
  MpsVerifier();

  void
  addCert(const Name& keyName, blsPublicKey pk);

  void
  addSignerList(const Name& listName, MpsSignerList list);

  std::map<Name, blsPublicKey>&
  getCerts();

  std::map<Name, MpsSignerList>&
  getSignerLists();

  const std::map<Name, blsPublicKey>&
  getCerts() const;

  const std::map<Name, MpsSignerList>&
  getSignerLists() const;

  bool
  readyToVerify(const Data& data) const;

  std::vector<Name>
  itemsToFetch(const Data& data) const;

  bool
  verifySignature(const Data& data, const MultipartySchema& schema) const;

  bool
  verifySignaturePiece(Data data, const SignatureInfo& info, const Name& signedBy, const Block& signaturePiece) const;

  /**
   * Verify the sigature piece with the signature info already in the given data.
   * @param dataWithInfo
   * @param signedBy
   * @param signaturePiece
   * @return true if verified; else false
   */
  bool
  verifySignaturePiece(const Data& dataWithInfo, const Name& signedBy, const Block& signaturePiece) const;
};

class MpsAggregater {
public:
  MpsAggregater();

  void
  buildMultiSignature(Data& data, const SignatureInfo& sigInfo,
                      const std::vector<blsSignature>& collectedPiece) const;

  void
  buildMultiSignature(Data& dataWithInfo, const std::vector<blsSignature>& collectedPiece) const;
};

}  // namespace ndn

#endif  // NDNMPS_CRYPTO_PLAYERS_HPP