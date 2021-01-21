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

/**
 * The signer class for maintaining secret/public key pair, sign and encode data packet.
 * Note that is is different from Signer from players.hpp as the other primary provides functionality
 * for signing protocol.
 */
class MpsSigner {
private:
  Name m_signerName;
  blsSecretKey m_sk;
  blsPublicKey m_pk;

public:
  /**
   * Construct the signers that provide packet encoding and signing.
   * Generate public and secret key pair.
   */
  MpsSigner(const Name& signerName);

  /**
   * Construct the signers that provide packet encoding and signing.
   * Initialize public and secret key pair from secret key serialization.
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
  sign(Data& data, const Name& keyLocatorName = Name()) const;
};

/**
 * The verifies class for maintaining public keys and signer lists, decode and verifies data packet.
 * Note that is is different from Verifier from players.hpp as the other primary provides functionality
 * for signing protocol.
 */
class MpsVerifier {
private:
  std::map<Name, blsPublicKey> m_certs;
  std::map<Name, MpsSignerList> m_signLists;
  mutable std::map<Name, blsPublicKey> m_aggregateKey;  //should be cache, not from network transmission for security reasons

public:
  /**
   * Construct the verifier that provide packet decoding and verification.
   */
  MpsVerifier();

  /**
   * Add trusted BLS keys to the verifier.
   * @param keyName the name of the key
   * @param pk the public key of the BLS key
   */
  void
  addCert(const Name& keyName, blsPublicKey pk);

  /**
   * Add obtained signer list to the verifier.
   * @param listName the name of the signer list
   * @param list the signer list
   */
  void
  addSignerList(const Name& listName, MpsSignerList list);

  /**
   * return the container for trusted keys.
   * @return the set of trusted keys.
   */
  std::map<Name, blsPublicKey>&
  getCerts();

  /**
   * return the container for known signer lists.
   * @return the set of known signer lists.
   */
  std::map<Name, MpsSignerList>&
  getSignerLists();

  /**
   * return the const container for trusted keys.
   * @return the set of trusted keys.
   */
  const std::map<Name, blsPublicKey>&
  getCerts() const;

  /**
   * return the const container for known signer lists.
   * @return the set of known signer lists.
   */
  const std::map<Name, MpsSignerList>&
  getSignerLists() const;

  /**
   * Check if the data is ready to verify. That is, the signer list is known and keys are known.
   * @param data the data to be checked
   * @return true of the ready to verify without further information.
   */
  bool
  readyToVerify(const Data& data) const;

  /**
   * return the set of (currently known)names to be fetched before the verifier is able to verify this data.
   * @param data the data to be checked
   * @return the set of names to be fetched to verify this data.
   */
  std::vector<Name>
  itemsToFetch(const Data& data) const;

  /**
   * verify the (multi-) signature of the packet.
   * @param data the data to be checked
   * @param schema the trust schema to check the data against.
   * @return true if the verifier verifies this data's signature successfully; false otherwise
   */
  bool
  verifySignature(const Data& data, const MultipartySchema& schema) const;

  /**
   * verify a signle piece of signature of the packet, from a signer.
   * @param data the unsigned data to be checked
   * @param info the signature info to be used
   * @param signedBy the signer name
   * @param signaturePiece the piece of signature value given.
   * @return true if the verifier verifies this signature piece successfully; false otherwise
   */
  bool
  verifySignaturePiece(Data data, const SignatureInfo& info, const Name& signedBy, const Block& signaturePiece) const;

  /**
   * Verify the sigature piece with the signature info already in the given data.
   * @param dataWithInfo the unsigned data to be checked, with the signature info already set
   * @param signedBy the signer name
   * @param signaturePiece the piece of signature value given.
   * @return true if the verifier verifies this signature piece successfully; false otherwise
   */
  bool
  verifySignaturePiece(const Data& dataWithInfo, const Name& signedBy, const Block& signaturePiece) const;
};

/**
 * The aggregater class for aggregating the signature piece.
 */
class MpsAggregater {
public:
  /**
   * Construct the aggregator that aggregates the signature pieces and signs the data.
   */
  MpsAggregater();

  /**
   * Build the multisignature based on the given pieces of signature.
   * @param data the unsigned data, will be signed at return
   * @param sigInfo the signature info the this data
   * @param collectedPiece the collected piece to be aggregated.
   */
  void
  buildMultiSignature(Data& data, const SignatureInfo& sigInfo,
                      const std::vector<blsSignature>& collectedPiece) const;

  /**
   * Build the multisignature based on the given pieces of signature.
   * @param data the unsigned data(with signature info already in place), will be signed at return
   * @param collectedPiece the collected piece to be aggregated.
   */
  void
  buildMultiSignature(Data& dataWithInfo, const std::vector<blsSignature>& collectedPiece) const;
};

}  // namespace ndn

#endif  // NDNMPS_CRYPTO_PLAYERS_HPP