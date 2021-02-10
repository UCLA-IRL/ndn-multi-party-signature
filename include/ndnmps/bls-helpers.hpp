#ifndef NDNMPS_SRC_BLS_HELPER_HPP
#define NDNMPS_SRC_BLS_HELPER_HPP

#include "common.hpp"

#define BLS_ETH

#include <bls/bls384_256.h>
#include <bls/bls.hpp>

#include <iostream>
#include <map>

namespace ndn {
namespace mps {

using BLSSecretKey = bls::SecretKey;
using BLSPublicKey = bls::PublicKey;
using BLSSignature = bls::Signature;

void
ndnBLSInit();

/**
 * Return the signature value for the packet.
 * @param data the unsigned data packet
 * @param sigInfo the signature info to be used
 * @return the signature value signed by this signer
 */
Buffer
ndnGenBLSSignature(const BLSSecretKey& signingKey, const Data& data, const SignatureInfo& sigInfo);

/**
 * Return the signature value for the packet with signature info already in the data
 * @param data the unsigned data packet with info
 * @return the signature value signed by this signer
 */
Buffer
ndnGenBLSSignature(const BLSSecretKey& signingKey, const Data& dataWithInfo);

/**
 * Return the signature value for the packet.
 * @param data the unsigned data packet
 * @param sigInfo the signature info to be used
 * @return the signature value signed by this signer
 */
Buffer
ndnGenBLSSignature(const BLSSecretKey& signingKey, const Interest& interest, const SignatureInfo& sigInfo);

/**
 * Return the signature value for the packet with signature info already in the data
 * @param data the unsigned data packet with info
 * @return the signature value signed by this signer
 */
Buffer
ndnGenBLSSignature(const BLSSecretKey& signingKey, const Interest& interest);

/**
 * sign the packet (as the only signer).
 * @param data the unsigned data packet, modified to signed packet
 * @param keyLocatorName the key name to place in key locator
 */
void
ndnBLSSign(const BLSSecretKey& signingKey, Data& data, const Name& keyLocatorName);

/**
 * sign the interest packet (as the only signer).
 * @param interest the unsigned data packet, modified to signed packet
 * @param keyLocatorName the key name to place in key locator (if empty use this signer's name)
 */
void
ndnBLSSign(const BLSSecretKey& signingKey, Interest& interest, const Name& keyLocatorName);

/**
 * sign the packet (as the only signer).
 * @param data the unsigned data packet, modified to signed packet
 * @param sigInfo sets the custom signature info
 * @param keyLocatorName the key name to place in key locator (if empty use this signer's name)
 */
void
ndnBLSSign(const BLSSecretKey& signingKey, Data& data, const SignatureInfo& sigInfo);

/**
 * sign the interest packet (as the only signer).
 * @param interest the unsigned data packet, modified to signed packet
 * @param sigInfo sets the custom signature info
 * @param keyLocatorName the key name to place in key locator (if empty use this signer's name)
 */
void
ndnBLSSign(const BLSSecretKey& signingKey, Interest& interest, const SignatureInfo& sigInfo);

/**
 * generate a self sign certificate for this signer
 * @param period the expected validity period
 * @return the generated certificate
 */
security::Certificate
ndnGenBLSSelfCert(const BLSPublicKey& pubKey, const BLSSecretKey& signingKey,
                  const security::ValidityPeriod& period);

bool
ndnBLSVerify(const BLSPublicKey& pubKey, const Data& data);

bool
ndnBLSVerify(const std::vector<BLSPublicKey>& pubKeys, const Data& data);

bool
ndnBLSVerify(const BLSPublicKey& pubKey, const Interest& interest);

bool
ndnBLSVerify(const std::vector<BLSPublicKey>& pubKeys, const Interest& interest);

BLSPublicKey
ndnBLSAggregatePublicKey(const std::vector<BLSPublicKey>& pubKeys);

Buffer
ndnBLSAggregateSignature(const std::vector<Buffer>& signatures);

BLSSignature
ndnBLSAggregateSignature(const std::vector<BLSSignature>& signatures);

} // mps
} // ndn

#endif // NDNMPS_SRC_BLS_HELPER_HPP