#ifndef NDNMPS_COMMON_HPP
#define NDNMPS_COMMON_HPP

#include <cstdint>
#include <iostream>
#include <ndn-cxx/encoding/tlv.hpp>
namespace ndn {
namespace tlv {

enum : uint32_t {
    MpsSignerList = 201,
};

/** @brief Extended SignatureType values with Multi-Party Signature
 *  @sa https://named-data.net/doc/NDN-packet-spec/current/signature.html
 */
enum MpsSignatureTypeValue : uint16_t {
    SignatureSha256WithBls   = 64,
};

std::ostream&
operator<<(std::ostream& os, MpsSignatureTypeValue st);
}

/**
 * @brief The extended type of a cryptographic key with Multi-Party Signature.
 */
enum class MpsKeyType {
    NONE = 0, ///< Unknown or unsupported key type
    RSA,      ///< RSA key, supports sign/verify and encrypt/decrypt operations
    EC,       ///< Elliptic Curve key (e.g. for ECDSA), supports sign/verify operations
    BLS,      ///< BLS key, supports sign/verify operations
    AES,      ///< AES key, supports encrypt/decrypt operations
    HMAC,     ///< HMAC key, supports sign/verify operations
};

std::ostream&
operator<<(std::ostream& os, MpsKeyType keyType);
}

#endif // NDNMPS_COMMON_HPP