#ifndef NDNMPS_COMMON_HPP
#define NDNMPS_COMMON_HPP

#include <cstdint>
#include <iostream>
namespace ndn {
namespace tlv {

enum : uint32_t {
    MultiPartyKeyLocator = 201,
};

/** @brief SignatureType values
 *  @sa https://named-data.net/doc/NDN-packet-spec/current/signature.html
 */
enum ExtendedSignatureTypeValue : uint16_t {
    //DigestSha256             = 0,
    //SignatureSha256WithRsa   = 1,
    //SignatureSha256WithEcdsa = 3,
    //SignatureHmacWithSha256  = 4,
    SignatureSha256WithBls   = 64,
};

std::ostream&
operator<<(std::ostream& os, ExtendedSignatureTypeValue st);
}

/**
 * @brief The type of a cryptographic key.
 */
enum class ExtendedKeyType {
    NONE = 0, ///< Unknown or unsupported key type
    RSA,      ///< RSA key, supports sign/verify and encrypt/decrypt operations
    EC,       ///< Elliptic Curve key (e.g. for ECDSA), supports sign/verify operations
    BLS,      ///< BLS key, supports sign/verify operations
    AES,      ///< AES key, supports encrypt/decrypt operations
    HMAC,     ///< HMAC key, supports sign/verify operations
};

std::ostream&
operator<<(std::ostream& os, ExtendedKeyType keyType);
}

#endif // NDNMPS_COMMON_HPP