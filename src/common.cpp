#include <ndn-cxx/util/backports.hpp>
#include "ndnmps/common.hpp"

namespace ndn {
namespace tlv {

std::ostream&
operator<<(std::ostream& os, ExtendedSignatureTypeValue st)
{
    switch (st) {
        case ExtendedSignatureTypeValue::DigestSha256:
            return os << "DigestSha256";
        case ExtendedSignatureTypeValue::SignatureSha256WithRsa:
            return os << "SignatureSha256WithRsa";
        case ExtendedSignatureTypeValue::SignatureSha256WithEcdsa:
            return os << "SignatureSha256WithEcdsa";
        case ExtendedSignatureTypeValue::SignatureHmacWithSha256:
            return os << "SignatureHmacWithSha256";
        case ExtendedSignatureTypeValue::SignatureSha256WithBls:
            return os << "SignatureSha256WithBls";
    }
    return os << "Unknown(" << static_cast<uint32_t>(st) << ')';
}

}

std::ostream&
operator<<(std::ostream& os, ExtendedKeyType keyType)
{
    switch (keyType) {
        case ExtendedKeyType::NONE:
            return os << "NONE";
        case ExtendedKeyType::RSA:
            return os << "RSA";
        case ExtendedKeyType::EC:
            return os << "EC";
        case ExtendedKeyType::AES:
            return os << "AES";
        case ExtendedKeyType::BLS:
            return os << "BLS";
        case ExtendedKeyType::HMAC:
            return os << "HMAC";
        }
        return os << to_underlying(keyType);
    }

}