#include "ndnmps/common.hpp"

#include <ndn-cxx/util/backports.hpp>

namespace ndn {
namespace tlv {

std::ostream&
operator<<(std::ostream& os, MpsSignatureTypeValue st)
{
  switch (static_cast<uint16_t>(st)) {
  case DigestSha256:
    return os << "DigestSha256";
  case SignatureSha256WithRsa:
    return os << "SignatureSha256WithRsa";
  case SignatureSha256WithEcdsa:
    return os << "SignatureSha256WithEcdsa";
  case SignatureHmacWithSha256:
    return os << "SignatureHmacWithSha256";
  case SignatureSha256WithBls:
    return os << "SignatureSha256WithBls";
  }
  return os << "Unknown(" << static_cast<uint32_t>(st) << ')';
}

}  // namespace tlv

std::ostream&
operator<<(std::ostream& os, MpsKeyType keyType)
{
  switch (keyType) {
  case MpsKeyType::NONE:
    return os << "NONE";
  case MpsKeyType::RSA:
    return os << "RSA";
  case MpsKeyType::EC:
    return os << "EC";
  case MpsKeyType::AES:
    return os << "AES";
  case MpsKeyType::BLS:
    return os << "BLS";
  case MpsKeyType::HMAC:
    return os << "HMAC";
  }
  return os << to_underlying(keyType);
}

}  // namespace ndn