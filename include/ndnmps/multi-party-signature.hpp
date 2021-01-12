#ifndef NDNMPS_MULTI_PARTY_SIGNATURE
#define NDNMPS_MULTI_PARTY_SIGNATURE

#include <ndn-cxx/signature.hpp>
#include <set>

namespace ndn {

class MultiPartySignature {
private:
public:
  MultiPartySignature(/* args */);
  ~MultiPartySignature();

public:
  static SignatureInfo
  getMultiPartySignatureInfo(const std::set<Name>& keys);
};

}  // namespace ndn

#endif  // NDNMPS_MULTI_PARTY_SIGNATURE