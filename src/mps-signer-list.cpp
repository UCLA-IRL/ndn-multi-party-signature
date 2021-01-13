//
// Created by Tyler on 12/29/20.
//

#include "ndnmps/mps-signer-list.hpp"
#include <utility>

namespace ndn {

MpsSignerList::MpsSignerList(std::vector<Name>&& signers)
    : std::vector<Name>(std::move(signers))
{
}
MpsSignerList::MpsSignerList(const std::vector<Name>& signers)
        : std::vector<Name>(signers)
{
}

MpsSignerList::MpsSignerList(const Block& wire)
    : std::vector<Name>()
{
  wireDecode(wire);
}

Block
MpsSignerList::wireEncode() const
{
  auto wire = Block(tlv::MpsSignerList);
  for (const auto& item : *this) {
    wire.push_back(item.wireEncode());
  }
  wire.encode();
  return wire;
}

void
MpsSignerList::wireDecode(const Block& wire)
{
  if (wire.type() != tlv::MpsSignerList)
    NDN_THROW(tlv::Error("MultiPartySignerList", wire.type()));
  clear();
  wire.parse();
  for (const auto& item : wire.elements()) {
    emplace_back(item);
  }
}

std::ostream&
operator<<(std::ostream& os, const MpsSignerList& signerList)
{
  os << "MpsSignerList [ ";
  for (const auto& i : signerList) {
    os << i << ", ";
  }
  return os << "]";
}

}  // namespace ndn