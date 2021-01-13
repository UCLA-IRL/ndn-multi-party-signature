//
// Created by Tyler on 12/29/20.
//

#include "ndnmps/mps-signer-list.hpp"
#include <utility>

namespace ndn {

MpsSignerList::MpsSignerList(const std::vector<Name>& signers)
    : m_signers(signers)
{
}

MpsSignerList::MpsSignerList(const Block& wire)
    : m_signers()
{
  wireDecode(wire);
}

Block
MpsSignerList::wireEncode() const
{
  auto wire = Block(tlv::MpsSignerList);
  for (const auto& item : m_signers) {
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
  m_signers.clear();
  wire.parse();
  for (const auto& item : wire.elements()) {
    m_signers.emplace_back(item);
  }
}

std::ostream&
operator<<(std::ostream& os, const MpsSignerList& signerList)
{
  os << "MpsSignerList [ ";
  for (const auto& i : signerList.m_signers) {
    os << i << ", ";
  }
  return os << "]";
}

}  // namespace ndn