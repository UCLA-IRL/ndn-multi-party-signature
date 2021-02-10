#ifndef NDNMPS_MPS_SIGNER_LIST_HPP
#define NDNMPS_MPS_SIGNER_LIST_HPP

#include <ndn-cxx/name.hpp>
#include <set>

#include "common.hpp"

namespace ndn {
namespace mps {

class MpsSignerList
{
public:
  std::vector<Name> m_signers;

public:  // constructors
  /** \brief Construct an empty list.
   *  \post `empty() == true`
   */
  MpsSignerList() = default;

  /** \brief Construct from vector of names.
   *  \note Implicit conversion is permitted.
   *  \post `getType() == tlv::Name`
   */
  MpsSignerList(std::vector<Name>&& signers);
  MpsSignerList(const std::vector<Name>& signers);

  /** \brief Construct from wire encoding.
   */
  MpsSignerList(const Block& wire);

public:
  /**
   * Encode the signer list to a block
   * @return the corresponding block from signer list
   */
  Block
  wireEncode() const;

  /**
   * Decode the signer list from a block
   * @param wire the block to decode from
   */
  void
  wireDecode(const Block& wire);

  /**
   * Encode the signer list as a block into a encoder
   * @param encoder the block to be encoded
   */
  template <encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;

public:
  /**
   * Compare the signer list. The comparison returns true if both side have the same names.
   * @param rhs the other side of comparison
   * @return true of both side have the same set of names.
   */
  bool
  operator==(const MpsSignerList& rhs) {
    std::vector<Name> nameList(m_signers.begin(), m_signers.end());
    std::vector<Name> rhsNameList(rhs.m_signers.begin(), rhs.m_signers.end());
    std::sort(nameList.begin(), nameList.end());
    std::sort(rhsNameList.begin(), rhsNameList.end());
    return nameList == rhsNameList;
  }

  bool
  operator!=(const MpsSignerList& rhs) {
    return !operator==(rhs);
  }
};

std::ostream&
operator<<(std::ostream& os, const MpsSignerList& signerList);

}  // namespace mps
}  // namespace ndn

#endif  //NDNMPS_MPS_SIGNER_LIST_HPP
