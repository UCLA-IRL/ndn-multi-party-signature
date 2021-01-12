//
// Created by Tyler on 12/29/20.
//

#ifndef NDNMPS_MPS_SIGNER_LIST_HPP
#define NDNMPS_MPS_SIGNER_LIST_HPP

#include <ndn-cxx/name.hpp>
#include <set>

#include "ndnmps/common.hpp"

namespace ndn {

class MpsSignerList {
public:
  class Error : public tlv::Error {
  public:
    using tlv::Error::Error;
  };

public:  // constructors
  /** \brief Construct an empty list.
     *  \post `empty() == true`
     */
  MpsSignerList();

  /** \brief Construct from vector of names.
     *  \note Implicit conversion is permitted.
     *  \post `getType() == tlv::Name`
     */
  MpsSignerList(std::set<Name> signers);

  /** \brief Construct from wire encoding.
     */
  explicit MpsSignerList(const Block& wire);

public:  // encode and decode
  /** \brief Prepend wire encoding to \p encoder.
     */
  template <encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;

  const Block&
  wireEncode() const;

  /** \brief Decode from wire encoding.
     *  \throw Error outer TLV type is not KeyLocator
     *  \note No error is raised for an unrecognized nested TLV, but attempting to reencode will throw.
     */
  void
  wireDecode(const Block& wire);

  const std::set<Name>&
  getSigners() const;

  std::set<Name>&
  getSigners();

  void
  setSigners(const std::set<Name>& locators);

private: // non-member operators
  // NOTE: the following "hidden friend" operators are available via
  //       argument-dependent lookup only and must be defined inline.

  friend bool
  operator==(const MpsSignerList& lhs, const MpsSignerList& rhs)
  {
    return lhs.m_locators == rhs.m_locators;
  }

  friend bool
  operator!=(const MpsSignerList& lhs, const MpsSignerList& rhs)
  {
    return lhs.m_locators != rhs.m_locators;
  }

private:
  std::set<Name> m_locators;
  mutable Block m_wire;
};

NDN_CXX_DECLARE_WIRE_ENCODE_INSTANTIATIONS(MpsSignerList);

std::ostream&
operator<<(std::ostream& os, const MpsSignerList& signerList);

}  // namespace ndn

#endif  //NDNMPS_MPS_SIGNER_LIST_HPP
