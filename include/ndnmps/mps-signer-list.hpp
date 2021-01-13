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
  MpsSignerList(const std::vector<Name>& signers);

  /** \brief Construct from wire encoding.
   */
  MpsSignerList(const Block& wire);

public:
  Block
  wireEncode() const;

  void
  wireDecode(const Block& wire);
};

std::ostream&
operator<<(std::ostream& os, const MpsSignerList& signerList);

}  // namespace ndn

#endif  //NDNMPS_MPS_SIGNER_LIST_HPP
