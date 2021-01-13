//
// Created by Tyler on 12/29/20.
//

#ifndef NDNMPS_MPS_SIGNER_LIST_HPP
#define NDNMPS_MPS_SIGNER_LIST_HPP

#include <ndn-cxx/name.hpp>
#include <set>

#include "ndnmps/common.hpp"

namespace ndn {

class MpsSignerList: public std::vector<Name> {

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
  Block
  wireEncode() const;

  void
  wireDecode(const Block& wire);

public:
  bool
  operator==(const MpsSignerList& rhs) {
    std::vector<Name> nameList(this->begin(), this->end());
    std::vector<Name> rhsNameList(rhs.begin(), rhs.end());
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

}  // namespace ndn

#endif  //NDNMPS_MPS_SIGNER_LIST_HPP
