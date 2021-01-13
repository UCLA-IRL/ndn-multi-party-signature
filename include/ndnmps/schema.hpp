#ifndef NDNMPS_SCHEMA_HPP
#define NDNMPS_SCHEMA_HPP

#include <ndn-cxx/name.hpp>
#include <nlohmann/json.hpp>
#include <set>
#include <list>
#include "mps-signer-list.hpp"

using Json = nlohmann::json;

namespace ndn {

class WildCardName : public Name {
public:

  WildCardName() = default;
  WildCardName(Name format);
  WildCardName(std::string str);
  WildCardName(const char * str);
  WildCardName(const Block& block);

  bool
  match(const Name& name) const;
};

/**
 * @brief configuration file to guide signing and verification.
 * TODO can be let a schema refer to other schema? we can make much more complex rules from it.
 */
class MultipartySchema {
public:
  WildCardName prefix; // Data name
  std::string ruleId; // rule ID
  std::vector<WildCardName> signers; // required signers
  std::vector<WildCardName> optionalSigners; // optional signers
  size_t minOptionalSigners; // min required optional signers

public:
  static MultipartySchema
  fromJSON(const std::string& fileOrConfigStr);

  static MultipartySchema
  fromINFO(const std::string& fileOrConfigStr);

  MultipartySchema();

  std::string
  toString();

  std::vector<Name>
  getKeyMatches(const Name& key) const;

  bool
  isSatisfied(const MpsSignerList& locator) const;

  std::set<Name>
  getMinSigners(const std::vector<Name>& availableKeys) const;

private:
  // static void
  // parseAssert(bool criterion);

  // static std::vector<std::pair<int, int>>
  // modifiedFordFulkerson(const std::vector<std::set<int>>& bipartiteAdjList,
  //                       int mustHaveSize, int optionalSize);

  // static bool
  // fordFulkersonDFS(const std::map<int, std::set<int>>& adjList, int start, int end, std::list<int>& path);
};

}  // namespace ndn

#endif  // NDNMPS_SCHEMA_HPP