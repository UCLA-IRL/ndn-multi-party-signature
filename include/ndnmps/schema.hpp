#ifndef NDNMPS_SCHEMA_HPP
#define NDNMPS_SCHEMA_HPP

#include <list>
#include <ndn-cxx/name.hpp>
#include <nlohmann/json.hpp>
#include <set>

#include "mps-signer-list.hpp"

using Json = nlohmann::json;

namespace ndn {

class WildCardName : public Name {
public:
  using Name::Name;

  bool
  match(const Name& name) const;
};

/**
 * @brief JSON based configuration file to guide signing and verification.
 * TODO can be let a schema refer to other schema? we can make much more complex rules from it.
 */
class MultipartySchema {
public:
  Name prefix;
  std::string ruleId;
  std::vector<WildCardName> signers;
  size_t minOptionalSigners;
  std::vector<WildCardName> optionalSigners;

public:
  static MultipartySchema
  fromFile(const std::string& configFile);

  static MultipartySchema
  fromString(const std::string& configStr);

  static MultipartySchema
  fromTlv(const Block& configBlock);

  std::string
  toString();

  std::vector<Name>
  getKeyMatches(const Name& key) const;

  optional<std::vector<Name>>
  getMinSigners(const std::vector<Name>& availableKeys) const;

  bool
  verifyKeyLocator(const MpsSignerList& locator) const;

private:
  static void
  parseAssert(bool criterion);

  static std::vector<std::pair<int, int>>
  modifiedFordFulkerson(const std::vector<std::set<int>>& bipartiteAdjList,
                        int mustHaveSize, int optionalSize);

  static bool
  fordFulkersonDFS(const std::map<int, std::set<int>>& adjList, int start, int end, std::list<int>& path);
};

}  // namespace ndn

#endif  // NDNMPS_SCHEMA_HPP