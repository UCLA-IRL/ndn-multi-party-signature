#include <nlohmann/json.hpp>
#include <set>
#include <list>
#include <ndn-cxx/name.hpp>
#include "multi-party-key-locator.hpp"

using Json = nlohmann::json;

namespace ndn {

class WildCardName: public Name {
public:

  using Name::Name;

  bool
  match(const Name& name) const;
};

/**
 * @brief JSON based configuration file to guide signing and verification.
 * TODO can be let a schema refer to other schema? we can make much more complex rules from it.
 */
class MultipartySchema
{
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

  std::string
  toString();
public:
    static bool
    verifyKeyLocator(const MultiPartyKeyLocator& locator, const MultipartySchema& schema);
private:
  static void
  parseAssert(bool criterion);

  static std::vector<std::pair<int, int>>
  modifiedFordFulkerson(const std::vector<std::set<int>>& bipartiteAdjList,
                        int mustHaveSize, int optionalSize);

  static bool
  fordFulkersonDFS(const std::map<int, std::set<int>>& adjList, int start, int end, std::list<int>& path);
};

} // namespace ndn