#include "ndnmps/schema.hpp"
#include <fstream>
#include <sstream>
#include <set>

namespace ndn {

bool
WildCardName::match(const Name& name) const
{
    if (this->size() != name.size()) return false;
    for (int i = 0; i < size(); i ++) {
        if (readString(this->get(i)) != "_" && readString(this->get(i)) != readString(name.get(i))) {
            return false;
        }
    }
    return true;
}

MultipartySchema
MultipartySchema::fromFile(const std::string& configFile)
{
  MultipartySchema schema;
  std::ifstream config(configFile);
  std::stringstream buffer;
  buffer << config.rdbuf();
  return MultipartySchema::fromString(buffer.str());
}

MultipartySchema
MultipartySchema::fromString(const std::string& configStr)
{
  MultipartySchema schema;
  Json content = Json::parse(configStr);
  parseAssert(content.is_object() &&
            content.find("prefix") != content.end() && content["prefix"].is_string() &&
            content.find("rule-id") != content.end() && content["rule-id"].is_string() &&
            content.find("signed-by") != content.end());
  schema.prefix = content.find("prefix")->get<std::string>();
  schema.ruleId = content.find("rule-id")->get<std::string>();
  Json signedBy = *content.find("signed-by");

  parseAssert(signedBy.is_object());
  if (signedBy.find("all-of") != signedBy.end()) {
      parseAssert(signedBy["all-of"].is_object());
      for (auto& party : signedBy["all-of"].items()) {
          parseAssert(party.key() == "key-format" && party.value().is_string());
          schema.signers.emplace_back(party.value().get<std::string>());
      }
  }
  if (signedBy.find("at-least") != signedBy.end()) {
      parseAssert(signedBy["at-least"].is_object());
      for (auto& party : signedBy["at-least"].items()) {
          if (party.key() == "num" && party.value().is_number_unsigned()) {
              schema.minOptionalSigners = party.value().get<size_t>();
          } else {
              parseAssert(party.key() == "key-format" && party.value().is_string());
              schema.optionalSigners.emplace_back(party.value().get<std::string>());
          }
      }
  } else {
      schema.minOptionalSigners = 0;
  }
  return schema;
}

std::string
MultipartySchema::toString()
{
  Json content;
  content["prefix"] = prefix.toUri();
  content["rule-id"] = ruleId;
  content["signed-by"] = Json::object();

  if (!signers.empty()) {
      auto signers_object = Json::object();
      for (const auto& signer : signers) {
          signers_object.emplace(std::string("key-format"), signer.toUri());
      }
      content["signed-by"]["all-of"] = signers_object;
  }

  if (!optionalSigners.empty() || minOptionalSigners != 0) {
      auto signers_object = Json::object();
      signers_object["num"] = minOptionalSigners;
      for (const auto& signer : optionalSigners) {
          signers_object.emplace(std::string("key-format"), signer.toUri());
      }
      content["signed-by"]["at-least"] = signers_object;
  }
  return content.dump();
}

void
MultipartySchema::parseAssert(bool criterion)
{
    if (!criterion) {
        NDN_THROW(std::runtime_error("Invalid JSON type"));
    }
}

std::vector<Name>
MultipartySchema::getKeyMatches(const Name& key) const
{
    std::vector<Name> matches;
    for (const auto& signer: signers) {
        if (signer.match(key)) {
            matches.emplace_back(signer);
        }
    }
    for (const auto& signer: optionalSigners) {
        if (signer.match(key)) {
            matches.emplace_back(signer);
        }
    }
    return matches;
}

bool
MultipartySchema::verifyKeyLocator(const MpsSignerList& locator) const
{
    std::vector<Name> keys;
    std::vector<std::set<int>> matches;
    for (const auto& signer: locator.getSigners()) {
        // no repeated keys
        if (std::find(keys.begin(), keys.end(), signer) != keys.end()) continue;
        keys.emplace_back(signer);
        for (int i = 0; i < signers.size(); i ++) {
            if (signers.at(i).match(signer)) {
                matches[i].emplace(keys.size() - 1);
            }
        }
        for (int i = 0; i < optionalSigners.size(); i ++) {
            if (optionalSigners.at(i).match(signer)) {
                matches[i + signers.size()].emplace(keys.size() - 1);
            }
        }
    }

    //find matches by maximum flow
    std::vector<std::pair<int, int>> out = modifiedFordFulkerson(matches, signers.size(), optionalSigners.size());

    return out.size() >= signers.size() + minOptionalSigners;
}

optional<std::vector<Name>>
MultipartySchema::getMinSigners(const std::vector<Name>& availableKeys) const
{
    std::vector<std::set<int>> matches;
    for (int keyId = 0; keyId < availableKeys.size(); keyId ++) {
        for (int i = 0; i < signers.size(); i ++) {
            if (signers.at(i).match(availableKeys[i])) {
                matches[i].emplace(keyId);
            }
        }
        for (int i = 0; i < optionalSigners.size(); i ++) {
            if (optionalSigners.at(i).match(availableKeys[i])) {
                matches[i + signers.size()].emplace(keyId);
            }
        }
    }

    //find matches by maximum flow
    std::vector<std::pair<int, int>> out = modifiedFordFulkerson(matches, signers.size(), optionalSigners.size());

    //translate back and filter to necessary only
    std::vector<Name> ans;
    int mustHaveCount = 0;
    int optionalCount = 0;
    for (auto item : out) {
        if (item.first < signers.size()) { // must have
            mustHaveCount ++;
            ans.emplace_back(availableKeys[item.second]);
        } else if (optionalCount < minOptionalSigners) {
            optionalCount ++;
            ans.emplace_back(availableKeys[item.second]);
        }
    }
    if (mustHaveCount == signers.size() && optionalCount >= minOptionalSigners) {
        return std::move(ans);
    } else {
        return nullopt;
    }
}

std::vector<std::pair<int, int>>
MultipartySchema::modifiedFordFulkerson(const std::vector<std::set<int>>& bipartiteAdjList, int mustHaveSize, int optionalSize)
{
    //node assignment: 0 as source, 1 as sink, 2 to mustHaveSize + optionalSize + 1 as position, rest as keys node.
    //convert the bipartite Adjency list to flow graph
    std::map<int, std::set<int>> adjList;
    //position
    for (int i = 2; i < mustHaveSize + optionalSize + 2; i ++) {
        adjList[0].emplace(i);
    }
    //possible assignments
    for (int i = 0; i < bipartiteAdjList.size(); i ++) {
        for (auto val : bipartiteAdjList.at(i)) {
            adjList[i + 2].emplace(val + mustHaveSize + optionalSize + 2);
            adjList[val + mustHaveSize + optionalSize + 2].emplace(1);
        }
    }

    //find augment path
    std::list<int> augmentPath;
    while (fordFulkersonDFS(adjList, 0, 1, augmentPath)) { // more augment path
        for (auto it = augmentPath.begin(); it != augmentPath.end(); it ++) {
            auto it2 = it;
            it2 ++;
            if (it2 == augmentPath.end()) break;

            adjList[*it].erase(*it2);
            if (!(*it == 0 && *it2 >= 2 && *it2 < 2 + mustHaveSize)) // only add reverse link if not a mustHave node
                adjList[*it2].emplace(*it);
        }
        augmentPath.clear();
    }

    //check mustHave met
    for (auto item : adjList[0]) {
        if (item < 2 + mustHaveSize) return std::vector<std::pair<int, int>>();
    }

    //return
    std::vector<std::pair<int, int>> ans;
    for (auto keyNode : adjList[1]) {
        assert(adjList[keyNode].size() == 1);
        auto positionId = *adjList[keyNode].begin();
        ans.emplace_back(positionId - 2, keyNode - mustHaveSize - optionalSize - 2);
    }

    return ans;
}

bool
MultipartySchema::fordFulkersonDFS(const std::map<int, std::set<int>>& adjList, int start, int end, std::list<int>& path) {
    path.emplace_back(start);
    if (start == end) return true;
    for (auto item : adjList.at(start)) {
        bool visited = false;
        for (auto pastItem : path) {
            if (item == pastItem) {
                visited = true;
                break;
            }
        }
        if (visited) continue; // prevent loop
        if (fordFulkersonDFS(adjList, item, end, path)) return true;
    }
    path.pop_back();
    return false;
}


} // namespace ndn