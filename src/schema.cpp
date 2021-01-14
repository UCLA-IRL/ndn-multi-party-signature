#include "ndnmps/schema.hpp"
#include <fstream>
#include <sstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <utility>

namespace ndn {

typedef boost::property_tree::ptree SchemaSection;

const static std::string CONFIG_DATA_NAME = "data-name";
const static std::string CONFIG_RULE_ID = "rule-id";
const static std::string CONFIG_ALL_OF = "all-of";
const static std::string CONFIG_AT_LEAST_NUM = "at-least-num";
const static std::string CONFIG_AT_LEAST = "at-least";

void
parseAssert(bool criterion)
{
  if (!criterion) {
    NDN_THROW(std::runtime_error("Invalid schema format"));
  }
}

MultipartySchema
fromSchemaSection(const SchemaSection& config)
{
  MultipartySchema schema;
  parseAssert(config.begin() != config.end() &&
              config.get(CONFIG_DATA_NAME, "") != "" &&
              config.get(CONFIG_RULE_ID, "") != "");
  schema.prefix = WildCardName(config.get(CONFIG_DATA_NAME, ""));
  schema.ruleId = config.get(CONFIG_RULE_ID, "");
  schema.minOptionalSigners = config.get(CONFIG_AT_LEAST_NUM, 0);
  auto allOfSection = config.get_child_optional(CONFIG_ALL_OF);
  if (allOfSection != boost::none) {
    for (auto it = allOfSection->begin(); it != allOfSection->end(); it++) {
      schema.signers.emplace_back(it->second.data());
    }
  }
  auto atLeastSection = config.get_child_optional(CONFIG_AT_LEAST);
  if (atLeastSection != boost::none) {
    for (auto it = atLeastSection->begin(); it != atLeastSection->end(); it++) {
      schema.optionalSigners.emplace_back(it->second.data());
    }
  }
  return schema;
}

WildCardName::WildCardName(const Name& format)
        :Name(format)
{}

WildCardName::WildCardName(const std::string& str)
        :Name(str)
{}

WildCardName::WildCardName(const char * str)
        :Name(str)
{}

WildCardName::WildCardName(const Block& block)
        :Name(block)
{}

bool
WildCardName::match(const Name& name) const
{
  if (this->size() != name.size())
    return false;
  for (int i = 0; i < size(); i++) {
    if (readString(this->get(i)) != "_" && readString(this->get(i)) != readString(name.get(i))) {
      return false;
    }
  }
  return true;
}

MultipartySchema
MultipartySchema::fromJSON(const std::string& fileOrConfigStr)
{
  SchemaSection config;
  boost::property_tree::json_parser::read_json(fileOrConfigStr, config);
  return fromSchemaSection(config);
}

MultipartySchema
MultipartySchema::fromINFO(const std::string& fileOrConfigStr)
{
  SchemaSection config;
  boost::property_tree::info_parser::read_info(fileOrConfigStr, config);
  return fromSchemaSection(config);
}

MultipartySchema::MultipartySchema()
        : minOptionalSigners(0)
{}

std::string
MultipartySchema::toString()
{
  Json content;
  content[CONFIG_DATA_NAME] = this->prefix.toUri();
  content[CONFIG_RULE_ID] = this->ruleId;
  if (this->minOptionalSigners > 0) {
    content[CONFIG_AT_LEAST_NUM] = this->minOptionalSigners;
  }
  if (!signers.empty()) {
    std::vector<std::string> signersVec;
    for (const auto& signer : this->signers) {
      signersVec.push_back(signer.toUri());
    }
    content[CONFIG_ALL_OF] = signersVec;
  }
  if (!optionalSigners.empty()) {
    std::vector<std::string> optionalSignersVec;
    for (const auto& signer : this->optionalSigners) {
      optionalSignersVec.push_back(signer.toUri());
    }
    content[CONFIG_AT_LEAST] = optionalSignersVec;
  }
  return content.dump();
}

std::vector<Name>
MultipartySchema::getKeyMatches(const Name& key) const
{
  std::vector<Name> matches;
  for (const auto& signer : signers) {
    if (signer.match(key)) {
      matches.emplace_back(signer);
    }
  }
  for (const auto& signer : optionalSigners) {
    if (signer.match(key)) {
      matches.emplace_back(signer);
    }
  }
  return matches;
}

bool
MultipartySchema::isSatisfied(const MpsSignerList& signers) const
{
  const auto& realSigners = signers;
  if (getMinSigners(realSigners).empty()) {
    return false;
  }
  return true;
}

Name
findAMatch(const WildCardName& target, const std::vector<Name>& collection)
{
  for (const auto& item : collection) {
    if (target.match(item)) {
      return item;
    }
  }
  return Name();
}

std::set<Name>
MultipartySchema::getMinSigners(const std::vector<Name>& availableKeys) const
{
  std::set<Name> resultSet;
  for (const auto& requiredSigner : this->signers) {
    auto result = findAMatch(requiredSigner, availableKeys);
    if (result.empty()) {
      return std::set<Name>();
    }
    else {
      resultSet.insert(result);
    }
  }
  size_t count = 0;
  for (const auto& optionalSigner : this->optionalSigners) {
    auto result = findAMatch(optionalSigner, availableKeys);
    if (!result.empty()) {
      count++;
      resultSet.insert(result);
    }
  }
  if (count < this->minOptionalSigners) {
    return std::set<Name>();
  }
  return resultSet;
}

// bool
// MultipartySchema::verifyKeyLocator(const MpsSignerList& locator) const
// {
//   std::vector<Name> keys;
//   std::vector<std::set<int>> matches;
//   for (const auto& signer : locator.m_signers) {
//     // no repeated keys
//     if (std::find(keys.begin(), keys.end(), signer) != keys.end())
//       continue;
//     keys.emplace_back(signer);
//     for (int i = 0; i < signers.size(); i++) {
//       if (signers.at(i).match(signer)) {
//         matches[i].emplace(keys.size() - 1);
//       }
//     }
//     for (int i = 0; i < optionalSigners.size(); i++) {
//       if (optionalSigners.at(i).match(signer)) {
//         matches[i + signers.size()].emplace(keys.size() - 1);
//       }
//     }
//   }

//   //find matches by maximum flow
//   std::vector<std::pair<int, int>> out = modifiedFordFulkerson(matches, signers.size(), optionalSigners.size());

//   return out.size() >= signers.size() + minOptionalSigners;
// }

// std::vector<Name>
// MultipartySchema::getMinSigners(const std::vector<Name>& availableKeys) const
// {
//   std::vector<std::set<int>> matches;
//   for (int keyId = 0; keyId < availableKeys.size(); keyId++) {
//     for (int i = 0; i < signers.size(); i++) {
//       if (signers.at(i).match(availableKeys[i])) {
//         matches[i].emplace(keyId);
//       }
//     }
//     for (int i = 0; i < optionalSigners.size(); i++) {
//       if (optionalSigners.at(i).match(availableKeys[i])) {
//         matches[i + signers.size()].emplace(keyId);
//       }
//     }
//   }

//   //find matches by maximum flow
//   std::vector<std::pair<int, int>> out = modifiedFordFulkerson(matches, signers.size(), optionalSigners.size());

//   //translate back and filter to necessary only
//   std::vector<Name> ans;
//   int mustHaveCount = 0;
//   int optionalCount = 0;
//   for (auto item : out) {
//     if (item.first < signers.size()) {  // must have
//       mustHaveCount++;
//       ans.emplace_back(availableKeys[item.second]);
//     }
//     else if (optionalCount < minOptionalSigners) {
//       optionalCount++;
//       ans.emplace_back(availableKeys[item.second]);
//     }
//   }
//   return ans;
// }

// std::vector<std::pair<int, int>>
// MultipartySchema::modifiedFordFulkerson(const std::vector<std::set<int>>& bipartiteAdjList, int mustHaveSize, int optionalSize)
// {
//   //node assignment: 0 as source, 1 as sink, 2 to mustHaveSize + optionalSize + 1 as position, rest as keys node.
//   //convert the bipartite Adjency list to flow graph
//   std::map<int, std::set<int>> adjList;
//   //position
//   for (int i = 2; i < mustHaveSize + optionalSize + 2; i++) {
//     adjList[0].emplace(i);
//   }
//   //possible assignments
//   for (int i = 0; i < bipartiteAdjList.size(); i++) {
//     for (auto val : bipartiteAdjList.at(i)) {
//       adjList[i + 2].emplace(val + mustHaveSize + optionalSize + 2);
//       adjList[val + mustHaveSize + optionalSize + 2].emplace(1);
//     }
//   }

//   //find augment path
//   std::list<int> augmentPath;
//   while (fordFulkersonDFS(adjList, 0, 1, augmentPath)) {  // more augment path
//     for (auto it = augmentPath.begin(); it != augmentPath.end(); it++) {
//       auto it2 = it;
//       it2++;
//       if (it2 == augmentPath.end())
//         break;

//       adjList[*it].erase(*it2);
//       if (!(*it == 0 && *it2 >= 2 && *it2 < 2 + mustHaveSize))  // only add reverse link if not a mustHave node
//         adjList[*it2].emplace(*it);
//     }
//     augmentPath.clear();
//   }

//   //check mustHave met
//   for (auto item : adjList[0]) {
//     if (item < 2 + mustHaveSize)
//       return std::vector<std::pair<int, int>>();
//   }

//   //return
//   std::vector<std::pair<int, int>> ans;
//   for (auto keyNode : adjList[1]) {
//     assert(adjList[keyNode].size() == 1);
//     auto positionId = *adjList[keyNode].begin();
//     ans.emplace_back(positionId - 2, keyNode - mustHaveSize - optionalSize - 2);
//   }

//   return ans;
// }

// bool
// MultipartySchema::fordFulkersonDFS(const std::map<int, std::set<int>>& adjList, int start, int end, std::list<int>& path)
// {
//   path.emplace_back(start);
//   if (start == end)
//     return true;
//   for (auto item : adjList.at(start)) {
//     bool visited = false;
//     for (auto pastItem : path) {
//       if (item == pastItem) {
//         visited = true;
//         break;
//       }
//     }
//     if (visited)
//       continue;  // prevent loop
//     if (fordFulkersonDFS(adjList, item, end, path))
//       return true;
//   }
//   path.pop_back();
//   return false;
// }

}  // namespace ndn