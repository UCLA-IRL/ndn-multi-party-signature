#include "ndnmps/schema.hpp"

#include <boost/property_tree/info_parser.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <fstream>
#include <sstream>
#include <utility>

namespace ndn {
namespace mps {

typedef boost::property_tree::ptree SchemaSection;

const static std::string CONFIG_PKT_NAME = "pkt-name";
const static std::string CONFIG_RULE_ID = "rule-id";
const static std::string CONFIG_ALL_OF = "all-of";
const static std::string CONFIG_AT_LEAST_NUM = "at-least-num";
const static std::string CONFIG_AT_LEAST = "at-least";

const static uint32_t WILDCARD_NAME_TYPE = ndn::tlv::NameComponentMax - 1;

void
parseAssert(bool criterion)
{
  if (!criterion) {
    NDN_THROW(std::runtime_error("Invalid schema format"));
  }
}

WildCardName::WildCardName(const Name& format)
  : m_name(format)
    , m_times(1)
{
}

WildCardName::WildCardName(const char* str)
  : WildCardName(std::string(str))
{}

WildCardName::WildCardName(const std::string& str)
{
  auto xPos = str.find('x');
  auto slashPos = str.find('/');
  if (slashPos == std::string::npos) {
    NDN_THROW(std::runtime_error("Error: unrecognized wildcard name format."));
  }
  if (xPos != std::string::npos && xPos < slashPos) {
    try {
      m_times = std::stoi(str.substr(0, xPos));
    }
    catch (const std::exception& e) {
      m_times = 1;
    }
  }
  std::string tempStr = str.substr(slashPos + 1);
  std::string compStr;
  slashPos = tempStr.find('/');
  while (slashPos != std::string::npos) {
    compStr = tempStr.substr(0, slashPos);
    if (compStr == "*") {
      m_name.append(Name::Component(WILDCARD_NAME_TYPE));
    }
    else {
      m_name.append(Name::Component(compStr));
    }
    tempStr = tempStr.substr(slashPos + 1);
    slashPos = tempStr.find('/');
  }
  if (tempStr == "*") {
    m_name.append(Name::Component(WILDCARD_NAME_TYPE));
  }
  else {
    m_name.append(Name::Component(tempStr));
  }
}

WildCardName::WildCardName(const Block& block)
  : m_name(block)
    , m_times(1)
{
}

bool
WildCardName::match(const Name& name) const
{
  if (m_name.size() != name.size()) {
    return false;
  }
  for (int i = 0; i < m_name.size(); i++) {
    if (m_name.get(i).type() != WILDCARD_NAME_TYPE && readString(m_name.get(i)) != readString(name.get(i))) {
      return false;
    }
  }
  return true;
}

MultipartySchema
fromSchemaSection(const SchemaSection& config)
{
  MultipartySchema schema;
  parseAssert(config.begin() != config.end() &&
              config.get(CONFIG_PKT_NAME, "") != "" &&
              config.get(CONFIG_RULE_ID, "") != "");
  schema.m_pktName = WildCardName(config.get(CONFIG_PKT_NAME, ""));
  schema.m_ruleId = config.get(CONFIG_RULE_ID, "");
  schema.m_minOptionalSigners = config.get(CONFIG_AT_LEAST_NUM, 0);
  auto allOfSection = config.get_child_optional(CONFIG_ALL_OF);
  if (allOfSection != boost::none) {
    for (auto it = allOfSection->begin(); it != allOfSection->end(); it++) {
      schema.m_signers.emplace_back(it->second.data());
    }
  }
  auto atLeastSection = config.get_child_optional(CONFIG_AT_LEAST);
  if (atLeastSection != boost::none) {
    for (auto it = atLeastSection->begin(); it != atLeastSection->end(); it++) {
      schema.m_optionalSigners.emplace_back(it->second.data());
    }
  }
  return schema;
}

MultipartySchema
MultipartySchema::fromJSON(const std::string& fileOrConfigStr)
{
  SchemaSection config;
  try {
    boost::property_tree::json_parser::read_json(fileOrConfigStr, config);  // as filename
  }
  catch (const std::exception&) {
    std::istringstream ss(fileOrConfigStr);
    boost::property_tree::json_parser::read_json(ss, config);
  }
  return fromSchemaSection(config);
}

MultipartySchema
MultipartySchema::fromINFO(const std::string& fileOrConfigStr)
{
  SchemaSection config;
  try {
    boost::property_tree::info_parser::read_info(fileOrConfigStr, config);  // as filename
  }
  catch (const std::exception&) {
    std::istringstream ss(fileOrConfigStr);
    boost::property_tree::info_parser::read_info(ss, config);
  }
  return fromSchemaSection(config);
}

MultipartySchema::MultipartySchema()
  : m_minOptionalSigners(0)
{
}

std::string
MultipartySchema::toString()
{
  SchemaSection content;
  content.put(CONFIG_PKT_NAME, m_pktName.toUri());
  content.put(CONFIG_RULE_ID, m_ruleId);
  if (m_minOptionalSigners > 0) {
    content.put(CONFIG_AT_LEAST_NUM, m_minOptionalSigners);
  }
  if (!m_signers.empty()) {
    SchemaSection signersNode;
    for (const auto& signer : m_signers) {
      // Create an unnamed node containing the value
      SchemaSection signerNode;
      signerNode.put("", signer.toUri());
      signersNode.push_back(std::make_pair("", signerNode));
    }
    content.add_child(CONFIG_ALL_OF, signersNode);
  }
  if (!m_optionalSigners.empty()) {
    SchemaSection optionalSignersNode;
    for (const auto& signer : m_optionalSigners) {
      SchemaSection signerNode;
      signerNode.put("", signer.toUri());
      optionalSignersNode.push_back(std::make_pair("", signerNode));
    }
    content.add_child(CONFIG_AT_LEAST, optionalSignersNode);
  }

  std::stringstream ss;
  boost::property_tree::info_parser::write_info(ss, content);
  return ss.str();
}

bool
MultipartySchema::passSchema(const std::vector<Name>& signers) const
{
  // make sure all required signers are listed
  size_t count = 0;
  for (const auto& pattern : m_signers) {
    count = 0;
    for (const auto& item : signers) {
      if (pattern.match(item)) {
        count++;
      }
    }
    if (count < pattern.m_times) {
      return false;
    }
  }
  // check optional signers
  size_t totalMatchedKeys = 0;
  for (const auto& pattern : m_optionalSigners) {
    count = 0;
    for (const auto& item : signers) {
      if (pattern.match(item)) {
        count++;
      }
    }
    totalMatchedKeys += std::min(count, pattern.m_times);
  }
  if (totalMatchedKeys >= m_minOptionalSigners) {
    return true;
  }
  return false;
}

bool
MultipartySchemaContainer::passSchema(const Name& packetName, const MpsSignerList& signers) const
{
  for (const auto& item : signers.m_signers) {
    if (m_trustedIds.count(item) == 0) {
      return false;
    }
  }
  for (const auto& schema : m_schemas) {
    if (schema.match(packetName)) {
      return schema.passSchema(signers.m_signers);
    }
  }
  return false;
}

MpsSignerList
MultipartySchemaContainer::getAvailableSigners(const MultipartySchema& schema) const
{
  std::set<Name> resultSet;
  for (const auto& pattern : schema.m_signers) {
    auto matchedKeys = getMatchedKeys(pattern);
    if (matchedKeys.size() < pattern.m_times) {
      NDN_THROW(
        std::runtime_error("Schema container does not have sufficient keys. Missing key(s) for " + pattern.toUri()));
    }
    for (size_t i = 0; i < pattern.m_times; i++) {
      resultSet.insert(matchedKeys[i]);
    }
  }
  size_t count = 0;
  for (const auto& pattern : schema.m_optionalSigners) {
    auto matchedKeys = getMatchedKeys(pattern);
    for (size_t i = 0; i < std::min(matchedKeys.size(), pattern.m_times); i++) {
      resultSet.insert(matchedKeys[i]);
      count++;
      if (count >= schema.m_minOptionalSigners) {
        break;
      }
    }
    if (count >= schema.m_minOptionalSigners) {
      break;
    }
  }
  if (count < schema.m_minOptionalSigners) {
    NDN_THROW(std::runtime_error("Schema container does not have sufficient keys. Missing optional keys"));
  }
  return MpsSignerList(std::vector<Name>(resultSet.begin(), resultSet.end()));
}

BLSPublicKey
MultipartySchemaContainer::aggregateKey(const MpsSignerList& signers) const
{
  BLSPublicKey aggKey;
  bool init = false;
  for (const auto& item : signers.m_signers) {
    if (m_trustedIds.count(item) != 0) {
      if (!init) {
        aggKey = m_trustedIds.at(item);
        init = true;
      }
      else {
        blsPublicKeyAdd(&aggKey, &m_trustedIds.at(item));
      }
    }
    else {
      NDN_THROW(std::runtime_error("Schema container does not have sufficient keys. Missing key for " + item.toUri()));
    }
  }
  return aggKey;
}

std::tuple<MpsSignerList, std::vector<Name>>
MultipartySchemaContainer::replaceSigner(const MpsSignerList& signers,
                                         const Name& unavailableKey,
                                         const MultipartySchema& schema) const
{
  m_unavailableSigners.insert(unavailableKey);

  std::set<Name> newResultSet(signers.m_signers.begin(), signers.m_signers.end());
  newResultSet.erase(unavailableKey);
  std::set<Name> diffSet;
  bool findReplacement = false;
  Name replacementName;

  // find the corresponding required signer schema that matches the unavailable name
  for (const auto& pattern : schema.m_signers) {
    if (pattern.match(unavailableKey)) {
      std::tie(findReplacement, replacementName) = findANewKeyForPattern(newResultSet, pattern);
      if (findReplacement) {
        if (!replacementName.empty()) {
          newResultSet.insert(replacementName);
          diffSet.insert(replacementName);
        }
      }
      else {
        // Schema container does not have sufficient keys that are available
        return std::make_tuple(MpsSignerList(), std::vector<Name>());
      }
    }
  }
  // find the corresponding optional signer schema that matches the unavailable name
  for (const auto& pattern : schema.m_optionalSigners) {
    std::tie(findReplacement, replacementName) = findANewKeyForPattern(newResultSet, pattern);
    if (findReplacement && replacementName.empty()) {
      continue;
    }
    if (findReplacement && !replacementName.empty()) {
      // find a new matched name that has not been included yet
      newResultSet.insert(replacementName);
      diffSet.insert(replacementName);
      break;
    }
  }
  return std::make_tuple(MpsSignerList(std::vector<Name>(newResultSet.begin(), newResultSet.end())),
                         std::vector<Name>(diffSet.begin(), diffSet.end()));
}

std::vector<Name>
MultipartySchemaContainer::getMatchedKeys(const WildCardName& pattern) const
{
  std::set<Name> resultSet;
  for (const auto& item : m_trustedIds) {
    if (pattern.match(item.first) && m_unavailableSigners.count(item.first) == 0) {
      resultSet.insert(item.first);
    }
  }
  return std::vector<Name>(resultSet.begin(), resultSet.end());
}

std::tuple<bool, Name>
MultipartySchemaContainer::findANewKeyForPattern(const std::set<Name>& existingSigners, WildCardName pattern) const
{
  size_t count = 0;
  for (const auto& item : existingSigners) {
    if (pattern.match(item)) {
      count++;
    }
  }
  if (count >= pattern.m_times) {
    // no need to find replacement
    return std::make_tuple(true, Name());
  }
  auto matchedKeys = getMatchedKeys(pattern);
  for (const auto& matchedKey : matchedKeys) {
    if (existingSigners.count(matchedKey) == 0) {
      return std::make_tuple(true, matchedKey);
    }
  }
  return std::make_tuple(false, Name());
}

}  // namespace mps
}  // namespace ndn