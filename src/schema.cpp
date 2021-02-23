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

WildCardName::WildCardName(const Name& format)
    : Name(format)
{
}

WildCardName::WildCardName(const std::string& str)
    : Name(str)
{
}

WildCardName::WildCardName(const char* str)
    : Name(str)
{
}

WildCardName::WildCardName(const Block& block)
    : Name(block)
{
}

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
MultipartySchema::passSchema(const MpsSignerList& signers) const
{
  // make sure all required signers are listed
  bool found = false;
  for (const auto& requiredSigner : m_signers) {
    found = false;
    for (const auto& item : signers.m_signers) {
      if (requiredSigner.match(item)) {
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  // check optional signers
  size_t count = 0;
  for (const auto& optionalSigner : m_optionalSigners) {
    found = false;
    for (const auto& item : signers.m_signers) {
      if (optionalSigner.match(item)) {
        found = true;
        break;
      }
    }
    if (found) {
      count++;
    }
  }
  if (count >= m_minOptionalSigners) {
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
      return schema.passSchema(signers);
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
    if (matchedKeys.empty()) {
      NDN_THROW(std::runtime_error("Schema container does not have sufficient keys. Missing key for " + pattern.toUri()));
    }
    resultSet.insert(matchedKeys.front());
  }
  size_t count = 0;
  for (const auto& pattern : schema.m_optionalSigners) {
    auto matchedKeys = getMatchedKeys(pattern);
    if (!matchedKeys.empty()) {
      resultSet.insert(matchedKeys.front());
      count++;
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

MpsSignerList
MultipartySchemaContainer::replaceSigner(const MpsSignerList& signers, const Name& unavailableKey, const MultipartySchema& schema) const
{
  std::set<Name> newResultSet(signers.m_signers.begin(), signers.m_signers.end());
  newResultSet.erase(unavailableKey);

  // find the corresponding required signer schema that matches the unavailable name
  std::vector<WildCardName> possiblyBrokenPattern;
  for (const auto& pattern : schema.m_signers) {
    if (pattern.match(unavailableKey)) {
      possiblyBrokenPattern.push_back(pattern);
    }
  }
  // find the corresponding optional signer schema that matches the unavailable name
  for (const auto& pattern : schema.m_optionalSigners) {
    if (pattern.match(unavailableKey)) {
      possiblyBrokenPattern.push_back(pattern);
    }
  }
  // find replacement
  bool findReplacement = false;
  for (const auto& brokenPattern : possiblyBrokenPattern) {
    findReplacement = false;
    for (const auto& existingKey : signers.m_signers) {
      if (existingKey != unavailableKey && brokenPattern.match(existingKey)) {
        findReplacement = true;
        break;
      }
    }
    auto matchedKeys = getMatchedKeys(brokenPattern);
    for (const auto& matchedKey : matchedKeys) {
      if (matchedKey != unavailableKey) {
        newResultSet.insert(matchedKey);
        findReplacement = true;
        break;
      }
    }
    if (!findReplacement) {
      // Schema container does not have sufficient keys that are available
      return MpsSignerList();
    }
  }
  return MpsSignerList(std::vector<Name>(newResultSet.begin(), newResultSet.end()));
}

std::vector<Name>
MultipartySchemaContainer::getMatchedKeys(const WildCardName& pattern) const
{
  std::set<Name> resultSet;
  for (const auto& item : m_trustedIds) {
    if (pattern.match(item.first)) {
      resultSet.insert(item.first);
    }
  }
  return std::vector<Name>(resultSet.begin(), resultSet.end());
}

}  // namespace mps
}  // namespace ndn