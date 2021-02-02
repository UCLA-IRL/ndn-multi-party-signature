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
  try {
    boost::property_tree::json_parser::read_json(fileOrConfigStr, config); // as filename
  } catch (const std::exception&) {
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
    boost::property_tree::info_parser::read_info(fileOrConfigStr, config); // as filename
  } catch (const std::exception&) {
    std::istringstream ss(fileOrConfigStr);
    boost::property_tree::info_parser::read_info(ss, config);
  }
  return fromSchemaSection(config);
}

MultipartySchema::MultipartySchema()
        : minOptionalSigners(0)
{}

std::string
MultipartySchema::toString()
{
  SchemaSection content;
  content.put(CONFIG_DATA_NAME, this->prefix.toUri());
  content.put(CONFIG_RULE_ID, this->ruleId);
  if (this->minOptionalSigners > 0) {
    content.put(CONFIG_AT_LEAST_NUM, this->minOptionalSigners);
  }
  if (!signers.empty()) {
    SchemaSection signersNode;
    for (const auto& signer : this->signers) {
      // Create an unnamed node containing the value
      SchemaSection signerNode;
      signerNode.put("", signer.toUri());
      signersNode.push_back(std::make_pair("", signerNode));
    }
    content.add_child(CONFIG_ALL_OF, signersNode);
  }
  if (!optionalSigners.empty()) {
    SchemaSection optionalSignersNode;
    for (const auto& signer : this->optionalSigners) {
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

std::set<Name>
MultipartySchema::getMinSigners(const std::vector<Name>& availableKeys) const
{
  std::map<Name, Name> matches;
  for (const auto& i : availableKeys) {
    for (const auto& pos : getKeyMatches(i)) {
      if (matches.count(pos) == 0)
        matches.emplace(pos, i);
    }
  }
  std::set<Name> resultSet;
  for (const auto& requiredSigner : this->signers) {
    if (matches.count(requiredSigner) == 0) {
      return std::set<Name>();
    }
    else {
      resultSet.insert(matches.at(requiredSigner));
    }
  }
  size_t count = 0;
  for (const auto& optionalSigner : this->optionalSigners) {
    if (matches.count(optionalSigner) != 0) {
      count++;
      resultSet.insert(matches.at(optionalSigner));
    }
    if (count >= this->minOptionalSigners) break;
  }
  if (count < this->minOptionalSigners) {
    return std::set<Name>();
  }
  return resultSet;
}

}  // namespace ndn