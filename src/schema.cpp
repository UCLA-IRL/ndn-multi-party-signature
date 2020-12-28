#include "ndnmps/schema.hpp"
#include <fstream>
#include <sstream>

namespace ndn {

bool
WildCardName::match(const Name& name){
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
  if (signedBy.find("all-of") != content.end()) {
      parseAssert(signedBy["all-of"].is_object());
      for (auto& party : signedBy["all-of"].items()) {
          parseAssert(party.key() == "key-format" && party.value().is_string());
          schema.signers.emplace_back(party.value().get<std::string>());
      }
  }
  if (signedBy.find("at-least") != content.end()) {
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

} // namespace ndn