#include <nlohmann/json.hpp>
#include <list>
#include <ndn-cxx/name.hpp>

using Json = nlohmann::json;

namespace ndn {

class WildCardName {
private:
  std::string m_name;
public:
  WildCardName(const std::string& name);

  bool
  match(const Name& name);
};

/**
 * @brief JSON based configuration file to guide signing and verification.
 */
class MultipartySchema
{
public:
  Json content;
  Name prefix;
  std::string ruleId;
  std::list<WildCardName> signers;
  size_t minOptionalSigners;
  std::list<WildCardName> optionalSigners;

public:
  static MultipartySchema
  fromFile(const std::string& configFile);

  static MultipartySchema
  fromString(const std::string& configStr);

  std::string
  toString();
};

} // namespace ndn