#include <nlohmann/json.hpp>
#include <list>
#include <ndn-cxx/name.hpp>

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
private:
  static void parseAssert(bool criterion);
};

} // namespace ndn