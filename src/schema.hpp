#include <nlohmann/json.hpp>

using Json = nlohmann::json;

namespace ndn {

/**
 * @brief JSON based configuration file to guide signing and verification.
 */
class MultipartySchema
{
public:
  Json content;

public:
  static MultipartySchema
  fromFile(const std::string& configFile);

  static MultipartySchema
  fromString(const std::string& configStr);

  std::string
  toString();
};

} // namespace ndn