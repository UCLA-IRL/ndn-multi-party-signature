/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2020, Regents of the University of California.
 *
 * This file, originally written as part of ndnmps (NDN Certificate Managerment Service),
 * is a part of ndnmps, NDN multi signature library.
 *
 * See AUTHORS.md for complete list of ndnmps authors and contributors.
 */

#include "boost-test.hpp"
#include <boost/filesystem.hpp>
#include <fstream>
#include <stdlib.h>

namespace ndn {
namespace ndnmps {
namespace tests {

class GlobalConfiguration
{
public:
  GlobalConfiguration()
  {
    const char* envHome = ::getenv("HOME");
    if (envHome)
      m_home = envHome;

    boost::filesystem::path dir{TMP_TESTS_PATH};
    dir /= "test-home";
    ::setenv("HOME", dir.c_str(), 1);

    boost::filesystem::create_directories(dir);
    std::ofstream clientConf((dir / ".ndn" / "client.conf").c_str());
    clientConf << "pib=pib-sqlite3" << std::endl
               << "tpm=tpm-file" << std::endl;
  }

  ~GlobalConfiguration()
  {
    if (!m_home.empty())
      ::setenv("HOME", m_home.data(), 1);
  }

private:
  std::string m_home;
};

#if BOOST_VERSION >= 106500
BOOST_TEST_GLOBAL_CONFIGURATION(GlobalConfiguration);
#elif BOOST_VERSION >= 105900
BOOST_GLOBAL_FIXTURE(GlobalConfiguration);
#else
BOOST_GLOBAL_FIXTURE(GlobalConfiguration)
#endif

} // namespace tests
} // namespace ndnmps
} // namespace ndn