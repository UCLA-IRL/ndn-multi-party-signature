#include "ndnmps/bls-helpers.hpp"
#include "test-common.hpp"
#include <iostream>

namespace ndn {
namespace mps {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestBLSHelper)

BOOST_AUTO_TEST_CASE(TestSignAndVerify)
{
  ndnBLSInit();

  BLSSecretKey sk;
  sk.init();
  Data data;
  data.setName(Name("/a/b/c/d"));
  data.setContent(Name("/1/2/3/4").wireEncode());
  ndnBLSSign(sk, data, Name("/signer/KEY/123"));

  BLSPublicKey pk;
  sk.getPublicKey(pk);
  BOOST_CHECK(ndnBLSVerify(pk, data));
}

BOOST_AUTO_TEST_CASE(TestSignAndAggregateVerify)
{
  ndnBLSInit();

  std::vector<BLSSecretKey> sks;
  std::vector<BLSPublicKey> pks;
  for (int i = 0; i < 10; i++) {
    sks[i].init();
    BLSPublicKey pk;
    sks[i].getPublicKey(pk);
    pks.push_back(pk);
  }

  Data data;
  data.setName(Name("/a/b/c/d"));
  data.setContent(Name("/1/2/3/4").wireEncode());
  SignatureInfo info(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), Name("/signer/KEY/123"));

  std::vector<Buffer> sigs;
  for (const auto& sk : sks) {
    sigs.push_back(std::move(ndnGenBLSSignature(sk, data, info)));
  }

  auto aggSigBuf = ndnBLSAggregateSignature(sigs);
  data.setSignatureInfo(info);
  data.setSignatureValue(std::make_shared<Buffer>(aggSigBuf));
  auto aggKey = ndnBLSAggregatePublicKey(pks);
  BOOST_CHECK(ndnBLSVerify(aggKey, data));
}

BOOST_AUTO_TEST_SUITE_END() // TestBLSHelper

}  // namespace tests
}  // namespace mps
}  // namespace ndn
