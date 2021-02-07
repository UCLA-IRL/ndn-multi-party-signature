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
  BLSPublicKey pk;
  sk.getPublicKey(pk);

  Data data;
  data.setName(Name("/a/b/c/d"));
  data.setContent(Name("/1/2/3/4").wireEncode());
  ndnBLSSign(sk, data, Name("/signer/KEY/123"));
  BOOST_CHECK(ndnBLSVerify(pk, data));

  Interest interest(Name("/a/b/c/d"));
  interest.setApplicationParameters(Name("/1/2/3/4").wireEncode());
  interest.setCanBePrefix(true);
  ndnBLSSign(sk, interest, Name("/signer/KEY/123"));
  BOOST_CHECK(interest.isParametersDigestValid());
  BOOST_CHECK(ndnBLSVerify(pk, interest));
}

BOOST_AUTO_TEST_CASE(TestSignAndAggregateVerify)
{
  ndnBLSInit();

  std::vector<BLSSecretKey> sks;
  std::vector<BLSPublicKey> pks;
  BLSPublicKey pk;
  BLSSecretKey sk;
  for (int i = 0; i < 10; i++) {
    sk.init();
    sk.getPublicKey(pk);
    sks.push_back(sk);
    pks.push_back(pk);
  }

  Data data;
  data.setName(Name("/a/b/c/d"));
  data.setContent(Name("/1/2/3/4").wireEncode());
  SignatureInfo info(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), Name("/signer/KEY/123"));

  std::vector<Buffer> sigs;
  for (const auto& sk : sks) {
    sigs.emplace_back(ndnGenBLSSignature(sk, data, info));
  }

  auto aggSigBuf = ndnBLSAggregateSignature(sigs);
  BOOST_CHECK(aggSigBuf.size() > 0);

  data.setSignatureInfo(info);
  data.setSignatureValue(std::make_shared<Buffer>(aggSigBuf));
  data.wireEncode();
  auto aggKey = ndnBLSAggregatePublicKey(pks);

  BOOST_CHECK(ndnBLSVerify(aggKey, data));
}

BOOST_AUTO_TEST_SUITE_END() // TestBLSHelper

}  // namespace tests
}  // namespace mps
}  // namespace ndn
