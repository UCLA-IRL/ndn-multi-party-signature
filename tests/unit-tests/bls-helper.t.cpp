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
  blsSecretKeySetByCSPRNG(&sk);
  BLSPublicKey pk;
  blsGetPublicKey(&pk, &sk);

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
    blsSecretKeySetByCSPRNG(&sk);
    blsGetPublicKey(&pk, &sk);
    sks.push_back(sk);
    pks.push_back(pk);
  }
  auto aggKey = ndnBLSAggregatePublicKey(pks);

  Data data;
  data.setName(Name("/a/b/c/d"));
  data.setContent(Name("/1/2/3/4").wireEncode());

  Interest interest(Name("/a/b/c/d"));
  interest.setApplicationParameters(Name("/1/2/3/4").wireEncode());
  interest.setCanBePrefix(true);

  SignatureInfo info(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), Name("/signer/KEY/123"));

  std::vector<Buffer> dataSigs;
  std::vector<Buffer> interestSigs;
  for (const auto& sk : sks) {
    dataSigs.emplace_back(ndnGenBLSSignature(sk, data, info));
    interestSigs.emplace_back(ndnGenBLSSignature(sk, interest, info));
  }

  auto aggDataSigBuf = ndnBLSAggregateSignature(dataSigs);
  auto aggInterestSigBuf = ndnBLSAggregateSignature(interestSigs);
  BOOST_CHECK(aggDataSigBuf.size() > 0);
  BOOST_CHECK(aggInterestSigBuf.size() > 0);

  data.setSignatureInfo(info);
  data.setSignatureValue(std::make_shared<Buffer>(aggDataSigBuf));
  data.wireEncode();
  BOOST_CHECK(ndnBLSVerify(aggKey, data));

  interest.setSignatureInfo(info);
  interest.setSignatureValue(std::make_shared<Buffer>(aggInterestSigBuf));
  interest.wireEncode();
  BOOST_CHECK(ndnBLSVerify(aggKey, interest));
}

BOOST_AUTO_TEST_SUITE_END() // TestBLSHelper

}  // namespace tests
}  // namespace mps
}  // namespace ndn
