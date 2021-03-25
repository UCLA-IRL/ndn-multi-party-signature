#include "ndnmps/bls-helpers.hpp"
#include "test-common.hpp"
#include <ndn-cxx/util/random.hpp>
#include <iostream>

namespace ndn {
namespace mps {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestBench)

void measureTime(int signer_size, int packet_size);

BOOST_AUTO_TEST_CASE(TestSignAndAggregateVerify)
{
  ndnBLSInit();

  for (int signer_size = 1; signer_size <= 64; signer_size <<= 1)
    measureTime(signer_size, 16);
  for (int packet_size = 2; packet_size <= 8192; packet_size <<= 1)
    measureTime(2, packet_size);
}

void measureTime(int signer_size, int packet_size) {
  std::cout << "Signer Size: " << signer_size << ", Packet Size: " << packet_size << std::endl;
  std::vector<BLSSecretKey> sks;
  std::vector<BLSPublicKey> pks;
  BLSPublicKey pk;
  BLSSecretKey sk;
  for (int i = 0; i < signer_size; i++) {
    blsSecretKeySetByCSPRNG(&sk);
    blsGetPublicKey(&pk, &sk);
    sks.push_back(sk);
    pks.push_back(pk);
  }

  std::vector<Data> packets(1000);
  for (int i = 0; i < 1000; i ++) {
    Data data;
    data.setName(Name("/a" + std::to_string(i)));
    Buffer buffer(packet_size);
    random::generateSecureBytes(buffer.data(), packet_size);
    data.setContent(std::make_shared<Buffer>(buffer));
    packets.push_back(data);
  }

  SignatureInfo info(static_cast<ndn::tlv::SignatureTypeValue>(tlv::SignatureSha256WithBls), Name("/signer/KEY/123"));

  std::vector<std::vector<Buffer>> dataSigs(packets.size());

  std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
  auto sigIt = dataSigs.begin();
  for (auto& d: packets) {
    for (const auto& sk : sks) {
      sigIt->emplace_back(ndnGenBLSSignature(sk, d, info));
    }
    sigIt ++;
  }
  std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> time_span = duration_cast<std::chrono::duration<double>>(t2 - t1);
  std::cout << "Signing time: " << time_span.count() / signer_size << " ms" << std::endl;

  t1 = std::chrono::high_resolution_clock::now();
  sigIt = dataSigs.begin();
  for (auto& d: packets) {
    auto aggDataSigBuf = ndnBLSAggregateSignature(*sigIt);
    d.setSignatureInfo(info);
    d.setSignatureValue(std::make_shared<Buffer>(aggDataSigBuf));
    d.wireEncode();
    sigIt ++;
  }
  t2 = std::chrono::high_resolution_clock::now();
  time_span = duration_cast<std::chrono::duration<double>>(t2 - t1);
  std::cout << "Aggregation time: " << time_span.count() << " ms" << std::endl;

  t1 = std::chrono::high_resolution_clock::now();
  for (auto& d: packets) {
    auto aggKey = ndnBLSAggregatePublicKey(pks);
    ndnBLSVerify(aggKey, d);
  }
  t2 = std::chrono::high_resolution_clock::now();
  time_span = duration_cast<std::chrono::duration<double>>(t2 - t1);
  std::cout << "Verification time: " << time_span.count() << " ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END() // TestBLSHelper

}  // namespace tests
}  // namespace mps
}  // namespace ndn
