/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2020, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "ndnmps/crypto-helpers.hpp"

#include <boost/endian/conversion.hpp>
#include <cstring>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/random.hpp>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>

namespace ndn {
namespace mps {

ECDHState::ECDHState()
{
  auto EC_NID = NID_X9_62_prime256v1;
  // params context
  EVP_PKEY_CTX* ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_paramgen_init(ctx_params);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_params, EC_NID);
  // generate params
  EVP_PKEY* params = nullptr;
  EVP_PKEY_paramgen(ctx_params, &params);
  // key generation context
  EVP_PKEY_CTX* ctx_keygen = EVP_PKEY_CTX_new(params, nullptr);
  EVP_PKEY_keygen_init(ctx_keygen);
  auto resultCode = EVP_PKEY_keygen(ctx_keygen, &m_privkey);
  EVP_PKEY_CTX_free(ctx_keygen);
  EVP_PKEY_free(params);
  EVP_PKEY_CTX_free(ctx_params);
  if (resultCode <= 0) {
    NDN_THROW(std::runtime_error("Error in initiating ECDH"));
  }
}

ECDHState::~ECDHState()
{
  if (m_privkey != nullptr) {
    EVP_PKEY_free(m_privkey);
  }
}

const std::vector<uint8_t>&
ECDHState::getSelfPubKey()
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(m_privkey);
  if (privECKey == nullptr) {
    NDN_THROW(std::runtime_error("Could not get key when calling EVP_PKEY_get1_EC_KEY()"));
  }
  auto ecPoint = EC_KEY_get0_public_key(privECKey);
  auto group = EC_KEY_get0_group(privECKey);
  auto requiredBufLen = EC_POINT_point2oct(group, ecPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  m_pubKey.resize(requiredBufLen);
  auto rev = EC_POINT_point2oct(group, ecPoint, POINT_CONVERSION_UNCOMPRESSED,
                                m_pubKey.data(), requiredBufLen, nullptr);
  EC_KEY_free(privECKey);
  if (rev == 0) {
    NDN_THROW(std::runtime_error("Could not convert EC_POINTS to octet string when calling EC_POINT_point2oct()"));
  }
  return m_pubKey;
}

const std::vector<uint8_t>&
ECDHState::deriveSecret(const std::vector<uint8_t>& peerKey)
{
  // prepare self private key
  auto privECKey = EVP_PKEY_get1_EC_KEY(m_privkey);
  auto group = EC_KEY_get0_group(privECKey);
  EC_KEY_free(privECKey);
  // prepare the peer public key
  auto peerPoint = EC_POINT_new(group);
  EC_POINT_oct2point(group, peerPoint, peerKey.data(), peerKey.size(), nullptr);
  EC_KEY* ecPeerkey = EC_KEY_new();
  EC_KEY_set_group(ecPeerkey, group);
  EC_KEY_set_public_key(ecPeerkey, peerPoint);
  EVP_PKEY* evpPeerkey = EVP_PKEY_new();
  EVP_PKEY_set1_EC_KEY(evpPeerkey, ecPeerkey);
  EC_KEY_free(ecPeerkey);
  EC_POINT_free(peerPoint);
  // ECDH context
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(m_privkey, nullptr);
  // Initialize
  EVP_PKEY_derive_init(ctx);
  // Provide the peer public key
  EVP_PKEY_derive_set_peer(ctx, evpPeerkey);
  // Determine buffer length for shared secret
  size_t secretLen = 0;
  EVP_PKEY_derive(ctx, nullptr, &secretLen);
  m_secret.resize(secretLen);
  // Derive the shared secret
  auto resultCode = EVP_PKEY_derive(ctx, m_secret.data(), &secretLen);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(evpPeerkey);
  if (resultCode == 0) {
    NDN_THROW(std::runtime_error("Error when calling ECDH"));
  }
  return m_secret;
}

void
hmacSha256(const uint8_t* data, size_t dataLen,
           const uint8_t* key, size_t keyLen,
           uint8_t* result)
{
  auto ret = HMAC(EVP_sha256(), key, keyLen,
                  data, dataLen, result, nullptr);
  if (ret == nullptr) {
    NDN_THROW(std::runtime_error("Error computing HMAC when calling HMAC()"));
  }
}

size_t
hkdf(const uint8_t* secret, size_t secretLen, const uint8_t* salt,
     size_t saltLen, uint8_t* output, size_t outputLen,
     const uint8_t* info, size_t infoLen)
{
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  EVP_PKEY_derive_init(pctx);
  EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
  EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltLen);
  EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretLen);
  EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infoLen);
  size_t outLen = outputLen;
  auto resultCode = EVP_PKEY_derive(pctx, output, &outLen);
  EVP_PKEY_CTX_free(pctx);
  if (resultCode == 0) {
    NDN_THROW(std::runtime_error("Error when calling HKDF"));
  }
  return outLen;
}

size_t
aesGcm128Encrypt(const uint8_t* plaintext, size_t plaintextLen, const uint8_t* associated, size_t associatedLen,
                 const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag)
{
  int len = 0;
  size_t ciphertextLen = 0;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
  EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
  EVP_EncryptUpdate(ctx, nullptr, &len, associated, associatedLen);
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintextLen);
  ciphertextLen = len;
  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  auto resultCode = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
  EVP_CIPHER_CTX_free(ctx);
  if (resultCode == 0) {
    NDN_THROW(std::runtime_error("Error in encryption plaintext with AES GCM"));
  }
  return ciphertextLen;
}

size_t
aesGcm128Decrypt(const uint8_t* ciphertext, size_t ciphertextLen, const uint8_t* associated, size_t associatedLen,
                 const uint8_t* tag, const uint8_t* key, const uint8_t* iv, uint8_t* plaintext)
{
  int len = 0;
  size_t plaintextLen = 0;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
  EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
  EVP_DecryptUpdate(ctx, nullptr, &len, associated, associatedLen);
  EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextLen);
  plaintextLen = len;
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<void*>(reinterpret_cast<const void*>(tag)));
  auto resultCode = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  plaintextLen += len;
  EVP_CIPHER_CTX_free(ctx);
  if (resultCode == 0) {
    NDN_THROW(std::runtime_error("Error in decrypting ciphertext with AES GCM"));
  }
  return plaintextLen;
}

// Can be removed after boost version 1.72, replaced by boost::endian::load_big_u32
static uint32_t
loadBigU32(const std::vector<uint8_t>& iv, size_t pos)
{
  uint32_t result = iv[pos] << 24 | iv[pos + 1] << 16 | iv[pos + 2] << 8 | iv[pos + 3];
  return result;
}

Block
encodeBlockWithAesGcm128(uint32_t tlvType, const uint8_t* key,
                         const uint8_t* payload, size_t payloadSize,
                         const uint8_t* associatedData, size_t associatedDataSize)
{
  // The spec of AES encrypted payload TLV used in NDNCERT:
  //   https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3#242-aes-gcm-encryption
  Buffer encryptedPayload(payloadSize);
  uint8_t tag[16];
  std::vector<uint8_t> encryptionIv;
  encryptionIv.resize(12, 0);
  random::generateSecureBytes(encryptionIv.data(), 8);
  size_t encryptedPayloadLen = aesGcm128Encrypt(payload, payloadSize, associatedData, associatedDataSize,
                                                key, encryptionIv.data(), encryptedPayload.data(), tag);
  Block content(tlvType);
  content.push_back(makeBinaryBlock(tlv::InitializationVector, encryptionIv.data(), encryptionIv.size()));
  content.push_back(makeBinaryBlock(tlv::AuthenticationTag, tag, 16));
  content.push_back(makeBinaryBlock(tlv::EncryptedPayload, encryptedPayload.data(), encryptedPayloadLen));
  content.encode();
  return content;
}

Buffer
decodeBlockWithAesGcm128(const Block& block, const uint8_t* key,
                         const uint8_t* associatedData, size_t associatedDataSize)
{
  // The spec of AES encrypted payload TLV used in NDNCERT:
  //   https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3#242-aes-gcm-encryption
  block.parse();
  const auto& encryptedPayloadBlock = block.get(tlv::EncryptedPayload);
  Buffer result(encryptedPayloadBlock.value_size());
  std::vector<uint8_t> currentIv(block.get(tlv::InitializationVector).value(), block.get(tlv::InitializationVector).value() + 12);
  auto resultLen = aesGcm128Decrypt(encryptedPayloadBlock.value(), encryptedPayloadBlock.value_size(),
                                    associatedData, associatedDataSize, block.get(tlv::AuthenticationTag).value(),
                                    key, currentIv.data(), result.data());
  if (resultLen != encryptedPayloadBlock.value_size()) {
    NDN_THROW(std::runtime_error("Error when decrypting the AES Encrypted Block: "
                                    "Decrypted payload is of an unexpected size"));
  }
  return result;
}

std::string
base64EncodeFromBytes(const uint8_t* data, size_t len, bool needBreak)
{
  std::stringstream ss;
  security::transform::bufferSource(data, len)
      >> security::transform::base64Encode(needBreak)
      >> security::transform::streamSink(ss);
  return ss.str();
}

} // namespace mps
} // namespace ndn
