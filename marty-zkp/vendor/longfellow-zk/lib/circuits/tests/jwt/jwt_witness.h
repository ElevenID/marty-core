// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_JWT_JWT_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_JWT_JWT_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/tests/base64/decode_util.h"
#include "circuits/tests/jwt/jwt_constants.h"
#include "util/crypto.h"
#include "util/log.h"

namespace proofs {

/* This struct allows a verifier to express which attribute and value the prover
 * must claim. */
struct OpenedAttribute {
  uint8_t id[32];
  uint8_t value[64];
  size_t id_len, value_len;
};

template <class Field>
bool fill_attribute(DenseFiller<Field>& filler, const OpenedAttribute& attr,
                    const Field& F, size_t version) {
  std::vector<uint8_t> vbuf;
  vbuf.push_back('"');
  vbuf.insert(vbuf.end(), attr.id, attr.id + attr.id_len);
  vbuf.push_back('"');
  vbuf.push_back(':');
  vbuf.push_back('"');
  vbuf.insert(vbuf.end(), attr.value, attr.value + attr.value_len);
  vbuf.push_back('"');
  for (size_t i = 0; i < 128; ++i) {
    if (i < vbuf.size()) {
      filler.push_back(vbuf[i], 8, F);
    } else {
      filler.push_back(0, 8, F);
    }
  }
  filler.push_back(vbuf.size(), 8, F);
  return true;
}


template <class EC, class ScalarField, size_t SHABlocks>
class JWTWitness {
  constexpr static size_t kMaxSHABlocks = SHABlocks;
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  using EcdsaWitness = VerifyWitness3<EC, ScalarField>;
  const EC& ec_;

 public:
  Elt e_, dpkx_, dpky_;
  EcdsaWitness sig_;
  EcdsaWitness kb_sig_;

  uint8_t preimage_[64 * kMaxSHABlocks];
  uint8_t e_bits_[256];
  FlatSHA256Witness::BlockWitness sha_bw_[kMaxSHABlocks];
  uint8_t numb_; /* Number of the correct sha block. */
  uint8_t na_;   /* Number of attributes. */
  size_t payload_ind_, payload_len_;
  std::vector<size_t> attr_ind_;

  struct Jws {
    std::string msg;
    std::string payload;
    size_t payload_len, payload_ind;
    Nat ne, nr, ns;
    Elt e, r, s;
  };

  bool parse_jws(std::string jwt, Jws& jws) {
    size_t dot = jwt.find_first_of('.');
    if (dot == std::string::npos) {
      log(ERROR, "JWT is not well-formed");
      return false;
    }
    size_t dot2 = jwt.find_first_of('.', dot + 1);
    if (dot2 == std::string::npos) {
      log(ERROR, "JWT is not in the format of header.payload.signature");
      return false;
    }
    auto hdr = jwt.substr(0, dot);
    auto pld = jwt.substr(dot + 1, dot2 - dot - 1);
    auto sig = jwt.substr(dot2 + 1);
    jws.msg = jwt.substr(0, dot2);
    jws.payload = pld;
    jws.payload_ind = dot + 1;
    jws.payload_len = pld.size();

    uint8_t hash[kSHA256DigestSize];
    SHA256 sha;
    sha.Update((const uint8_t*)jws.msg.data(), dot2);
    sha.DigestData(hash);
    jws.ne = nat_from_be(hash);

    std::vector<uint8_t> sigb;
    sigb.reserve(ec_.f_.kBytes * 2);
    if (!base64_decode_url(sig, sigb) || sigb.size() < ec_.f_.kBytes * 2) {
      log(ERROR, "signature is not in the format of base64url");
      return false;
    }
    jws.nr = nat_from_be(&sigb[0]);
    jws.ns = nat_from_be(&sigb[ec_.f_.kBytes]);

    jws.e = ec_.f_.to_montgomery(jws.ne);
    jws.r = ec_.f_.to_montgomery(jws.nr);
    jws.s = ec_.f_.to_montgomery(jws.ns);

    return true;
  }

  explicit JWTWitness(const EC& ec, const ScalarField& Fn)
      : ec_(ec), sig_(Fn, ec), kb_sig_(Fn, ec) {}

  void fill_witness(DenseFiller<Field>& filler) const {
    filler.push_back(e_);
    filler.push_back(dpkx_);
    filler.push_back(dpky_);
    sig_.fill_witness(filler);
    kb_sig_.fill_witness(filler);

    // Write the message.
    for (size_t i = 0; i < 64 * kMaxSHABlocks; ++i) {
      filler.push_back(preimage_[i], 8, ec_.f_);
    }

    for (size_t i = 0; i < 256; ++i) {
      filler.push_back(e_bits_[i], 1, ec_.f_);
    }

    for (size_t j = 0; j < kMaxSHABlocks; ++j) {
      fill_sha(filler, sha_bw_[j]);
    }

    filler.push_back(numb_, 8, ec_.f_);

    for (size_t i = 0; i < na_; ++i) {
      filler.push_back(attr_ind_[i], kJWTIndexBits, ec_.f_);
    }

    filler.push_back(payload_ind_, kJWTIndexBits, ec_.f_);
    filler.push_back(payload_len_, kJWTIndexBits, ec_.f_);
  }

  void fill_sha(DenseFiller<Field>& filler,
                const FlatSHA256Witness::BlockWitness& bw) const {
    BitPluckerEncoder<Field, kSHAJWTPluckerBits> BPENC(ec_.f_);
    for (size_t k = 0; k < 48; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.oute[k]));
      filler.push_back(BPENC.mkpacked_v32(bw.outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.h1[k]));
    }
  }

  // Transform from u32 be (i.e., be[0] is the most significant nibble)
  // into nat form, which requires first converting to le byte order.
  Nat nat_from_u32(const uint32_t be[]) const {
    uint8_t tmp[Nat::kBytes];
    const size_t top = Nat::kBytes / 4;
    for (size_t i = 0; i < Nat::kBytes; ++i) {
      tmp[i] = (be[top - i / 4 - 1] >> ((i % 4) * 8)) & 0xff;
    }
    return Nat::of_bytes(tmp);
  }

  // Transform from u8 be (i.e., be[31] is the most significant byte) into
  // nat form, which requires first converting to le byte order.
  Nat nat_from_be(const uint8_t be[/* Nat::kBytes */]) {
    uint8_t tmp[Nat::kBytes];
    // Transform into byte-wise le representation.
    for (size_t i = 0; i < Nat::kBytes; ++i) {
      tmp[i] = be[Nat::kBytes - i - 1];
    }
    return Nat::of_bytes(tmp);
  }

  bool compute_witness(std::string jwt, Elt pkX, Elt pkY,
                       std::vector<OpenedAttribute> attrs) {
    size_t tilde = jwt.find_first_of('~');
    if (tilde == std::string::npos) {
      log(ERROR, "JWT is not in the format of header.payload.signature~kb");
      return false;
    }
    auto id = jwt.substr(0, tilde);
    auto kb = jwt.substr(tilde + 1);
    Jws id_jws;
    if (!parse_jws(id, id_jws)) {
      return false;
    }

    if (id_jws.msg.size() > kMaxSHABlocks * 64 - 9) {
      log(INFO, "JWT payload bytes is too large");
      return false;
    }

    FlatSHA256Witness::transform_and_witness_message(
        id_jws.msg.size(), reinterpret_cast<const uint8_t*>(id_jws.msg.data()),
        kMaxSHABlocks, numb_, preimage_, sha_bw_);

    e_ = id_jws.e;
    payload_ind_ = id_jws.payload_ind;
    payload_len_ = id_jws.payload_len;
    if (!sig_.compute_witness(pkX, pkY, id_jws.ne, id_jws.nr, id_jws.ns)) {
      log(ERROR, "signature verification failed");
      return false;
    }

    for (size_t i = 0; i < 256; ++i) {
      e_bits_[i] = id_jws.ne.bit(i);
    }

    // Find the positions of each of the attributes.
    na_ = attrs.size();
    std::vector<uint8_t> payload;
    payload.reserve(id_jws.payload.size());
    if (!base64_decode_url(id_jws.payload, payload)) {
      log(ERROR, "JWT payload is not in the format of base64url");
      return false;
    }
    std::string str((const char*)payload.data(), payload.size());
    for (size_t i = 0; i < na_; ++i) {
      std::string idm =
          "\"" + std::string((const char*)attrs[i].id, attrs[i].id_len) +
          "\":\"" +
          std::string((const char*)attrs[i].value, attrs[i].value_len) + "\"";
      size_t ind = str.find(idm, 0);
      if (ind == std::string::npos) {
        log(ERROR, "Could not find attribute %s", idm.c_str());
        return false;
      }
      attr_ind_.push_back(ind);
    }

    // Find device public key in payload.
    std::string cnf_prefix =
        "\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"";
    size_t x_ind = str.find(cnf_prefix.data(), 0, cnf_prefix.size());
    if (x_ind == std::string::npos) {
      log(ERROR, "Could not find device public key in payload");
      return false;
    }
    size_t y_ind = str.find("\",\"y\":\"", x_ind + cnf_prefix.size());
    if (y_ind == std::string::npos) {
      log(ERROR, "Could not find device public key in payload");
      return false;
    }
    std::string x = str.substr(x_ind + cnf_prefix.size(), 43);
    std::string y = str.substr(y_ind + 7, 43);
    std::vector<uint8_t> dpkx, dpky;
    dpkx.reserve(65); dpky.reserve(65);
    if (!base64_decode_url(x, dpkx)) {
      log(ERROR, "CNF:dpkx payload is not in the format of base64url");
      return false;
    }
    if (!base64_decode_url(y, dpky)) {
      log(ERROR, "CNF:dpky payload is not in the format of base64url");
      return false;
    }
    Nat nx = nat_from_be(dpkx.data());
    Nat ny = nat_from_be(dpky.data());
    dpkx_ = ec_.f_.to_montgomery(nx);
    dpky_ = ec_.f_.to_montgomery(ny);

    // Process the key binding portion
    if (kb.empty()) {
      log(ERROR, "kb portion is missing");
      return false;
    }
    Jws kb_jws;
    if (!parse_jws(kb, kb_jws)) {
      log(ERROR, "kb jws parsing failed");
      return false;
    }
    if (!kb_sig_.compute_witness(dpkx_, dpky_, kb_jws.ne, kb_jws.nr,
                                 kb_jws.ns)) {
      log(ERROR, "kb signature verification failed");
      return false;
    }
    return true;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_JWT_JWT_WITNESS_H_
