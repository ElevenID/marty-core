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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_BITADDR_BITADDR_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_BITADDR_BITADDR_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/tests/ec/pk_witness.h"
#include "circuits/tests/ripemd/ripemd_witness.h"
#include "ec/p256k1.h"

namespace proofs {

// Helper to construct witness for BitaddrCircuit
class BitaddrWitness {
 public:
  using Field = Fp256k1Base;
  using EC = P256k1;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;

  const Field& f_;
  PkWitness<EC, Field> ecpk_;
  Elt pkx_, pky_;
  // Use fixed size arrays or single instances as we only have 1 block
  FlatSHA256Witness::BlockWitness sha_;
  RipemdWitness::BlockWitness ripemd_;

  explicit BitaddrWitness(const Field& f) : f_(f), ecpk_(f, p256k1) {}

  // Compute witness from secret key sk
  bool compute_witness(const Nat& sk) {
    // 1. Ecpk Witness
    if (!ecpk_.compute_witness(sk)) {
      return false;
    }

    // 2. Compute SHA256 Input (Prefix + x bytes)
    // Need public key x coordinate.
    EC::ECPoint Q = p256k1.scalar_multf(p256k1.generator(), sk);
    p256k1.normalize(Q);
    pkx_ = Q.x;
    pky_ = Q.y;

    Nat nx = f_.from_montgomery(pkx_);
    Nat ny = f_.from_montgomery(pky_);

    int y_lsb = ny.bit(0);
    uint8_t prefix = (y_lsb == 0) ? 0x02 : 0x03;

    std::vector<uint8_t> sha_msg;
    sha_msg.reserve(33);
    sha_msg.push_back(prefix);

    for (size_t i = 0; i < 32; ++i) {
      uint8_t b = 0;
      for (int j = 0; j < 8; ++j) {
        if (nx.bit(255 - (i * 8 + j))) {
          b |= (1 << (7 - j));
        }
      }
      sha_msg.push_back(b);
    }

    // 3. SHA256 Witness
    uint8_t nb_sha = 0;
    std::vector<uint8_t> sha_padded_in(64 * 1);
    FlatSHA256Witness::transform_and_witness_message(
        sha_msg.size(), sha_msg.data(), 1, nb_sha, sha_padded_in.data(), &sha_);

    // 4. RIPEMD Witness
    // Extract SHA output from sha.h1 (Big Endian words)
    std::vector<uint8_t> ripemd_msg;
    ripemd_msg.reserve(32);
    for (int i = 0; i < 8; ++i) {
      uint32_t w = sha_.h1[i];
      ripemd_msg.push_back((w >> 24) & 0xFF);
      ripemd_msg.push_back((w >> 16) & 0xFF);
      ripemd_msg.push_back((w >> 8) & 0xFF);
      ripemd_msg.push_back(w & 0xFF);
    }

    // Compute RIPEMD160 Witness using helper
    std::vector<RipemdWitness::BlockWitness> r_bw;
    RipemdWitness::witness_message(ripemd_msg, r_bw);
    ripemd_ = r_bw[0];

    return true;
  }

  // Fills the filler with all witness values
  // Only used by ZkProver test, not LogicEvaluation test
  // Assumes compute_witness has been called
  void fill_witness(DenseFiller<Field>& filler) const {
    ecpk_.fill_witness(filler);

    filler.push_back(pkx_);
    filler.push_back(pky_);

    Nat nx = f_.from_montgomery(pkx_);
    Nat ny = f_.from_montgomery(pky_);
    for (size_t i = 0; i < EC::kBits; ++i)
      filler.push_back(f_.of_scalar(nx.bit(i)));
    for (size_t i = 0; i < EC::kBits; ++i)
      filler.push_back(f_.of_scalar(ny.bit(i)));

    BitPluckerEncoder<Field, 2> enc(f_);
    auto push_packed = [&](uint32_t val) {
      auto packed = enc.mkpacked_v32(val);
      for (const auto& x : packed) {
        filler.push_back(x);
      }
    };

    for (int k = 0; k < 48; ++k) push_packed(sha_.outw[k]);
    for (int k = 0; k < 64; ++k) {
      push_packed(sha_.oute[k]);
      push_packed(sha_.outa[k]);
    }
    for (int k = 0; k < 8; ++k) push_packed(sha_.h1[k]);

    const auto& r_bw = ripemd_;
    for (int k = 0; k < 80; ++k) {
      push_packed(r_bw.left_temp[k]);
      push_packed(r_bw.left_calc[k]);
      push_packed(r_bw.right_temp[k]);
      push_packed(r_bw.right_calc[k]);
    }
    for (int k = 0; k < 5; ++k) push_packed(r_bw.h_out[k]);
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_BITADDR_BITADDR_WITNESS_H_
