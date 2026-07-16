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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_CIRCUIT_H_

#include <stddef.h>

#include <cstdint>
#include <vector>

#include "circuits/logic/bit_adder.h"
#include "circuits/tests/ripemd/ripemd_constants.h"
#include "util/panic.h"

namespace proofs {

// Ripemd160Circuit
//
// Implements RIPEMD-160 hash function as an arithmetic circuit.
template <class Logic, class BitPlucker>
class Ripemd160Circuit {
 public:
  using v32 = typename Logic::v32;
  using Field = typename Logic::Field;
  using packed_v32 = typename BitPlucker::packed_v32;
  using v8 = typename Logic::v8;
  using v64 = typename Logic::v64;
  using v160 = typename Logic::template bitvec<160>;

  const Logic& l_;
  BitPlucker bp_;

  static packed_v32 packed_input(const Logic& lc) {
    return BitPlucker::template packed_input<packed_v32>(lc);
  }

  struct BlockWitness {
    // For each of the 80 steps, maintain two witnesses for left/right:
    // L_temp[i] = a + f(...) + X[r] + K
    // L_calc[i] = rol(L_temp[i], s) + e
    packed_v32 left_temp[80];
    packed_v32 left_calc[80];

    // Same for right path
    packed_v32 right_temp[80];
    packed_v32 right_calc[80];

    packed_v32 h_out[5];

    void input(const Logic& lc) {
      for (size_t k = 0; k < 80; ++k) {
        left_temp[k] = packed_input(lc);
        left_calc[k] = packed_input(lc);
        right_temp[k] = packed_input(lc);
        right_calc[k] = packed_input(lc);
      }
      for (size_t k = 0; k < 5; ++k) {
        h_out[k] = packed_input(lc);
      }
    }
  };

  explicit Ripemd160Circuit(const Logic& l) : l_(l), bp_(l_) {}

  // Verifies the compression function for one block.
  // H1 is the state resulting from applying in[16] to state H0.
  // The helper arrays (left_temp, left_calc, etc) are witnesses that allow
  // us to verify the 80 steps of the compression function with low-degree
  // constraints.
  // We check that:
  //   left_temp[i] == a + f(b, c, d) + x + k
  //   left_calc[i] == rol(left_temp[i], s) + e
  // and similarly for the right path.
  void assert_transform_block(const v32 in[16], const v32 H0[5],
                              const v32 left_temp[80], const v32 left_calc[80],
                              const v32 right_temp[80],
                              const v32 right_calc[80], const v32 H1[5]) const {
    const Logic& L = l_;
    BitAdder<Logic, 32> BA(L);

    // Initialize state
    v32 a(H0[0]);
    v32 b(H0[1]);
    v32 c(H0[2]);
    v32 d(H0[3]);
    v32 e(H0[4]);
    v32 aa(H0[0]);
    v32 bb(H0[1]);
    v32 cc(H0[2]);
    v32 dd(H0[3]);
    v32 ee(H0[4]);

    // Main loop: 5 rounds of 16 steps
    for (int round = 0; round < 5; ++round) {
      for (int step = 0; step < 16; ++step) {
        int idx = round * 16 + step;

        // Left path
        // t = rol(a + f(b, c, d) + X[r] + K, s) + e
        // Decomposed:
        // temp = a + f(b, c, d) + X[r] + K
        // calc = rol(temp, s) + e
        // b_new = calc
        {
          auto f_val = f_round_left(round, b, c, d);
          const v32& x_val = in[ripemd::RL[round][step]];
          auto k_val = L.vbit32(ripemd::KL[round]);

          // Verify left_temp[idx] == a + f_val + x_val + k_val
          BA.assert_eqmod(left_temp[idx], BA.add({a, f_val, x_val, k_val}), 4);

          auto rot_val = rol(left_temp[idx], ripemd::SL[round][step]);

          // Verify left_calc[idx] == rot_val + e
          BA.assert_eqmod(left_calc[idx], BA.add({rot_val, e}), 2);

          // Update left state
          a = e;
          e = d;
          d = rol(c, 10);
          c = b;
          b = left_calc[idx];
        }

        // Right path
        {
          auto f_val = f_round_right(round, bb, cc, dd);
          const v32& x_val = in[ripemd::RR[round][step]];
          auto k_val = L.vbit32(ripemd::KR[round]);

          // Verify right_temp[idx] == aa + f_val + x_val + k_val
          BA.assert_eqmod(right_temp[idx], BA.add({aa, f_val, x_val, k_val}),
                          4);

          auto rot_val = rol(right_temp[idx], ripemd::SR[round][step]);

          // Verify right_calc[idx] == rot_val + ee
          BA.assert_eqmod(right_calc[idx], BA.add({rot_val, ee}), 2);

          // Update right state
          aa = ee;
          ee = dd;
          dd = rol(cc, 10);
          cc = bb;
          bb = right_calc[idx];
        }
      }
    }

    // Combine results
    // H1[0] = H0[1] + c + dd
    // H1[1] = H0[2] + d + ee
    // H1[2] = H0[3] + e + aa
    // H1[3] = H0[4] + a + bb
    // H1[4] = H0[0] + b + cc

    BA.assert_eqmod(H1[0], BA.add({H0[1], c, dd}), 3);
    BA.assert_eqmod(H1[1], BA.add({H0[2], d, ee}), 3);
    BA.assert_eqmod(H1[2], BA.add({H0[3], e, aa}), 3);
    BA.assert_eqmod(H1[3], BA.add({H0[4], a, bb}), 3);
    BA.assert_eqmod(H1[4], BA.add({H0[0], b, cc}), 3);
  }

  // Packed API
  // Asserts that state H1 results from applying in[] to H0.
  // bw is the witness for the compression function.
  void assert_transform_block(const v32 in[16], const v32 H0[5],
                              const BlockWitness& bw, const v32 H1[5]) const {
    std::vector<v32> left_temp(80), left_calc(80);
    std::vector<v32> right_temp(80), right_calc(80);

    for (int i = 0; i < 80; ++i) {
      left_temp[i] = bp_.unpack_v32(bw.left_temp[i]);
      left_calc[i] = bp_.unpack_v32(bw.left_calc[i]);
      right_temp[i] = bp_.unpack_v32(bw.right_temp[i]);
      right_calc[i] = bp_.unpack_v32(bw.right_calc[i]);
    }

    assert_transform_block(in, H0, left_temp.data(), left_calc.data(),
                           right_temp.data(), right_calc.data(), H1);
  }

  // Packed API
  // Asserts that state H1 results from applying in[] to H0.
  // bw is the witness for the compression function.
  // In this version, the pH1 array is bit-packed for efficiency.
  void assert_transform_block_packed(const v32 in[16], const v32 H0[5],
                                     const BlockWitness& bw,
                                     const packed_v32 pH1[5]) const {
    std::vector<v32> H1(5);
    for (int i = 0; i < 5; ++i) H1[i] = bp_.unpack_v32(pH1[i]);

    assert_transform_block(in, H0, bw, H1.data());
  }

  // Asserts that target is the result of hashing the message of length at most
  // 64*max bytes in the in[] array. nb is the number of blocks in the message.
  // The in[] array must be zero-padded for the non-used blocks.
  void assert_message_hash(size_t max, const v8& nb, const v8 in[/* 64*max */],
                           const v160& target,
                           const BlockWitness bw[/*max*/]) const {
    assert_message(max, nb, in, bw);
    assert_hash(max, target, nb, bw);
  }

  // Returns the length of the message in bits.
  v64 find_len(size_t max, const v8 in[/*64*max*/], const v8& nb) const {
    const Logic& L = l_;
    v64 len = L.template vbit<64>(0);
    for (size_t i = 0; i < max; ++i) {
      auto isblk = L.veq(nb, i + 1);  // If nb == i, i is zero-indexed.
      size_t ind = i * 64 + 63;
      for (size_t j = 0; j < 64; ++j) { /* this loop is over bits */
        len[j] =
            L.lor_exclusive(len[j], L.land(isblk, in[ind - 7 + j / 8][j % 8]));
      }
    }
    L.vassert_is_bit(len);
    return len;
  }

  // This method asserts that the BlockWitnesses are correct for the given
  // message.
  void assert_message(size_t max, const v8& nb, const v8 in[/* 64*max */],
                      const BlockWitness bw[/*max*/]) const {
    const Logic& L = l_;
    const packed_v32* H = nullptr;
    std::vector<v32> tmp(16);

    for (size_t b = 0; b < max; ++b) {
      const v8* inb = &in[64 * b];
      for (size_t i = 0; i < 16; ++i) {
        // Little-endian mapping of v8[4] into v32.
        // inb[4*i + 0] is LSB.
        tmp[i] = L.vappend(L.vappend(inb[4 * i + 0], inb[4 * i + 1]),
                           L.vappend(inb[4 * i + 2], inb[4 * i + 3]));
      }
      if (b == 0) {
        v32 H0[5];
        initial_context(H0);
        v32 H1[5];
        for (int k = 0; k < 5; ++k) H1[k] = bp_.unpack_v32(bw[b].h_out[k]);
        assert_transform_block(tmp.data(), H0, bw[b], H1);
      } else {
        assert_transform_block_packed_H0(tmp.data(), H, bw[b], bw[b].h_out);
      }
      H = bw[b].h_out;
    }
    assert_zero_padding(max, nb, in);
  }

 private:
  // Overload for packed H0
  void assert_transform_block_packed_H0(const v32 in[16],
                                        const packed_v32 pH0[5],
                                        const BlockWitness& bw,
                                        const packed_v32 pH1[5]) const {
    std::vector<v32> H0(5);
    for (int i = 0; i < 5; ++i) H0[i] = bp_.unpack_v32(pH0[i]);

    assert_transform_block_packed(in, H0.data(), bw, pH1);
  }

  void assert_hash(size_t max, const v160& e, const v8& nb,
                   const BlockWitness bw[/*max*/]) const {
    const Logic& L = l_;
    packed_v32 x[5];
    for (size_t b = 0; b < max; ++b) {
      auto bt = L.veq(nb, b + 1); /* b is zero-indexed */
      auto ebt = L.eval(bt);
      for (size_t i = 0; i < 5; ++i) {
        for (size_t k = 0; k < bp_.kNv32Elts; ++k) {
          if (b == 0) {
            x[i][k] = L.mul(ebt, bw[b].h_out[i][k]);
          } else {
            auto maybe_h = L.mul(ebt, bw[b].h_out[i][k]);
            x[i][k] = L.add(x[i][k], maybe_h);
          }
        }
      }
    }

    // Unpack H0..H4 into v160.
    // RIPEMD-160 is little-endian.
    v160 mm;
    for (size_t j = 0; j < 5; ++j) {
      auto hj = bp_.unpack_v32(x[j]);
      for (size_t k = 0; k < 32; ++k) {
        mm[j * 32 + k] = hj[k];
      }
    }
    L.vassert_eq(mm, e);
  }

  void assert_zero_padding(size_t max, const v8& nb,
                           const v8 in[/*64 * max*/]) const {
    const Logic& L = l_;
    for (size_t i = 0; i < max; ++i) {
      auto wantzero = L.vleq(nb, i);  // If nb <= i, block should be 0.
      for (size_t j = 0; j < 64; ++j) {
        size_t ind = i * 64 + j;
        auto zero = L.veq(in[ind], 0);
        L.assert_implies(wantzero, zero);
      }
    }
  }

  v32 rol(const v32& x, int n) const { return l_.vrotl(x, n); }

  v32 f1(const v32& x, const v32& y, const v32& z) const {
    return l_.vxor3(x, y, z);
  }

  v32 f2(const v32& x, const v32& y, const v32& z) const {
    // (x & y) | (~x & z)
    return l_.vCh(x, y, z);
  }

  v32 f3(const v32& x, const v32& y, const v32& z) const {
    // (x | ~y) ^ z
    auto noty = l_.vnot(y);
    auto xsuby = l_.vor(x, noty);
    return l_.vxor(xsuby, z);
  }

  v32 f4(const v32& x, const v32& y, const v32& z) const {
    // (x & z) | (y & ~z)
    return l_.vCh(z, x, y);
  }

  v32 f5(const v32& x, const v32& y, const v32& z) const {
    // x ^ (y | ~z)
    return f3(y, z, x);
  }

  // Helper to select function based on round
  v32 f_round_left(int round, const v32& x, const v32& y, const v32& z) const {
    switch (round) {
      case 0:
        return f1(x, y, z);
      case 1:
        return f2(x, y, z);
      case 2:
        return f3(x, y, z);
      case 3:
        return f4(x, y, z);
      case 4:
        return f5(x, y, z);
    }
    check(false, "Invalid round");
    return v32(x);
  }

  v32 f_round_right(int round, const v32& x, const v32& y, const v32& z) const {
    switch (round) {
      case 0:
        return f5(x, y, z);
      case 1:
        return f4(x, y, z);
      case 2:
        return f3(x, y, z);
      case 3:
        return f2(x, y, z);
      case 4:
        return f1(x, y, z);
    }
    check(false, "Invalid round");
    return v32(x);
  }

  void initial_context(v32 H[5]) const {
    static const uint32_t initial[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE,
                                        0x10325476, 0xC3D2E1F0};
    for (size_t i = 0; i < 5; i++) {
      H[i] = l_.template vbit<32>(initial[i]);
    }
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_CIRCUIT_H_
