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

#include "circuits/tests/ripemd/ripemd_witness.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "circuits/tests/ripemd/ripemd_constants.h"

namespace proofs {

namespace ripemd {
inline uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

inline uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t f2(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) | (~x & z);
}
inline uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
inline uint32_t f4(uint32_t x, uint32_t y, uint32_t z) {
  return (x & z) | (y & ~z);
}
inline uint32_t f5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

#define ROTATE_STATE(a, b, c, d, e, t) \
  do {                                 \
    (a) = (e);                         \
    (e) = (d);                         \
    (d) = rol((c), 10);                \
    (c) = (b);                         \
    (b) = (t);                         \
  } while (0)

inline uint32_t f_round_left(int r, uint32_t x, uint32_t y, uint32_t z) {
  switch (r) {
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
  return 0;
}

inline uint32_t f_round_right(int r, uint32_t x, uint32_t y, uint32_t z) {
  switch (r) {
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
  return 0;
}

}  // namespace ripemd

using ripemd::f_round_left;
using ripemd::f_round_right;
using ripemd::KL;
using ripemd::KR;
using ripemd::RL;
using ripemd::rol;
using ripemd::RR;
using ripemd::SL;
using ripemd::SR;

void RipemdWitness::witness_block(const uint32_t in[16], const uint32_t H0[5],
                                  uint32_t left_temp[80],
                                  uint32_t left_calc[80],
                                  uint32_t right_temp[80],
                                  uint32_t right_calc[80], uint32_t H1[5]) {
  uint32_t a = H0[0], b = H0[1], c = H0[2], d = H0[3], e = H0[4];
  uint32_t aa = H0[0], bb = H0[1], cc = H0[2], dd = H0[3], ee = H0[4];

  for (int round = 0; round < 5; ++round) {
    for (int step = 0; step < 16; ++step) {
      int idx = round * 16 + step;

      // Left
      {
        uint32_t f_val = f_round_left(round, b, c, d);
        uint32_t temp = a + f_val + in[RL[round][step]] + KL[round];
        left_temp[idx] = temp;
        uint32_t calc = rol(temp, SL[round][step]) + e;
        left_calc[idx] = calc;
        ROTATE_STATE(a, b, c, d, e, calc);
      }

      // Right
      {
        uint32_t f_val = f_round_right(round, bb, cc, dd);
        uint32_t temp = aa + f_val + in[RR[round][step]] + KR[round];
        right_temp[idx] = temp;
        uint32_t calc = rol(temp, SR[round][step]) + ee;
        right_calc[idx] = calc;
        ROTATE_STATE(aa, bb, cc, dd, ee, calc);
      }
    }
  }

  H1[0] = H0[1] + c + dd;
  H1[1] = H0[2] + d + ee;
  H1[2] = H0[3] + e + aa;
  H1[3] = H0[4] + a + bb;
  H1[4] = H0[0] + b + cc;
}

std::vector<uint8_t> RipemdWitness::PadMessage(
    const std::vector<uint8_t>& msg) {
  std::vector<uint8_t> padded = msg;
  uint64_t L = padded.size() * 8;
  padded.push_back(0x80);
  while ((padded.size() % 64) != 56) {
    padded.push_back(0x00);
  }
  // Append length (64-bit little endian)
  for (int i = 0; i < 8; ++i) {
    padded.push_back((L >> (i * 8)) & 0xff);
  }
  return padded;
}

void RipemdWitness::witness_message(const std::vector<uint8_t>& msg,
                                    std::vector<BlockWitness>& witnesses) {
  // 1. Padding
  std::vector<uint8_t> padded = PadMessage(msg);

  // 2. Process blocks
  size_t num_blocks = padded.size() / 64;
  witnesses.resize(num_blocks);
  uint32_t initial[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                         0xC3D2E1F0};
  const uint32_t* H = initial;

  for (size_t b = 0; b < num_blocks; ++b) {
    uint32_t in[16];
    for (int i = 0; i < 16; ++i) {
      // Little endian load
      in[i] = (uint32_t)padded[b * 64 + i * 4 + 0] |
              ((uint32_t)padded[b * 64 + i * 4 + 1] << 8) |
              ((uint32_t)padded[b * 64 + i * 4 + 2] << 16) |
              ((uint32_t)padded[b * 64 + i * 4 + 3] << 24);
    }
    witness_block(in, H, witnesses[b].left_temp, witnesses[b].left_calc,
                  witnesses[b].right_temp, witnesses[b].right_calc,
                  witnesses[b].h_out);
    H = witnesses[b].h_out;
  }
}
}  // namespace proofs
