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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "util/panic.h"

namespace proofs {

struct RipemdWitness {
  using v32 = uint32_t;

  struct BlockWitness {
    uint32_t left_temp[80];
    uint32_t left_calc[80];
    uint32_t right_temp[80];
    uint32_t right_calc[80];
    uint32_t h_out[5];
  };

  static void witness_block(const uint32_t in[16], const uint32_t H0[5],
                            uint32_t left_temp[80], uint32_t left_calc[80],
                            uint32_t right_temp[80], uint32_t right_calc[80],
                            uint32_t H1[5]);

  static void witness_message(const std::vector<uint8_t>& msg,
                              std::vector<BlockWitness>& witnesses);

  static std::vector<uint8_t> PadMessage(const std::vector<uint8_t>& msg);

  template <class Field, int plucker_size = 1>
  static void fill_input(DenseFiller<Field>& filler,
                         const std::vector<uint8_t>& message, size_t ninputs,
                         size_t maxBlocks, const Field& f);
};

template <class Field, int plucker_size>
void RipemdWitness::fill_input(DenseFiller<Field>& filler,
                               const std::vector<uint8_t>& message,
                               size_t ninputs, size_t maxBlocks,
                               const Field& f) {
  std::vector<RipemdWitness::BlockWitness> bwb;
  RipemdWitness::witness_message(message, bwb);
  size_t numBlocks = maxBlocks;
  uint8_t numb = bwb.size();

  // checking if message fits in maxBlocks
  check(bwb.size() <= maxBlocks, "bwb.size() <= maxBlocks");

  // fill input wires
  filler.push_back(f.one());
  filler.push_back(numb, 8, f);

  // Let's replicate padding here to get full input bytes.
  std::vector<uint8_t> padded = RipemdWitness::PadMessage(message);

  for (size_t j = 0; j < padded.size(); j++) {
    filler.push_back(padded[j], 8, f);
  }
  // If padded.size() < 64 * numBlocks, fill remaining.
  for (size_t j = padded.size(); j < 64 * numBlocks; j++) {
    filler.push_back((uint8_t)0, 8, f);
  }

  // Target hash.
  if (!bwb.empty()) {
    const auto& final_h = bwb.back().h_out;
    for (int j = 0; j < 5; ++j) {
      uint32_t val = final_h[j];
      for (int k = 0; k < 32; ++k) {
        uint8_t bit = (val >> k) & 1;
        filler.push_back(bit ? f.one() : f.zero());
      }
    }
  } else {
    for (int k = 0; k < 160; ++k) filler.push_back(f.zero());
  }

  // Block witnesses.
  BitPluckerEncoder<Field, plucker_size> BPENC(f);
  // Pad witnesses if needed
  if (bwb.size() < numBlocks) {
    auto last_h = bwb.empty() ? std::array<uint32_t, 5>{0x67452301, 0xEFCDAB89,
                                                        0x98BADCFE, 0x10325476,
                                                        0xC3D2E1F0}
                              : std::array<uint32_t, 5>{0};
    if (!bwb.empty()) {
      for (int k = 0; k < 5; ++k) last_h[k] = bwb.back().h_out[k];
    }

    // We need to generate witnesses for compressing blocks of 0s.
    // The input for these blocks is 0.
    uint32_t zero_block[16] = {0};
    for (size_t j = bwb.size(); j < numBlocks; ++j) {
      RipemdWitness::BlockWitness bw;
      uint32_t h1[5];
      RipemdWitness::witness_block(zero_block, last_h.data(), bw.left_temp,
                                   bw.left_calc, bw.right_temp, bw.right_calc,
                                   h1);
      for (int k = 0; k < 5; ++k) bw.h_out[k] = h1[k];  // Store h1 as h_out
      bwb.push_back(bw);
      for (int k = 0; k < 5; ++k) last_h[k] = h1[k];
    }
  }

  for (size_t j = 0; j < numBlocks; j++) {
    const auto& w = bwb[j];
    for (size_t k = 0; k < 80; ++k) {
      filler.push_back(BPENC.mkpacked_v32(w.left_temp[k]));
      filler.push_back(BPENC.mkpacked_v32(w.left_calc[k]));
      filler.push_back(BPENC.mkpacked_v32(w.right_temp[k]));
      filler.push_back(BPENC.mkpacked_v32(w.right_calc[k]));
    }
    for (size_t k = 0; k < 5; ++k) {
      filler.push_back(BPENC.mkpacked_v32(w.h_out[k]));
    }
  }
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_WITNESS_H_
