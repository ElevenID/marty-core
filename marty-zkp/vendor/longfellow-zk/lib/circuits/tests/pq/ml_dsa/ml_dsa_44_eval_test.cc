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

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "algebra/fp24.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_types.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_witness.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp24;
using EvalBackend = EvaluationBackend<Field>;
using EvalLogic = Logic<Field, EvalBackend>;
using MLDSA44Verify = MLDSA44Verify<EvalLogic, Field>;
using v8 = typename EvalLogic::v8;

Sha3Circuit<EvalLogic>::BlockWitness convert_block_witness(
    const EvalLogic& L, const Sha3Witness::BlockWitness& raw_bw) {
  Sha3Circuit<EvalLogic>::BlockWitness bw;
  for (size_t round = 0; round < 24; ++round) {
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) {
        bw.a_intermediate[round][x][y] =
            L.template vbit<64>(raw_bw.a_intermediate[round][x][y]);
      }
    }
  }
  return bw;
}

template <typename Container>
void convert_rqw(MLDSA44Verify::RqW& dst, const Container& src,
                 const EvalLogic& L) {
  for (size_t i = 0; i < ml_dsa::N; ++i) {
    dst.coeffs[i] = L.konst(src[i]);
  }
}

void push_bytes(std::vector<v8>& dst, const uint8_t* src, size_t size,
                const EvalLogic& L) {
  for (size_t i = 0; i < size; ++i) {
    dst.push_back(L.vbit8(src[i]));
  }
}

template <typename SrcContainer, typename DstContainer>
void convert_array(DstContainer& dst, const SrcContainer& src,
                   const EvalLogic& L) {
  for (size_t i = 0; i < src.size(); ++i) {
    dst[i] = L.vbit8(src[i]);
  }
}

template <size_t N, typename SrcContainer, typename DstContainer>
void convert_array_bits(DstContainer& dst, const SrcContainer& src,
                        const EvalLogic& L) {
  for (size_t i = 0; i < src.size(); ++i) {
    dst[i] = L.template vbit<N>(src[i]);
  }
}

MLDSA44Verify::Pk convert_pk(const ml_dsa::PublicKey& ref_pk,
                             const ml_dsa_44_witness& witness_gen,
                             const EvalLogic& L, const Field& F) {
  MLDSA44Verify::Pk pk_w;
  // a_hat
  for (size_t r = 0; r < ml_dsa::K; ++r) {
    for (size_t s = 0; s < ml_dsa::L; ++s) {
      convert_rqw(pk_w.a_hat.mat[r][s], ref_pk.a_hat[r][s], L);
    }
  }
  // t1 -> nttt1
  for (size_t r = 0; r < ml_dsa::K; ++r) {
    convert_rqw(pk_w.nttt1[r], witness_gen.nttt1_[r], L);
  }
  convert_array(pk_w.tr, witness_gen.tr_, L);
  return pk_w;
}

MLDSA44Verify::SignatureW convert_sig(const ml_dsa::Signature& ref_sig,
                                      const ml_dsa_44_witness& witness_gen,
                                      const EvalLogic& L, const Field& F) {
  MLDSA44Verify::SignatureW sig_w;
  // c_tilde
  convert_array(sig_w.c_tilde, witness_gen.c_tilde_, L);
  for (size_t r = 0; r < ml_dsa::L; ++r) {
    convert_rqw(sig_w.z[r], ref_sig.z[r], L);
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      sig_w.z_bits[r][i] = L.template vbit<19>(witness_gen.z_bits_[r][i]);
    }
  }
  // h
  for (size_t r = 0; r < ml_dsa::K; ++r) {
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      sig_w.h[r].coeffs[i] = L.konst(ref_sig.h[r][i] ? F.one() : F.zero());
    }
  }
  return sig_w;
}

MLDSA44Verify::SampleInBallWitness convert_sample_in_ball(
    const ml_dsa_44_witness& witness_gen, const EvalLogic& L, const Field& F) {
  MLDSA44Verify::SampleInBallWitness sib_w;
  sib_w.shake_bws = convert_block_witness(L, witness_gen.shake_bws_);
  for (size_t i = 0; i < ml_dsa::TAU; ++i) {
    sib_w.j_vals[i] = L.vbit8(witness_gen.j_vals_[i]);
    sib_w.j_k_indices[i] = L.template vbit<16>(witness_gen.j_k_indices_[i]);
  }
  // Copy position_trace
  sib_w.position_trace.resize(witness_gen.position_trace_.size());
  for (size_t s = 0; s < witness_gen.position_trace_.size(); ++s) {
    sib_w.position_trace[s].resize(witness_gen.position_trace_[s].size());
    convert_array(sib_w.position_trace[s], witness_gen.position_trace_[s], L);
  }
  return sib_w;
}

MLDSA44Verify::Witness convert_witness(const ml_dsa_44_witness& witness_gen,
                                       const EvalLogic& L, const Field& F) {
  MLDSA44Verify::Witness witness;
  convert_rqw(witness.c_, witness_gen.c_coeffs_, L);

  witness.sample_in_ball_ = convert_sample_in_ball(witness_gen, L, F);

  // Populate nttz, nttc, nttt1, w_prime_approx
  for (size_t i = 0; i < ml_dsa::L; ++i) {
    convert_rqw(witness.nttz_[i], witness_gen.nttz_[i], L);
  }
  convert_rqw(witness.nttc_, witness_gen.nttc_, L);
  for (size_t i = 0; i < ml_dsa::K; ++i) {
    convert_rqw(witness.w_prime_approx_[i], witness_gen.w_prime_approx_[i], L);
  }

  // Populate w1 and hint_aux_bits
  for (size_t i = 0; i < ml_dsa::K; ++i) {
    for (size_t k = 0; k < ml_dsa::N; ++k) {
      int32_t w1_val = witness_gen.w1_[i][k];
      if (w1_val < 0) {
        w1_val += ml_dsa::Q;
      }
      witness.w1_[i].coeffs[k] = L.konst(L.f_.of_scalar(w1_val));
      witness.hint_aux_bits_[i][k] =
          L.template vbit<19>(witness_gen.hint_aux_bits_[i][k]);
    }
  }

  // Populate w_prime_1 and w_prime_1_bits
  for (size_t i = 0; i < ml_dsa::K; ++i) {
    for (size_t k = 0; k < ml_dsa::N; ++k) {
      int32_t w1_val = witness_gen.w_prime_1_[i][k];
      EXPECT_TRUE(w1_val >= 0 && w1_val <= 43);
    }
    convert_rqw(witness.w_prime_1_[i], witness_gen.w_prime_1_[i], L);
    convert_array_bits<6>(witness.w_prime_1_bits_[i],
                          witness_gen.w_prime_1_bits_[i], L);
  }

  // Populate w1_tilde_
  convert_array(witness.w1_tilde_, witness_gen.w1_tilde_, L);

  // Populate c_prime_tilde_bws
  for (const auto& raw_bw : witness_gen.c_prime_tilde_bws_) {
    witness.c_prime_tilde_bws_.push_back(convert_block_witness(L, raw_bw));
  }

  witness.h_sum_bits_ = L.template vbit<7>(witness_gen.h_sum_bits_);

  return witness;
}

TEST(MLDSA44EvalTest, SampleInBall) {
  const Field& F = ml_dsa::Fq;
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  MLDSA44Verify verify(L);

  auto tests = ml_dsa::GetSampleInBallTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    std::vector<uint8_t> rho(32);
    std::array<EvalLogic::v8, 32> rho_w;
    for (int i = 0; i < 32; ++i) {
      rho[i] = tests[t].in[i];
      rho_w[i] = L.vbit8(rho[i]);
    }

    // Run reference SampleInBall to find j_vals, j_k_indices, and num blocks
    // Emulate what SampleInBall does to get the witnesses.
    std::array<uint8_t, 136> out;
    ml_dsa::H(rho, out);

    MLDSA44Verify::SampleInBallWitness witness;

    size_t out_idx = 8;
    witness.position_trace.resize(ml_dsa::TAU);
    std::vector<uint8_t> current_pos;
    current_pos.reserve(ml_dsa::TAU);

    for (size_t s = 0; s < ml_dsa::TAU; ++s) {
      size_t i = 256 - ml_dsa::TAU + s;
      uint8_t j;
      do {
        j = out[out_idx++];
      } while (j > i);
      witness.j_vals[s] = L.vbit8(j);
      witness.j_k_indices[s] = L.template vbit<16>(out_idx - 1);

      for (size_t k = 0; k < current_pos.size(); ++k) {
        if (current_pos[k] == j) {
          current_pos[k] = i;
          break;
        }
      }
      current_pos.push_back(j);

      witness.position_trace[s].reserve(s + 1);
      for (auto p : current_pos) {
        witness.position_trace[s].push_back(L.vbit8(p));
      }
    }

    std::vector<Sha3Witness::BlockWitness> bws;
    Sha3Witness::compute_witness_shake256(rho, 136, bws);
    witness.shake_bws = convert_block_witness(L, bws[0]);

    MLDSA44Verify::RqW cprime;
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      cprime.coeffs[i] = L.konst(F.of_scalar(tests[t].out[i]));
    }

    verify.assert_sample_in_ball(rho_w, cprime, witness);
  }
}

TEST(MLDSA44EvalTest, SHA3_Consistency) {
  const Field& F = ml_dsa::Fq;
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  Sha3Circuit<EvalLogic> sha3(L);

  std::vector<uint8_t> rho(32);
  for (int i = 0; i < 32; ++i) rho[i] = i;

  std::array<uint8_t, 272> expected_out;
  ml_dsa::H(rho, expected_out);

  std::vector<Sha3Witness::BlockWitness> bws;
  Sha3Witness::compute_witness_shake256(rho, 272, bws);

  std::vector<Sha3Circuit<EvalLogic>::BlockWitness> circuit_bws(bws.size());
  for (size_t k = 0; k < bws.size(); ++k) {
    circuit_bws[k] = convert_block_witness(L, bws[k]);
  }

  std::vector<EvalLogic::v8> rho_vec;
  push_bytes(rho_vec, rho.data(), rho.size(), L);

  std::vector<EvalLogic::v8> out;
  sha3.assert_shake256(rho_vec, 272, out, circuit_bws);

  ASSERT_EQ(out.size(), expected_out.size());
  for (size_t i = 0; i < out.size(); ++i) {
    uint8_t val = 0;
    for (int b = 0; b < 8; ++b) {
      if (L.eval(out[i][b]).elt() == F.one()) {
        val |= (1 << b);
      }
    }
    EXPECT_EQ(val, expected_out[i]);
  }
}

TEST(MLDSA44EvalTest, NTTConsistency) {
  const Field& F = ml_dsa::Fq;
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  MLDSA44Verify verify(L);

  auto tests = ml_dsa::GetNTTTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    MLDSA44Verify::RqW w_in, w_out;
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      w_in.coeffs[i] = L.konst(F.of_scalar(tests[t].in[i]));
      w_out.coeffs[i] = L.konst(F.of_scalar(tests[t].out[i]));
    }
    verify.assert_ntt(w_in, w_out);
  }

  for (size_t t = 0; t < tests.size(); ++t) {
    MLDSA44Verify::RqW w_in, w_out;
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      w_in.coeffs[i] = L.konst(F.of_scalar(tests[t].out[i]));
      w_out.coeffs[i] = L.konst(F.of_scalar(tests[t].in[i]));
    }
    verify.assert_inverse_ntt(w_in, w_out);
  }
}

TEST(MLDSA44EvalTest, UseHintSingle) {
  const Field& F = ml_dsa::Fq;
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  MLDSA44Verify verify(L);

  auto tests = ml_dsa::GetUseHintTestCases();
  for (const auto& test_case : tests) {
    bool h = test_case.h;
    int32_t r = test_case.r;
    int32_t expected = test_case.expected;

    auto [r1, r0] = ml_dsa::Decompose(r);

    int32_t w1_raw = r1;
    if (h && r0 > 0)
      w1_raw = r1 + 1;
    else if (h && r0 <= 0)
      w1_raw = r1 - 1;

    int64_t gamma2 = static_cast<int64_t>(ml_dsa::GAMMA_2);
    int64_t delta =
        static_cast<int64_t>(r) - static_cast<int64_t>(r1) * (2 * gamma2);

    // Symmetrically reduce modulo Q to get true remainder in Z_Q!
    delta = delta % static_cast<int64_t>(ml_dsa::Q);
    if (delta > static_cast<int64_t>(ml_dsa::Q) / 2) {
      delta -= ml_dsa::Q;
    } else if (delta < -static_cast<int64_t>(ml_dsa::Q) / 2) {
      delta += ml_dsa::Q;
    }

    uint64_t R = delta + gamma2 - 1;
    uint64_t s = (delta > 0) ? 0 : 1;
    uint64_t aux_bits = R | (s << 18);

    auto normalize = [](int64_t x) {
      int64_t v = x % static_cast<int64_t>(ml_dsa::Q);
      if (v < 0) v += ml_dsa::Q;
      return static_cast<uint64_t>(v);
    };

    auto h_elt = L.konst(F.of_scalar(normalize(h)));
    auto w_prime_approx_elt = L.konst(F.of_scalar(normalize(r)));
    auto w1_elt = L.konst(F.of_scalar(normalize(r1)));
    auto w_prime_1_elt = L.konst(F.of_scalar(normalize(expected)));

    // Bits
    auto hint_aux_bits = L.template vbit<19>(normalize(aux_bits));
    auto w_prime_1_bits = L.template vbit<6>(normalize(expected));

    verify.assert_use_hint_single(h_elt, w_prime_approx_elt, w1_elt,
                                  hint_aux_bits, w_prime_1_elt, w_prime_1_bits);
  }
}

TEST(MLDSA44EvalTest, W1Encode) {
  const Field& F = ml_dsa::Fq;
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  MLDSA44Verify verify(L);

  auto tests = ml_dsa::GetW1EncodeTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    std::array<std::array<EvalLogic::template bitvec<6>, ml_dsa::N>, ml_dsa::K>
        w_prime_1_bits_arr;
    for (size_t k = 0; k < ml_dsa::K; ++k) {
      for (size_t i = 0; i < ml_dsa::N; ++i) {
        w_prime_1_bits_arr[k][i] = L.template vbit<6>(tests[t].in[k][i]);
      }
    }

    std::array<EvalLogic::v8, ml_dsa::K * 192> putative_out;
    for (size_t i = 0; i < tests[t].out.size(); ++i) {
      putative_out[i] = L.vbit8(tests[t].out[i]);
    }
    verify.assert_w1_encode(w_prime_1_bits_arr, putative_out);
  }
}

TEST(MLDSA44EvalTest, AssertValidSignature) {
  const Field& F = ml_dsa::Fq;
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  using v8 = EvalLogic::v8;
  MLDSA44Verify verify(L);

  // Take the first example
  auto tests = ml_dsa::GetMlDsa44Examples();
  for (size_t t = 0; t < tests.size(); ++t) {
    const auto& example = tests[t];

    // 1. Decode Pk and Sig
    ml_dsa::PublicKey ref_pk = ml_dsa::pkDecode(example.pkey);
    auto maybe_ref_sig = ml_dsa::sigDecode(example.sig);
    EXPECT_TRUE(maybe_ref_sig.has_value());
    ml_dsa::Signature ref_sig = maybe_ref_sig.value();

    // 1. Compute Witness
    ml_dsa_44_witness witness_gen;
    witness_gen.compute_witness(example.pkey, example.sig, example.msg,
                                example.ctx);

    // 2. Setup inputs for the circuit
    typename MLDSA44Verify::Pk pk_w = convert_pk(ref_pk, witness_gen, L, F);

    typename MLDSA44Verify::SignatureW sig_w =
        convert_sig(ref_sig, witness_gen, L, F);

    // Generate SampleInBallWitness
    typename MLDSA44Verify::Witness witness =
        convert_witness(witness_gen, L, F);

    std::array<v8, 64> mu;
    convert_array(mu, witness_gen.mu_, L);
    verify.assert_valid_signature_on_mu(pk_w, sig_w, mu, witness);
  }
}

}  // namespace
}  // namespace proofs
