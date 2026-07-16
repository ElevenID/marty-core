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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/logic/memcmp.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_types.h"
#include "circuits/tests/sha3/sha3_circuit.h"

namespace proofs {

// ----------------------------------------------------------------------------
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!
//
// This ML-DSA circuit is an experimental implementation for research purposes.
// It has not been fully vetted and is not recommended for production use cases
// at this time.
//
// ML-DSA is specified in
//
//      FIPS 204
//      Federal Information Processing Standards Publication
//      Module-Lattice-Based Digital
//      Signature Standard
//      https://csrc.nist.gov/pubs/fips/204/final
//
// A public key in the system is a pair (rho, t1).
//
// The value rho is used to derive the pk matrix A \in R_q^{k x l}.
// The matrix T = A.s_1 + s_2 in R_q^k, and t1 is a rounded version of T.
// The hint h \in R_2^k.
//
// These operations are performed outside of the circuit and
// used as inputs for the Verifier.
// rho, t1 = _unpack_pk(pk)
// A_hat = _expand_matrix_from_seed(rho)
// tr = _h(pk, 64)    # 64-byte hash of the public key
// t1 = t1.scale(1 << self.d)
// t1 = t1.to_ntt()
// 1.  (rho, t1) = pkDecode(pk)
// Decode public key bytes.
// rho: 32-byte seed for generating matrix A.
// t1: Vector of 4 polynomials in R_q (k=4).
//     Represents the high bits of A*s + t.

// 2.  (c_tilde, z, h) = sigDecode(sigma)  [ALWAYS PRIVATE]
// Decode signature bytes.
// c_tilde: 32-byte hash commitment (the "challenge" seed).
// z: Vector of 4 polynomials in R_q (l=4). The masked secret vector.
// h: Vector of 4 polynomials in R_q (k=4). The hint vector used to
//    recover high bits.
// 3.  IF h is INVALID (e.g., decoding failed or malformed) THEN
//         RETURN False
//     END IF

// 4.  A_hat = ExpandA(rho)
// Expand the public matrix A from the seed rho.
// A_hat: 4x4 Matrix of polynomials in R_q (k=4, l=4).
// Note: The matrix is generated and stored directly in NTT (Number
// Theoretic Transform) representation.
// ----------------------------------------------------------------------------

template <class LogicCircuit, class Field>
class MLDSA44Verify {
  using v6 = typename LogicCircuit::template bitvec<6>;
  using v7 = typename LogicCircuit::template bitvec<7>;
  using v8 = typename LogicCircuit::v8;
  using v10 = typename LogicCircuit::template bitvec<10>;
  using v16 = typename LogicCircuit::template bitvec<16>;
  using v19 = typename LogicCircuit::template bitvec<19>;
  using v64 = typename LogicCircuit::v64;
  using EltW = typename LogicCircuit::EltW;
  using Elt = typename Field::Elt;
  using BitW = typename LogicCircuit::BitW;
  using BlockWitness = typename Sha3Circuit<LogicCircuit>::BlockWitness;

 public:
  struct RqW {
    std::array<EltW, ml_dsa::N> coeffs;

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < ml_dsa::N; ++i) {
        coeffs[i] = lc.eltw_input();
      }
    }
  };

  struct MatrixAW {
    std::array<std::array<RqW, ml_dsa::L>, ml_dsa::K> mat;

    void input(const LogicCircuit& lc) {
      for (size_t r = 0; r < ml_dsa::K; ++r) {
        for (size_t c = 0; c < ml_dsa::L; ++c) {
          mat[r][c].input(lc);
        }
      }
    }
  };

  struct Pk {
    MatrixAW a_hat;
    std::array<RqW, ml_dsa::K> nttt1;
    std::array<v8, 64> tr;

    void input(const LogicCircuit& lc) {
      a_hat.input(lc);
      for (size_t i = 0; i < ml_dsa::K; ++i) {
        nttt1[i].input(lc);
      }
      for (size_t i = 0; i < 64; ++i) {
        tr[i] = lc.template vinput<8>();
      }
    }
  };

  struct SignatureW {
    std::array<v8, 32> c_tilde;
    std::array<RqW, ml_dsa::L> z;
    // 19 bits per coefficient for z to cover 2 * GAMMA_1 (gamma_1 = 131072,
    // so 262144 range fits in 19 bits max)
    std::array<std::array<v19, ml_dsa::N>, ml_dsa::L> z_bits;
    std::array<RqW, ml_dsa::K> h;

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < 32; ++i) {
        c_tilde[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < ml_dsa::L; ++i) {
        z[i].input(lc);
      }
      for (size_t i = 0; i < ml_dsa::L; ++i) {
        for (size_t j = 0; j < ml_dsa::N; ++j) {
          z_bits[i][j] = lc.template vinput<19>();
        }
      }
      for (size_t i = 0; i < ml_dsa::K; ++i) {
        h[i].input(lc);
      }
    }
  };

  struct SampleInBallWitness {
    BlockWitness shake_bws;
    std::array<v8, ml_dsa::TAU> j_vals;
    std::array<v16, ml_dsa::TAU> j_k_indices;
    std::vector<std::vector<v8>> position_trace;

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < ml_dsa::TAU; ++i) {
        j_vals[i] = lc.template vinput<8>();
        j_k_indices[i] = lc.template vinput<16>();
      }
      shake_bws.input(lc);
      // Note: position_trace is sized by caller.
      if (position_trace.empty()) {
        position_trace.resize(ml_dsa::TAU);
      }
      for (size_t s = 0; s < ml_dsa::TAU; ++s) {
        if (position_trace[s].size() != s + 1) {
          position_trace[s].resize(s + 1);
        }
        for (size_t k = 0; k <= s; ++k) {
          position_trace[s][k] = lc.template vinput<8>();
        }
      }
    }
  };

  class Witness {
   public:
    SampleInBallWitness sample_in_ball_;
    RqW c_;
    RqW w_prime_approx_[ml_dsa::K];
    RqW w1_[ml_dsa::K];
    std::array<std::array<v19, ml_dsa::N>, ml_dsa::K> hint_aux_bits_;
    RqW w_prime_1_[ml_dsa::K];
    std::array<std::array<v6, ml_dsa::N>, ml_dsa::K> w_prime_1_bits_;
    std::array<RqW, ml_dsa::L> nttz_;
    RqW nttc_;
    std::array<v8, ml_dsa::K * 192> w1_tilde_;
    std::vector<BlockWitness> c_prime_tilde_bws_;
    v7 h_sum_bits_;

    void input(const LogicCircuit& lc) {
      sample_in_ball_.input(lc);
      c_.input(lc);
      for (size_t i = 0; i < ml_dsa::K; ++i) {
        w_prime_approx_[i].input(lc);
        w1_[i].input(lc);
        for (size_t j = 0; j < ml_dsa::N; ++j) {
          hint_aux_bits_[i][j] = lc.template vinput<19>();
        }
        w_prime_1_[i].input(lc);
        for (size_t j = 0; j < ml_dsa::N; ++j) {
          w_prime_1_bits_[i][j] = lc.template vinput<6>();
        }
      }
      for (size_t i = 0; i < ml_dsa::L; ++i) {
        nttz_[i].input(lc);
      }
      nttc_.input(lc);
      for (auto& w1 : w1_tilde_) {
        w1 = lc.template vinput<8>();
      }
      for (auto& bw : c_prime_tilde_bws_) {
        bw.input(lc);
      }
      h_sum_bits_ = lc.template vinput<7>();
    }
  };

  void matrix_vector_mul(const MatrixAW& A, const std::array<RqW, ml_dsa::L>& x,
                         std::array<RqW, ml_dsa::K>& y) const {
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t c = 0; c < ml_dsa::N; ++c) {
        y[i].coeffs[c] = lc_.konst(lc_.f_.zero());
      }
      for (size_t j = 0; j < ml_dsa::L; ++j) {
        for (size_t c = 0; c < ml_dsa::N; ++c) {
          y[i].coeffs[c] = lc_.add(
              y[i].coeffs[c], lc_.mul(A.mat[i][j].coeffs[c], x[j].coeffs[c]));
        }
      }
    }
  }

  void scalar_vector_mul(const RqW& c, const std::array<RqW, ml_dsa::K>& x,
                         std::array<RqW, ml_dsa::K>& y) const {
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        y[i].coeffs[k] = lc_.mul(c.coeffs[k], x[i].coeffs[k]);
      }
    }
  }

  void assert_ntt(const RqW& c, const RqW& cprime) const {
    std::vector<EltW> p(c.coeffs.begin(), c.coeffs.end());
    int k = 1;
    int length = ml_dsa::N / 2;
    while (length > 0) {
      for (int start = 0; start < ml_dsa::N; start += 2 * length) {
        auto zeta = lc_.f_.of_scalar_field(ml_dsa::kZetas[k]);
        auto neg_zeta = lc_.f_.negf(zeta);
        k++;
        for (int j = start; j < start + length; ++j) {
          auto t = lc_.axpy(p[j], zeta, p[j + length]);
          p[j + length] = lc_.axpy(p[j], neg_zeta, p[j + length]);
          p[j] = t;
        }
      }
      length /= 2;
    }
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      lc_.assert_eq(p[i], cprime.coeffs[i]);
    }
  }

  void assert_inverse_ntt(const RqW& c, const RqW& cprime) const {
    std::vector<EltW> p(c.coeffs.begin(), c.coeffs.end());
    int k = 256;
    int length = 1;
    while (length < ml_dsa::N) {
      for (int start = 0; start < ml_dsa::N; start += 2 * length) {
        k--;
        auto neg_zeta = lc_.f_.negf(lc_.f_.of_scalar_field(ml_dsa::kZetas[k]));
        for (int j = start; j < start + length; ++j) {
          auto t = p[j];
          p[j] = lc_.add(t, p[j + length]);
          auto diff = lc_.sub(t, p[j + length]);
          p[j + length] = lc_.mul(neg_zeta, diff);
        }
      }
      length *= 2;
    }

    // Multiply by 256^(-1) mod q = 8347681
    auto f = lc_.konst(lc_.f_.of_scalar_field(8347681u));
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      p[i] = lc_.mul(f, p[i]);
      lc_.assert_eq(p[i], cprime.coeffs[i]);
    }
  }

  explicit MLDSA44Verify(const LogicCircuit& lc) : lc_(lc) {}

  // Validates the "UseHint" operation for a single coefficient, ensuring that
  // the high bits `w_prime_1` are correctly derived from the approximate high
  // bits `w_prime_approx` and the hint `h` according to FIPS 204.
  //
  // FIPS UseHint(h, r) Standard Logic:
  // 1. Decompose `r = r1 * 2*gamma2 + r0` where `-gamma2 < r0 <= gamma2`.
  // 2. If `h == 1` and `r0 > 0`, return `(r1 + 1) mod 44`.
  // 3. If `h == 1` and `r0 <= 0`, return `(r1 - 1) mod 44`.
  // 4. If `h == 0`, return `r1`.
  //
  // Our Circuit Optimization:
  // This function uses an optimized algorithm (interval shifting) that offloads
  // the computation of the expected answer `hinted_r1` to the prover and
  // requires ONLY ONE range check.
  //
  // Specifically, this function asserts:
  // 1. Shift Indicator `c` derivation:
  //    - Extracts the 19th bit of `hint_r0_bits_elt` as a sign bit `s`.
  //    - Compute `c = h * (1 - 2*s)`. This maps `h=0 -> c=0`, and `h=1 -> c
  //    \in {-1, 1}`.
  //    - This carefully aligns with the FIPS standard constraints: if the hint
  //    `h` is 1, `c` will tell us whether we are shifting `r1` by +1
  //    (`c=1`, because `r0 > 0`) or by -1 (`c=-1`, because `r0 <= 0`).
  //    If `h = 0`, no shift applies (`c=0`).
  //
  // 2. Decomposition and Range check for `r0`:
  //    - The approximated value `r` decomposes into `r1` and `r0` such that:
  //      `r0 = r - r1 * 2*gamma2`
  //    - If we follow the standard, `r0` must lie in `(-gamma2, gamma2]`.
  //    - Instead of range-checking `r0` over this signed interval, we assert
  //      that `r0_shifted = r0 - c * 2*gamma2 + (gamma2 - 1)` must lie
  //      strictly in `[0, 2*gamma2 - 1]`.
  //    - By adding `(gamma2 - 1)`, we functionally shift the legitimate range
  //    to be strictly non-negative.
  //    - By subtracting `c * 2*gamma2`, we logically enforce the explicit FIPS
  //    boundaries on `r0` depending on `c`:
  //      - If `c = 1` (`r1` shifts +1), then `r0` MUST have been `> 0`.
  //      - If `c = -1` (`r1` shifts -1), then `r0` MUST have been `<= 0`.
  //    - This requires only one range check by reconstructing `r0_shifted` from
  //    the first 18 bits of `hint_r0_bits_elt` and bounds checking `r0_shifted
  //    <= 2*gamma2 - 1`.
  //
  // 3. Modulo check on computed `hinted_r1`:
  //    - Verifies that `hinted_r1` is indeed congruent to the raw (unmoduloed)
  //    shift `r1 + c` meaning `(r1 + c - hinted_r1) \in {0, 44, -44}`.
  //
  // 4. Range check on `hinted_r1` bounds:
  //    - `hinted_r1` is the final answer supplied by the prover.
  //    - It is explicitly reconstructed from boolean bits `r1_bits_elt`
  //    matching bounded `[0, 43]`.
  void assert_use_hint_single(const EltW& h_elt, const EltW& r_elt,
                              const EltW& r1_raw, const v19& hint_r0_bits_elt,
                              const EltW& hinted_r1,
                              const v6& r1_bits_elt) const {
    auto two_gamma2 = lc_.konst(lc_.f_.of_scalar(2 * ml_dsa::GAMMA_2));
    auto shift_val = lc_.konst(lc_.f_.of_scalar(ml_dsa::GAMMA_2 - 1));
    EltW zero = lc_.konst(lc_.f_.zero());

    lc_.assert_is_bit(h_elt);

    // 1. Reconstruct R and extract sign bit s
    EltW r0_shifted =
        lc_.as_scalar(lc_.template slice<0, 18>(hint_r0_bits_elt));

    // Check R <= 2*GAMMA_2 - 1  (18 bits since 2*GAMMA_2 - 1 = 190463 < 2^18)
    auto max_bound = lc_.template vbit<18>(2 * ml_dsa::GAMMA_2 - 1);
    auto is_leq_max = lc_.leq(18, hint_r0_bits_elt.data(), max_bound.data());
    lc_.assert1(is_leq_max);

    // Extract s as the 19th bit
    BitW s_bit = hint_r0_bits_elt[18];

    // Compute c = h * (1 - 2*s) -> If s=1, c = -h; else c = h.
    EltW neg_h = lc_.sub(zero, h_elt);
    EltW c_elt = lc_.mux(s_bit, neg_h, h_elt);

    // In UseHint, delta is exactly r0. There is no +/- 2*gamma2 shifted bounds.
    // delta = R - (gamma2 - 1)
    EltW delta = lc_.sub(r0_shifted, shift_val);

    // Verify r_elt == r1_elt * 2*GAMMA_2 + delta
    EltW term1 = lc_.mul(r1_raw, two_gamma2);
    EltW val = lc_.add(term1, delta);
    lc_.assert_eq(r_elt, val);

    // 3. Verify r1_recon range [0, 43]
    EltW r1_recon = lc_.as_scalar(r1_bits_elt);
    lc_.assert_eq(hinted_r1, r1_recon);
    auto r1_bound = lc_.template vbit<6>(43);
    auto is_w1_valid = lc_.leq(6, r1_bits_elt.data(), r1_bound.data());
    lc_.assert1(is_w1_valid);

    // 4. Verify hinted_r1 == r1_raw - c modulo 44
    EltW diff = lc_.sub(r1_raw, hinted_r1);
    EltW true_shift_diff = lc_.add(diff, c_elt);

    EltW m = lc_.konst(lc_.f_.of_scalar(44));
    EltW diff_minus_44 = lc_.sub(true_shift_diff, m);
    EltW diff_plus_44 = lc_.add(true_shift_diff, m);

    EltW prod1 = lc_.mul(true_shift_diff, diff_minus_44);
    EltW prod2 = lc_.mul(prod1, diff_plus_44);
    lc_.assert0(prod2);
  }

  void assert_use_hint(
      const std::array<RqW, ml_dsa::K>& h,
      const RqW (&w_prime_approx)[ml_dsa::K], const RqW (&w1)[ml_dsa::K],
      const std::array<std::array<v19, ml_dsa::N>, ml_dsa::K>& hint_aux_bits,
      const RqW (&w_prime_1)[ml_dsa::K],
      const std::array<std::array<v6, ml_dsa::N>, ml_dsa::K>& w_prime_1_bits,
      const v7& h_sum_bits) const {
    EltW sum = lc_.konst(lc_.f_.zero());
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        assert_use_hint_single(h[i].coeffs[k], w_prime_approx[i].coeffs[k],
                               w1[i].coeffs[k], hint_aux_bits[i][k],
                               w_prime_1[i].coeffs[k], w_prime_1_bits[i][k]);
        sum = lc_.add(sum, h[i].coeffs[k]);
      }
    }

    auto is_valid_weight = lc_.vleq(h_sum_bits, ml_dsa::OMEGA);
    lc_.assert1(is_valid_weight);

    EltW reconstructed_sum = lc_.as_scalar(h_sum_bits);
    lc_.assert_eq(sum, reconstructed_sum);
  }

  // Verifies that the infinity norm of the polynomial vector `vec` is within
  // the specified `bound`. This function checks that each coefficient `c` of
  // `vec` satisfies `-bound <= c < bound` (i.e., `c \in [-bound, bound - 1]`).
  //
  // The verification is performed using a provided bit-decomposition `vec_bits`
  // for each coefficient. The steps are:
  // 1. Reconstruct a value `r` from `vec_bits` such that `r = sum(bits * 2^k)`.
  //    This `r` represents the shifted coefficient `c + bound`.
  // 2. Assert that `vec[i][j] + bound == r`. This ensures that the
  //    bit-decomposition `vec_bits` corresponds to the coefficient `vec[i][j]`
  //    shifted by `bound`.
  // 3. Assert that `r <= 2 * bound - 1`. Since `r` is non-negative (from bits),
  //    this enforces `0 <= c + bound <= 2 * bound - 1`, which simplifies to
  //    `-bound <= c <= bound - 1`.
  template <size_t SIZE, size_t BIT_WIDTH>
  void assert_infty_norm(
      const std::array<RqW, SIZE>& vec,
      const std::array<
          std::array<typename LogicCircuit::template bitvec<BIT_WIDTH>,
                     ml_dsa::N>,
          SIZE>& vec_bits,
      uint64_t bound) const {
    const Memcmp<LogicCircuit> CMP(lc_);

    for (size_t i = 0; i < SIZE; ++i) {
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        // 1. Reconstruct the shifted value from bit witnesses
        EltW r = lc_.as_scalar(vec_bits[i][j]);

        // 2. Check that the reconstructed (shifted) value matches the
        // original value shifted by bound.
        //    vec[i].coeffs[j] + bound == reconstructed.
        EltW shifted_original =
            lc_.add(vec[i].coeffs[j], lc_.konst(lc_.f_.of_scalar(bound)));
        lc_.assert_eq(shifted_original, r);

        // 3. Verify inequality constraint (reconstructed < 2*bound + 1) ->
        // reconstructed <= 2*bound.The shifted value must fall in [1, 2*bound -
        // 1]. Hence, vec_bits[i][j] <= 2*bound - 1.
        auto is_leq =
            lc_.leq(BIT_WIDTH, vec_bits[i][j].data(),
                    lc_.template vbit<BIT_WIDTH>(2 * bound - 1).data());
        lc_.assert1(is_leq);
      }
    }
  }

  // Verifies the `w1Encode` operation, which serializes the polynomial vector
  // `w_prime_1` into a byte array. This byte array is subsequently used to
  // hash (along with `mu`) and validate the signature challenge `c_tilde`.
  //
  // The encoding constraints are structured and validated as follows:
  // 1. **Bit Extraction**:
  //    - Each coefficient in `w_prime_1` is bounded in `[0, 43]` and is
  //      fully represented using exactly 6 bits.
  //    - The method iterates through all `K` polynomials and all `N` (256)
  //      coefficients, extracting the lowest 6 bits of each coefficient.
  //    - These bits are concatenated into a flat array of `K * N * 6` bits.
  // 2. **Byte Packing (SimpleBitPack)**:
  //    - The bit array is partitioned into 8-bit subsets to form bytes.
  //    - As required by FIPS 204 Algorithm 18 (`SimpleBitPack`), bits are
  //      packed in little-endian order, meaning the first bit of each subset
  //      is bound to the Least Significant Bit (LSB) of the output byte.
  // 3. **Padding Constraints**:
  //    - The algorithm enforces that if the total bit count is not perfectly
  //      divisible by 8, any residual bits making up the final byte are
  //      constrained to zero-wires (`lc_.bit(0)`).
  void assert_w1_encode(
      const std::array<std::array<v6, ml_dsa::N>, ml_dsa::K>& w_prime_1_bits,
      const std::array<v8, ml_dsa::K * 192>& putative_w1_tilde) const {
    // Each coefficient in w_prime_1 used 6 bits.
    // We construct the byte representation directly from these bits.
    // bitlen = 6.
    size_t bitlen = 6;
    size_t total_bytes = ml_dsa::K * 192;

    // Gather all 6*256*K bits into a big vector, then split.
    std::vector<BitW> all_bits;
    all_bits.reserve(ml_dsa::K * ml_dsa::N * bitlen);

    for (size_t k = 0; k < ml_dsa::K; ++k) {
      for (size_t i = 0; i < ml_dsa::N; ++i) {
        for (size_t b = 0; b < bitlen; ++b) {
          all_bits.push_back(w_prime_1_bits[k][i][b]);
        }
      }
    }

    for (size_t i = 0; i < total_bytes; ++i) {
      // FIPS 204 Algorithm 18 SimpleBitPack:
      // z[byte_idx] |= (1 << bit_idx) where bit_idx is pos % 8.
      v8 byte_val;
      for (size_t b = 0; b < 8; ++b) {
        if (i * 8 + b < all_bits.size()) {
          byte_val[b] = all_bits[i * 8 + b];
        } else {
          byte_val[b] = lc_.bit(0);
        }
      }
      lc_.vassert_eq(putative_w1_tilde[i], byte_val);
    }
  }

  // Verifies the "SampleInBall" operation, which generates a sparse polynomial
  // `c` with coefficients in {-1, 0, 1} and exactly `TAU` non-zero
  // coefficients. This corresponds to Algorithm 29 in FIPS 204.
  //
  // 4: (ctx, s) <- H.Squeeze(ctx, 8)
  // 5: h <- BytesToBits(s)    # 64 bits for -1,1
  // 6: for i from 256 - TAU to 255 do
  // 7:   (ctx, j) <- H.Squeeze(ctx, 1)
  // 8:   while j > i do       #  rejection sampling in {0, … , i}
  // 9:     (ctx, j) <- H.Squeeze(ctx, 1)
  // 10:  end while            # j is a pseudorandom byte that is ≤ i
  // 11:  c_i <- c_j
  // 12:  c_j <- (-1)^h[i + TAU - 256]
  // 13: end for
  //
  // The function validates the generation of `c` from the seed `rho`:
  // 1. **SHAKE256**: Computes 272b of SHAKE256 output `out` from `rho`.
  // 2. **Rejection Sampling Verification**: The algorithm picks `TAU` indices
  //    `j` using rejection sampling from `out` (starting at byte 8). For each
  //    step `s` (target index `i = 256 - TAU + s`):
  //    - The witness provides the index `k_idx` in `out` where a valid sample
  //    `j` was found.
  //    - **Validation**:
  //      - `out[k_idx] == j`: verifies the witness `j` matches the SHAKE
  //      output.
  //      - `j <= i`: verifies the sample is within the valid range for the
  //      swap.
  //      - For all `k` such that `prev_k_index <= k < k_idx`: verifies `out[k]
  //      > i`.
  //        This ensures that all skipped bytes were legitimately rejected
  //        because they were out of range.
  //
  // 3. **Shuffle Trace Verification (Parallel)**:
  //    - Instead of sequentially updating the polynomial `c`, we verify a
  //      "trace" of the shuffle positions witnessed by
  //      `witness.position_trace`.
  //    - For each step `s`, we verify that `position_trace[s]` is correctly
  //      derived from `position_trace[s-1]` by swapping the element at `j` with
  //      `i`.
  //    - This allows all `s` steps to be verified in parallel, reducing the
  //      circuit depth from O(TAU) to O(1) (relative to the shuffle steps).
  //
  // 4. **Final Polynomial Construction**:
  //    - Constructs the expected polynomial `c` from the final positions in
  //      `position_trace[TAU-1]`.
  //    - For each coefficient index `k`, we sum the contributions from all `s`
  //      (where `final_pos[s] == k`).
  //    - `c[k] = sum_{s} (final_pos[s] == k ? (-1)^sign_s : 0)`.
  //    - Asserts that `cprime` matches this constructed `c`.
  void assert_sample_in_ball(const std::array<v8, 32>& rho, const RqW& cprime,
                             const SampleInBallWitness& witness) const {
    // 1. Compute SHAKE256 on rho
    Sha3Circuit<LogicCircuit> sha3(lc_);
    std::vector<v8> out;
    std::vector<v8> rho_vec(rho.begin(), rho.end());
    size_t out_bytes = 136;
    std::vector<BlockWitness> bws;
    bws.push_back(witness.shake_bws);
    sha3.assert_shake256(rho_vec, out_bytes, out, bws);

    // 2. Verification of Rejection Sampling (j values)
    v16 prev_k_index = lc_.template vbit<16>(8);  // out_idx starts at 8

    for (size_t s = 0; s < ml_dsa::TAU; ++s) {
      size_t i = 256 - ml_dsa::TAU + s;
      const v8& j = witness.j_vals[s];
      const v16& k_idx = witness.j_k_indices[s];

      // Enforce that the k_idx witness is within bounds.
      auto is_in_bounds = lc_.vleq(k_idx, out.size() - 1);
      lc_.assert1(is_in_bounds);

      // Enforce the out_idx is increasing
      auto is_increasing = lc_.vleq(prev_k_index, k_idx);
      lc_.assert1(is_increasing);

      // Verify j <= i
      v16 j_ext = lc_.template vbit<16>(0);
      for (size_t k = 0; k < 8; ++k) j_ext[k] = j[k];

      v16 i_vec = lc_.template vbit<16>(i);
      auto j_valid = lc_.vleq(j_ext, i_vec);
      lc_.assert1(j_valid);

      // Verify out[k_idx] == j and skipped values > i
      for (size_t k = 0; k < out.size(); ++k) {
        v16 curr_k = lc_.template vbit<16>(k);
        auto is_target = lc_.veq(curr_k, k_idx);

        // If k == k_idx, then out[k] == j
        auto match_val = lc_.veq(out[k], j);
        lc_.assert_implies(is_target, match_val);

        // If prev_k_index <= k < k_idx, then out[k] > i
        auto gt_prev = lc_.vleq(prev_k_index, curr_k);
        auto lt_target = lc_.vlt(curr_k, k_idx);
        auto in_range = lc_.land(gt_prev, lt_target);

        v16 out_k_ext = lc_.template vbit<16>(0);
        for (size_t b = 0; b < 8; ++b) out_k_ext[b] = out[k][b];

        auto rejected_val = lc_.vlt(i_vec, out_k_ext);  // out[k] > i
        lc_.assert_implies(in_range, rejected_val);
      }
      prev_k_index = lc_.vadd(k_idx, 1);
    }

    // 3. Verify Shuffle Trace (Parallel)
    // Step s=0
    lc_.vassert_eq(witness.position_trace[0][0], witness.j_vals[0]);

    for (size_t s = 1; s < ml_dsa::TAU; ++s) {
      size_t i = 256 - ml_dsa::TAU + s;
      const v8& j = witness.j_vals[s];

      const auto& prev_pos = witness.position_trace[s - 1];
      const auto& curr_pos = witness.position_trace[s];

      // Assert curr_pos[s] == j
      lc_.vassert_eq(curr_pos[s], j);

      // Parallel checks for k < s
      for (size_t k = 0; k < s; ++k) {
        const auto& p = prev_pos[k];
        auto is_j = lc_.veq(p, j);
        // If p == j, update to i, else stay p
        // vmux logic:
        v8 i_v = lc_.template vbit<8>(i);
        v8 target;
        for (size_t b = 0; b < 8; ++b) {
          target[b] = lc_.mux(is_j, i_v[b], p[b]);
        }
        lc_.vassert_eq(curr_pos[k], target);
      }
    }

    // 4. Verify cprime against final trace
    const auto& final_pos = witness.position_trace[ml_dsa::TAU - 1];
    EltW one = lc_.konst(lc_.f_.one());
    EltW mone = lc_.konst(lc_.f_.mone());
    EltW zero = lc_.konst(lc_.f_.zero());

    // Pre-calculate expected values for each position in the trace
    std::vector<EltW> trace_vals(ml_dsa::TAU);
    for (size_t s = 0; s < ml_dsa::TAU; ++s) {
      size_t bit_idx = s;
      size_t byte_idx = bit_idx / 8;
      size_t bit_shift = bit_idx % 8;
      auto sign_bit = out[byte_idx][bit_shift];
      trace_vals[s] = lc_.mux(sign_bit, mone, one);
    }

    // Full Construction Check:
    // c[k] = sum_{s} (final_pos[s] == k ? trace_vals[s] : 0)
    for (size_t k = 0; k < ml_dsa::N; ++k) {
      v8 k_v = lc_.template vbit<8>(k);

      // We sum up contributions from all s.
      // Since final_pos distinct, at most one s contributes.
      // We can use a linear sum or tree sum.
      // logic.h add(i0, i1, func) checks range.
      // We can use lc_.add(0, TAU, ...)
      EltW val_k = lc_.add(0, ml_dsa::TAU, [&](size_t s) {
        auto is_match = lc_.veq(final_pos[s], k_v);
        return lc_.mux(is_match, trace_vals[s], zero);
      });

      lc_.assert_eq(cprime.coeffs[k], val_k);
    }
  }

  std::vector<v8> prepare_mu_input(const std::array<v8, 64>& tr, const v8* msg,
                                   size_t len) const {
    // 2. Prepare the full input: tr || msg || padding.
    // Maximum size: 64 + 650 = 714 bytes.
    // Block size: 136 bytes.

    std::vector<v8> input_bytes;
    input_bytes.reserve(64 + len + 2);  // +2 for padding
    for (size_t i = 0; i < 64; ++i) input_bytes.push_back(tr[i]);
    for (size_t i = 0; i < len; ++i) input_bytes.push_back(msg[i]);

    // Padding for SHAKE256: append 0x1F, then … then 0x80 at end of block.
    // Formula: Pad with 10*1.
    // First byte 0x1F (0001 1111) handles "4 bits domain + 1 bit pad start".
    auto pad1 = lc_.template vbit<8>(0x1F);
    input_bytes.push_back(pad1);

    // We must pad with zeros until we reach block boundary - 1.
    size_t rate = 136;
    size_t current_len = input_bytes.size();
    size_t zero_pad_len = rate - (current_len % rate);
    if (zero_pad_len == 0) zero_pad_len = rate;

    // We append (zero_pad_len - 1) zero bytes.
    auto zero = lc_.template vbit<8>(0);
    for (size_t i = 0; i < zero_pad_len - 1; ++i) {
      input_bytes.push_back(zero);
    }

    // Last byte is 0x80.
    auto pad2 = lc_.template vbit<8>(0x80);
    input_bytes.push_back(pad2);

    // Now input_bytes size should be multiple of rate.
    check(input_bytes.size() % rate == 0, "Padding failed");
    return input_bytes;
  }
  void assert_mu(const std::array<v8, 64>& tr, const v8* msg, size_t len,
                 const std::vector<BlockWitness>& mu_bws,
                 const std::array<v8, 64>& mu) const {
    Sha3Circuit<LogicCircuit> sha3(lc_);
    using v64 = typename LogicCircuit::template bitvec<64>;
    v64 A[5][5];
    for (int x = 0; x < 5; ++x) {
      for (int y = 0; y < 5; ++y) {
        A[x][y] = lc_.template vbit<64>(0);
      }
    }

    std::vector<v8> input_bytes = prepare_mu_input(tr, msg, len);
    size_t rate = 136;
    size_t num_blocks = input_bytes.size() / rate;

    // Absorb
    size_t input_idx = 0;
    size_t bw_idx = 0;

    for (size_t b_idx = 0; b_idx < num_blocks; ++b_idx) {
      // XOR block into state
      size_t x = 0, y = 0;
      for (size_t i = 0; i < rate; i += 8) {
        v64 a;
        for (size_t b = 0; b < 8; ++b) {
          // Reconstruct v64 from 8 v8s (Little Endian)
          for (size_t j = 0; j < 8; ++j) {
            if (i + b < rate) {
              a[b * 8 + j] = input_bytes[input_idx + i + b][j];
            }
          }
        }
        A[x][y] = lc_.vxor(A[x][y], a);
        ++x;
        if (x == 5) {
          ++y;
          x = 0;
        }
      }
      input_idx += rate;

      // Permute
      check(bw_idx < mu_bws.size(), "Not enough BlockWitnesses for mu");
      sha3.keccak_f_1600(A, mu_bws[bw_idx++]);
    }

    // Squeeze 64 bytes
    std::vector<v8> squeezed(64);
    size_t x = 0, y = 0;
    for (size_t i = 0; i < 64; i += 8) {
      for (size_t b = 0; b < 8; ++b) {
        for (size_t j = 0; j < 8; ++j) {
          squeezed[i + b][j] = A[x][y][b * 8 + j];
        }
      }
      ++x;
      if (x == 5) {
        ++y;
        x = 0;
      }
    }

    // Assert match with witness.mu_
    for (size_t i = 0; i < 64; ++i) {
      for (size_t b = 0; b < 8; ++b) {
        lc_.assert_eq(squeezed[i][b], mu[i][b]);
      }
    }
  }

  void assert_w_prime_approx(const Pk& pk, const SignatureW& sig,
                             const Witness& w) const {
    for (size_t i = 0; i < ml_dsa::L; ++i) {
      assert_ntt(sig.z[i], w.nttz_[i]);
    }
    assert_ntt(w.c_, w.nttc_);

    std::array<RqW, ml_dsa::K> Az;
    std::array<RqW, ml_dsa::K> ct1;
    // Az = A_hat * nttz
    matrix_vector_mul(pk.a_hat, w.nttz_, Az);
    // ct1 = nttc * nttt1
    scalar_vector_mul(w.nttc_, pk.nttt1, ct1);

    for (size_t i = 0; i < ml_dsa::K; ++i) {
      RqW diff;
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        diff.coeffs[k] = lc_.sub(Az[i].coeffs[k], ct1[i].coeffs[k]);
      }
      assert_inverse_ntt(diff, w.w_prime_approx_[i]);
    }
  }

  void assert_ctilde(const std::array<v8, 64>& mu,
                     const std::array<v8, ml_dsa::K * 192>& w_prime_1_bytes,
                     const std::vector<BlockWitness>& c_prime_tilde_bws,
                     const std::array<v8, 32>& c_tilde) const {
    Sha3Circuit<LogicCircuit> sha3(lc_);

    // Prepare input: mu || w_prime_1_bytes
    // 192 * 4 + 64 = 832 bytes --> requires 7 blocks of shake.
    std::vector<v8> input_bytes;
    input_bytes.insert(input_bytes.end(), mu.begin(), mu.end());
    input_bytes.insert(input_bytes.end(), w_prime_1_bytes.begin(),
                       w_prime_1_bytes.end());

    std::vector<v8> squeezed(32);

    sha3.assert_shake256(input_bytes, 32, squeezed, c_prime_tilde_bws);

    // Assert match with c_tilde (from signature)
    for (size_t i = 0; i < 32; ++i) {
      lc_.vassert_eq(squeezed[i], c_tilde[i]);
    }
  }

  // This method assumes that the 64b mu is verified externally.
  void assert_valid_signature_on_mu(const Pk& pk, const SignatureW& sig,
                                    const std::array<v8, 64>& mu,
                                    const Witness& w) const {
    // 7.  c = SampleInBall(c_tilde)
    // Generate the challenge c from the commitment c_tilde.
    // c: R_q with small coefficients (weights +/- 1).
    assert_sample_in_ball(sig.c_tilde, w.c_, w.sample_in_ball_);

    // 8. Compute w'_Approx in the NTT domain.
    // w_prime_approx = InverseNTT( A_hat o NTT(z) - NTT(c) o NTT(t1 * 2^d) )
    // w_prime_approx: Vector of 4 polynomials in R_q (k=4).
    assert_w_prime_approx(pk, sig, w);

    // 9.  w_prime_1 = UseHint(h, w_prime_approx)
    //     Use hint h to reconstruct the exact high bits w1 \in R_q^K.
    assert_use_hint(sig.h, w.w_prime_approx_, w.w1_, w.hint_aux_bits_,
                    w.w_prime_1_, w.w_prime_1_bits_, w.h_sum_bits_);

    assert_w1_encode(w.w_prime_1_bits_, w.w1_tilde_);

    // 11. Verification Check 1: ||z|| < (gamma1 - beta)
    assert_infty_norm<ml_dsa::L, 19>(sig.z, sig.z_bits,
                                     ml_dsa::GAMMA_1 - ml_dsa::BETA);

    // 12. Verification Check 2: c_prime = H(mu || w1Encode(w_prime_1), 32)
    assert_ctilde(mu, w.w1_tilde_, w.c_prime_tilde_bws_, sig.c_tilde);
  }

 private:
  const LogicCircuit& lc_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_H_
