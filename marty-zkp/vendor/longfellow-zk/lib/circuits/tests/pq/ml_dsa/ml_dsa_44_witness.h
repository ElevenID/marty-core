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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_WITNESS_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "algebra/fp24.h"
#include "arrays/dense.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_types.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"
#include "circuits/tests/sha3/sha3_witness.h"

namespace proofs {

class ml_dsa_44_witness {
 public:
  std::array<uint8_t, 64> tr_;
  std::array<uint8_t, ml_dsa::C_TILDE_BYTES> c_tilde_;
  std::array<uint8_t, 64> mu_;
  std::array<uint8_t, ml_dsa::K * 192> w1_tilde_;
  std::vector<Sha3Witness::BlockWitness> mu_bws_;
  std::array<uint8_t, ml_dsa::C_TILDE_BYTES> c_prime_tilde_;
  std::vector<Sha3Witness::BlockWitness> c_prime_tilde_bws_;
  std::array<std::array<uint64_t, ml_dsa::N>, ml_dsa::L> z_bits_;
  uint64_t h_sum_bits_;

  Sha3Witness::BlockWitness shake_bws_;

  std::array<uint8_t, ml_dsa::TAU> j_vals_;
  std::array<uint16_t, ml_dsa::TAU> j_k_indices_;
  std::array<std::array<uint8_t, ml_dsa::TAU>, ml_dsa::TAU> position_trace_{};
  ml_dsa::Rq c_coeffs_;  // Polynomial c in domain

  static int64_t SymmetricReduce(int64_t delta) {
    delta = delta % static_cast<int64_t>(ml_dsa::Q);
    if (delta > static_cast<int64_t>(ml_dsa::Q) / 2) {
      delta -= ml_dsa::Q;
    }
    return delta;
  }

  // Derived NTT values
  ml_dsa::RqL nttz_;
  ml_dsa::Rq nttc_;  // Single poly
  ml_dsa::RqK nttt1_;
  ml_dsa::RqK w_prime_approx_;
  std::array<std::array<int32_t, ml_dsa::N>, ml_dsa::K> w1_;
  std::array<std::array<uint64_t, ml_dsa::N>, ml_dsa::K> hint_aux_bits_;
  std::array<std::array<int32_t, ml_dsa::N>, ml_dsa::K> w_prime_1_;
  std::array<std::array<uint64_t, ml_dsa::N>, ml_dsa::K> w_prime_1_bits_;

  // Public inputs or derived values
  std::array<uint8_t, 32> rho_;
  ml_dsa::RqK t1_;

  const Fp24& f_ = ml_dsa::Fq;

  ml_dsa::PublicKey ref_pk_;
  ml_dsa::Signature ref_sig_;
  std::vector<uint8_t> msg_;

  ml_dsa::Rq eval_ntt(const ml_dsa::Rq& p_in) const {
    ml_dsa::Rq p = p_in;
    int k = 1;
    int length = ml_dsa::N / 2;
    while (length > 0) {
      for (int start = 0; start < ml_dsa::N; start += 2 * length) {
        auto zeta = f_.of_scalar(ml_dsa::kZetas[k]);
        k++;
        for (int j = start; j < start + length; ++j) {
          auto t = zeta;
          f_.mul(t, p[j + length]);  // t = zeta * p[j+len]
          p[j + length] = p[j];
          f_.sub(p[j + length], t);  // p[j+len] = p[j] - t
          f_.add(p[j], t);           // p[j] = p[j] + t
        }
      }
      length /= 2;
    }
    return p;
  }

  ml_dsa::Rq eval_inverse_ntt(const ml_dsa::Rq& p_in) const {
    ml_dsa::Rq p = p_in;
    int k = 256;
    int length = 1;
    while (length < ml_dsa::N) {
      for (int start = 0; start < ml_dsa::N; start += 2 * length) {
        k--;
        auto neg_zeta = f_.of_scalar(ml_dsa::kZetas[k]);
        f_.neg(neg_zeta);  // Revert to negative zeta
        for (int j = start; j < start + length; ++j) {
          auto t = p[j];
          f_.add(p[j], p[j + length]);  // p[j] = p[j] + p[j+len]
          f_.sub(t,
                 p[j + length]);  // t = p[j] - p[j+len] (using original p[j])
          f_.mul(t, neg_zeta);
          p[j + length] = t;
        }
      }
      length *= 2;
    }
    auto inv_256 = f_.of_scalar_field(8347681u);  // 256^-1 mod q
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      f_.mul(p[i], inv_256);
    }
    return p;
  }

  template <typename Field>
  void fill_pk(DenseFiller<Field>& filler, const Field& f) const {
    // 1. Pk
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t j = 0; j < ml_dsa::L; ++j) {
        for (size_t k = 0; k < ml_dsa::N; ++k) {
          filler.push_back(f.of_scalar(ref_pk_.a_hat[i][j][k]));
        }
      }
    }
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        filler.push_back(f.of_scalar(nttt1_[i][k]));
      }
    }
    for (size_t i = 0; i < 64; ++i) {
      filler.push_back(tr_[i], 8, f);
    }
  }

  template <typename Field>
  void fill_witness(DenseFiller<Field>& filler, const Field& f) const {
    fill_pk(filler, f);

    // 2. Sig
    for (size_t i = 0; i < 32; ++i) {
      filler.push_back(c_tilde_[i], 8, f);
    }
    for (size_t i = 0; i < ml_dsa::L; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        filler.push_back(f.of_scalar(ref_sig_.z[i][k]));
      }
    }
    for (size_t i = 0; i < ml_dsa::L; ++i) {
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        filler.push_back(z_bits_[i][j], 19, f);
      }
    }
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        filler.push_back(ref_sig_.h[i][k] ? f.one() : f.zero());
      }
    }

    // 3. Witness
    for (size_t i = 0; i < ml_dsa::TAU; ++i) {
      filler.push_back(j_vals_[i], 8, f);
      filler.push_back(j_k_indices_[i], 16, f);
    }

    Sha3Witness::fill_witness(filler, shake_bws_, f);

    for (size_t s = 0; s < ml_dsa::TAU; ++s) {
      for (size_t k = 0; k <= s; ++k) {
        filler.push_back(position_trace_[s][k], 8, f);
      }
    }

    for (size_t k = 0; k < ml_dsa::N; ++k)
      filler.push_back(f.of_scalar(c_coeffs_[k]));

    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k)
        filler.push_back(f.of_scalar(w_prime_approx_[i][k]));
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        int32_t val = w1_[i][k];
        if (val < 0) val += ml_dsa::Q;
        filler.push_back(f.of_scalar(val));
      }
      for (size_t j = 0; j < ml_dsa::N; ++j)
        filler.push_back(hint_aux_bits_[i][j], 19, f);

      for (size_t k = 0; k < ml_dsa::N; ++k)
        filler.push_back(f.of_scalar(w_prime_1_[i][k]));
      for (size_t j = 0; j < ml_dsa::N; ++j)
        filler.push_back(w_prime_1_bits_[i][j], 6, f);
    }

    for (size_t i = 0; i < ml_dsa::L; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k)
        filler.push_back(f.of_scalar(nttz_[i][k]));
    }
    for (size_t k = 0; k < ml_dsa::N; ++k)
      filler.push_back(f.of_scalar(nttc_[k]));

    for (size_t i = 0; i < w1_tilde_.size(); ++i)
      filler.push_back(w1_tilde_[i], 8, f);

    for (size_t i = 0; i < 7; ++i) {
      Sha3Witness::fill_witness(filler, c_prime_tilde_bws_[i], f);
    }
    filler.push_back(h_sum_bits_, 7, f);
  }

  bool compute_witness(const std::vector<uint8_t>& pk,
                       const std::vector<uint8_t>& sig,
                       const std::vector<uint8_t>& msg,
                       const std::vector<uint8_t>& ctx) {
    // 1. Decode Pk
    auto ref_pk = ml_dsa::pkDecode(pk);
    ref_pk_ = ref_pk;
    std::copy(pk.begin(), pk.begin() + 32, rho_.begin());
    std::copy(ref_pk.tr.begin(), ref_pk.tr.end(), tr_.begin());

    for (size_t i = 0; i < ml_dsa::K; ++i) {
      t1_[i] = ref_pk.t1[i];  // Copy Rq directly
    }

    // 2. Decode Sig
    auto maybe_ref_sig = ml_dsa::sigDecode(sig);
    if (!maybe_ref_sig.has_value()) return false;
    auto ref_sig = maybe_ref_sig.value();
    std::copy(ref_sig.c_tilde.begin(), ref_sig.c_tilde.end(), c_tilde_.begin());
    ref_sig_ = ref_sig;
    msg_ = msg;

    // Z and H handling
    uint64_t h_sum = 0;
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        if (ref_sig.h[i][k]) h_sum++;
      }
    }
    h_sum_bits_ = h_sum;

    for (size_t i = 0; i < ml_dsa::L; ++i) {
      ml_dsa::Rq z_poly = ref_sig.z[i];

      for (size_t j = 0; j < ml_dsa::N; ++j) {
        // Shift z to be positive in [0, 2*(GAMMA1 - BETA)] range for
        // interaction with assert_infty_norm. We want to check ||z||_oo <
        // GAMMA1 - BETA. The check in the circuit expects the witness bits to
        // represent z + (GAMMA1 - BETA). Since z is in [-(Q-1)/2, (Q-1)/2]
        // (conceptually) but stored as [0, Q), we first normalize it to signed
        // int32, then shift.

        int32_t val =
            static_cast<int32_t>(f_.from_montgomery(z_poly[j]).limb_[0]);
        if (val > (ml_dsa::Q / 2)) {
          val -= ml_dsa::Q;
        }

        // val is now in range roughly [-GAMMA1, GAMMA1] if valid.
        // We compute shifted = val + (GAMMA1 - BETA).
        // The bound is GAMMA1 - BETA.
        // If |val| < bound, then -bound < val < bound
        // => 0 < val + bound < 2*bound.
        // So shifted value should be in [0, 2*bound].
        // Actually [1, 2*bound-1] strictly if we want strict <.
        // The circuit uses 19 bits.
        int32_t bound = ml_dsa::GAMMA_1 - ml_dsa::BETA;
        int32_t shifted = val + bound;

        // We store it as 64-bit primarily to match the vector type, but it fits
        // in 19 bits.
        z_bits_[i][j] = static_cast<uint64_t>(shifted);
      }
      nttz_[i] = eval_ntt(z_poly);
    }

    // 3. SampleInBall logic
    std::vector<uint8_t> shake_input(c_tilde_.begin(),
                                     c_tilde_.end());  // 32 bytes
    c_coeffs_ = ml_dsa::SampleInBall(c_tilde_);

    // Flattened c for NTT
    nttc_ = eval_ntt(c_coeffs_);

    // witness logic for SampleInBall (SHAKE blocks)
    std::vector<Sha3Witness::BlockWitness> temp_bws;
    Sha3Witness::compute_witness_shake256(shake_input, 136, temp_bws);
    shake_bws_ = temp_bws[0];

    // Manual rejecting sampling witness
    std::array<uint8_t, 136> hash_out;
    ml_dsa::H(shake_input, hash_out);

    int count = 0;
    size_t out_idx = 8;
    for (int i = 256 - ml_dsa::TAU; i < 256; ++i) {
      uint8_t j;
      do {
        j = hash_out[out_idx++];
      } while (j > i);
      j_vals_[count] = j;
      j_k_indices_[count] = out_idx - 1;
      count++;
    }

    // Compute position trace
    std::vector<uint8_t> current_pos;
    current_pos.reserve(ml_dsa::TAU);

    for (size_t s = 0; s < ml_dsa::TAU; ++s) {
      uint8_t j = j_vals_[s];
      uint8_t i = 256 - ml_dsa::TAU + s;

      // If j is occupied, move it to i
      for (auto& p : current_pos) {
        if (p == j) {
          p = i;
          break;  // Should only be one match if logic is correct
        }
      }
      // New coefficient is at j
      current_pos.push_back(j);
      std::copy(current_pos.begin(), current_pos.end(),
                position_trace_[s].begin());
    }

    // nttt1
    auto& f_ = ml_dsa::Fq;
    auto scale_factor = f_.of_scalar(1 << 13);
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      ml_dsa::Rq t1_scaled = ref_pk.t1[i];
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        f_.mul(t1_scaled[j], scale_factor);  // in-place
      }
      nttt1_[i] = eval_ntt(t1_scaled);
    }

    // w_prime_approx
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      ml_dsa::Rq diff;
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        auto az = f_.zero();
        // Az = sum(A[i][j] * z[j])
        for (size_t j = 0; j < ml_dsa::L; ++j) {
          auto term = ref_pk.a_hat[i][j][k];
          f_.mul(term, nttz_[j][k]);  // in-place term *= nttz
          f_.add(az, term);           // in-place az += term
        }
        auto ct1 = nttc_[k];
        f_.mul(ct1, nttt1_[i][k]);  // in-place ct1 *= nttt1

        diff[k] = az;
        f_.sub(diff[k], ct1);  // in-place diff[k] -= ct1
      }

      w_prime_approx_[i] = eval_inverse_ntt(diff);
    }

    // 6. Compute Decompose and UseHint witnesses

    // Using string conversion to handle field elements safely
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        // Elt to int32 conversion
        auto n = f_.from_montgomery(w_prime_approx_[i][k]).limb_[0];
        int32_t val = static_cast<int32_t>(n);

        auto [r1, r0] = ml_dsa::Decompose(val);

        bool h_bit = ref_sig.h[i][k];
        w_prime_1_[i][k] = ml_dsa::UseHint(h_bit, val);

        // Calculate unreduced w1 based on hint
        int32_t w1_raw = r1;
        if (h_bit && r0 > 0)
          w1_raw = r1 + 1;
        else if (h_bit && r0 <= 0)
          w1_raw = r1 - 1;

        w1_[i][k] = r1;

        // Populate bit witnesses with normalization logic
        auto normalize = [&](int64_t x) {
          int64_t v = x % static_cast<int64_t>(ml_dsa::Q);
          if (v < 0) v += ml_dsa::Q;
          return static_cast<uint64_t>(v);
        };

        // 18-bit Range Check interval shifting logic
        int64_t gamma2 = static_cast<int64_t>(ml_dsa::GAMMA_2);
        int64_t delta =
            static_cast<int64_t>(val) - static_cast<int64_t>(r1) * (2 * gamma2);

        // Symmetrically reduce modulo Q to get true remainder in Z_Q
        delta = SymmetricReduce(delta);

        uint64_t R = delta + gamma2 - 1;
        uint64_t s = (delta > 0) ? 0 : 1;

        uint64_t aux_bits = R | (s << 18);
        hint_aux_bits_[i][k] = normalize(aux_bits);

        w_prime_1_bits_[i][k] = normalize(w_prime_1_[i][k]);
      }
    }

    // 7. Compute w1Encode (needed for mu)
    std::array<ml_dsa::Rq, ml_dsa::K> w1_polys;
    for (size_t i = 0; i < ml_dsa::K; ++i) {
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        w1_polys[i][j] = f_.of_scalar(w_prime_1_[i][j]);
      }
    }
    w1_tilde_ = ml_dsa::w1Encode(w1_polys);

    // 8. Compute mu = H(tr || M', 64)
    // Concat tr and msg_prime
    std::vector<uint8_t> mu_input(tr_.begin(), tr_.end());
    mu_input.push_back(0);  // domain separator
    mu_input.push_back(static_cast<uint8_t>(ctx.size()));
    mu_input.insert(mu_input.end(), ctx.begin(), ctx.end());
    mu_input.insert(mu_input.end(), msg.begin(), msg.end());

    std::array<uint8_t, 64> mu_out;
    ml_dsa::H(mu_input, mu_out);
    std::copy(mu_out.begin(), mu_out.end(), mu_.begin());
    Sha3Witness::compute_witness_shake256(mu_input, 64, mu_bws_);

    // 9. c_prime_tilde = H(mu || w1_tilde, 32)
    std::vector<uint8_t> c_prime_tilde_input(mu_out.begin(), mu_out.end());
    c_prime_tilde_input.insert(c_prime_tilde_input.end(), w1_tilde_.begin(),
                               w1_tilde_.end());

    std::array<uint8_t, 32> c_prime_tilde_vec;
    ml_dsa::H(c_prime_tilde_input, c_prime_tilde_vec);
    std::copy(c_prime_tilde_vec.begin(), c_prime_tilde_vec.end(),
              c_prime_tilde_.begin());

    Sha3Witness::compute_witness_shake256(c_prime_tilde_input, 32,
                                          c_prime_tilde_bws_);

    if (c_tilde_ != c_prime_tilde_) {
      return false;
    }

    return true;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_WITNESS_H_
