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

#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "circuits/tests/pq/ml_dsa/ml_dsa_44_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_types.h"
#include "gtest/gtest.h"

namespace proofs {
namespace ml_dsa {
namespace {

MatrixA MatrixAFromVectors(const uint64_t in[K][L][N]) {
  MatrixA A;
  for (size_t r = 0; r < K; ++r) {
    for (size_t s = 0; s < L; ++s) {
      for (size_t i = 0; i < N; ++i) {
        A[r][s][i] = Fq.of_scalar(in[r][s][i]);
      }
    }
  }
  return A;
}

std::array<Rq, K> ComputeWApprox(const PublicKey& pub_key,
                                 const std::array<Rq, L>& z, const Rq& c) {
  Rq c_ntt = c;
  Ntt(c_ntt);

  std::array<Rq, L> z_ntt = z;
  for (size_t i = 0; i < L; ++i) {
    Ntt(z_ntt[i]);
  }

  std::array<Rq, K> t1_ntt = pub_key.t1;
  for (size_t i = 0; i < K; ++i) {
    Ntt(t1_ntt[i]);
  }

  std::array<Rq, K> w_approx_ntt;
  for (size_t r = 0; r < K; ++r) {
    Rq az_r;  // Sum for row r
    for (size_t j = 0; j < N; ++j) az_r[j] = Fq.zero();

    for (size_t s = 0; s < L; ++s) {
      Rq prod = mulf(pub_key.a_hat[r][s], z_ntt[s]);
      az_r = addf(az_r, prod);
    }

    // Subtract c_ntt * t1_ntt[r] * 2^d
    Rq ct1 = mulf(c_ntt, t1_ntt[r]);
    Elt two_d = Fq.of_scalar(1 << D);
    ct1 = scalef(ct1, two_d);

    w_approx_ntt[r] = subf(az_r, ct1);
  }

  std::array<Rq, K> w_approx;
  for (size_t i = 0; i < K; ++i) {
    w_approx[i] = w_approx_ntt[i];
    InvNtt(w_approx[i]);
  }
  return w_approx;
}

TEST(MlDsaRefTest, NttRoundTrip) {
  Rq a;
  for (size_t i = 0; i < N; ++i) {
    a[i] = Fq.of_scalar(i * 12345 + 1);
  }
  Rq original = a;

  Ntt(a);
  InvNtt(a);

  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(a[i], original[i]) << "Mismatch at " << i;
  }
}

TEST(MlDsaRefTest, ExpandA) {
  std::vector<uint8_t> rho = {0x5e, 0x1b, 0xad, 0xb2, 0x92, 0x27, 0x6b, 0x20,
                              0x2a, 0x6f, 0x6a, 0xf9, 0x0e, 0x3c, 0xdc, 0xf6,
                              0xc1, 0xb5, 0xcc, 0x62, 0x60, 0xc0, 0x1b, 0x74,
                              0x7d, 0xac, 0x61, 0x9f, 0xe1, 0x61, 0x30, 0x28};

  MatrixA A = ExpandA(rho);

  MatrixA expected_A = MatrixAFromVectors(kExpectedExpandAVectors);

  for (size_t r = 0; r < K; ++r) {
    for (size_t s = 0; s < L; ++s) {
      for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(A[r][s][i], expected_A[r][s][i])
            << "Mismatch at r=" << r << " s=" << s << " i=" << i;
      }
    }
  }
}

TEST(MlDsaRefTest, SampleInBall) {
  auto tests = GetSampleInBallTests();
  for (size_t i = 0; i < tests.size(); ++i) {
    std::array<uint8_t, 32> rho_arr;
    std::copy(tests[i].in.begin(), tests[i].in.end(), rho_arr.begin());
    Rq c = SampleInBall(rho_arr);
    for (size_t j = 0; j < N; ++j) {
      EXPECT_EQ(c[j], Fq.of_scalar(tests[i].out[j]))
          << "Mismatch for test case t=" << i << " at j=" << j;
    }
  }
}

TEST(MlDsaRefTest, SigDecode) {
  auto tests = GetSigDecodeTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    auto maybe_sig = sigDecode(tests[t].in);
    ASSERT_TRUE(maybe_sig.has_value());
    Signature sig = maybe_sig.value();

    // Verify c_tilde
    for (size_t i = 0; i < C_TILDE_BYTES; ++i) {
      EXPECT_EQ(sig.c_tilde[i], tests[t].c_tilde[i])
          << "Mismatch c_tilde for test case t=" << t << " at i=" << i;
    }

    // Verify z
    for (size_t r = 0; r < L; ++r) {
      for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(sig.z[r][i], Fq.of_scalar(tests[t].z[r][i]))
            << "Mismatch z for test case t=" << t << " at r=" << r
            << " i=" << i;
      }
    }

    // Verify h
    for (size_t r = 0; r < K; ++r) {
      for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(sig.h[r][i], tests[t].h[r][i])
            << "Mismatch h for test case t=" << t << " at r=" << r
            << " i=" << i;
      }
    }
  }
}

TEST(MlDsaRefTest, PkDecode) {
  auto tests = GetPkDecodeTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    PublicKey pub_key = pkDecode(tests[t].in);

    // Verify tr
    for (size_t i = 0; i < 64; ++i) {
      EXPECT_EQ(pub_key.tr[i], tests[t].tr[i])
          << "Mismatch tr for test case t=" << t << " at i=" << i;
    }

    // Verify t1
    for (size_t r = 0; r < K; ++r) {
      for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(pub_key.t1[r][i], Fq.of_scalar(tests[t].t1[r][i]))
            << "Mismatch t1 for test case t=" << t << " at r=" << r
            << " i=" << i;
      }
    }

    // ExpandA testing validation logic could also be added,
    // although ExpandA is independently tested. We verify rho matching by
    // asserting against test vectors.
    MatrixA expected_A =
        ExpandA(std::vector<uint8_t>(tests[t].rho, tests[t].rho + 32));
    for (size_t r = 0; r < K; ++r) {
      for (size_t s = 0; s < L; ++s) {
        for (size_t i = 0; i < N; ++i) {
          EXPECT_EQ(pub_key.a_hat[r][s][i], expected_A[r][s][i])
              << "Mismatch a_hat at r=" << r << " s=" << s << " i=" << i;
        }
      }
    }
  }
}

TEST(MlDsaRefTest, PreprocessMessage) {
  for (const auto& ex : GetMlDsa44Examples()) {
    // 1. Get tr from pk
    PublicKey pub_key = pkDecode(ex.pkey);
    std::vector<uint8_t> tr(pub_key.tr.begin(), pub_key.tr.end());

    // 2. Preprocess Message
    std::vector<uint8_t> m_prime = preprocess_message(ex.msg, ex.ctx);

    // 3. Compute mu = H(tr || m_prime, 64)
    std::vector<uint8_t> input = tr;
    input.insert(input.end(), m_prime.begin(), m_prime.end());
    std::array<uint8_t, 64> mu;
    H(input, mu);

    EXPECT_TRUE((mu.size() == ex.mu.size()) &&
                std::equal(mu.begin(), mu.end(), ex.mu.begin()));
  }
}

TEST(MlDsaRefTest, VerifyExamples) {
  for (const auto& ex : GetMlDsa44Examples()) {
    // 1. Decode Public Key + signature
    PublicKey pub_key = pkDecode(ex.pkey);
    auto maybe_sig = sigDecode(ex.sig);
    ASSERT_TRUE(maybe_sig.has_value());
    Signature sig = maybe_sig.value();
    std::vector<uint8_t> tr(pub_key.tr.begin(), pub_key.tr.end());

    // 2. Preprocess Message
    std::vector<uint8_t> m_prime = preprocess_message(ex.msg, ex.ctx);

    // 3. Compute mu = H(tr || m_prime, 64)
    std::vector<uint8_t> input = tr;
    input.insert(input.end(), m_prime.begin(), m_prime.end());
    std::array<uint8_t, 64> mu;
    H(input, mu);

    EXPECT_TRUE((mu.size() == ex.mu.size()) &&
                std::equal(mu.begin(), mu.end(), ex.mu.begin()));

    // check infinity norm of z
    // gamma1 - beta = 131072 - 78 = 130994
    for (size_t i = 0; i < L; ++i) {
      for (size_t j = 0; j < N; ++j) {
        // Fq.from_montgomery() gives "canonical" representation in [0, q-1]
        // Normalize to [-q/2, q/2] for infinity norm
        Elt e = sig.z[i][j];
        uint64_t val = Fq.from_montgomery(e).limb_[0];
        int64_t sval = static_cast<int64_t>(val);
        if (sval > Q / 2) sval -= Q;
        EXPECT_LT(std::abs(sval), GAMMA_1 - BETA)
            << "Infinity norm check failed";
      }
    }

    // Spec Step 4: c = SampleInBall(c_tilde)
    Rq c = SampleInBall(sig.c_tilde);

    // 6. Compute w_approx = A z - c t1 2^d
    std::array<Rq, K> w_approx = ComputeWApprox(pub_key, sig.z, c);

    // 7. Recover w1 = UseHint(h, w_approx)
    std::array<Rq, K> w1;
    for (size_t r = 0; r < K; ++r) {
      for (size_t j = 0; j < N; ++j) {
        // w_approx[r][j] is Elt. Need to decompose/usehint on integers.
        uint64_t val = Fq.from_montgomery(w_approx[r][j]).limb_[0];
        // UseHint takes int32_t. Val is [0, q-1].
        uint32_t w1_val = UseHint(sig.h[r][j], static_cast<int32_t>(val));
        EXPECT_LE(w1_val, 43) << "w1 > 43 at r=" << r << " j=" << j;
        w1[r][j] = Fq.of_scalar(w1_val);
      }
    }

    // 8. Compute c_prime = H(mu || w1Encode(w1))
    auto w1_bytes = w1Encode(w1);
    std::vector<uint8_t> c_prime_input;
    c_prime_input.insert(c_prime_input.end(), mu.begin(), mu.end());
    c_prime_input.insert(c_prime_input.end(), w1_bytes.begin(), w1_bytes.end());

    std::array<uint8_t, 32> c_prime;
    H(c_prime_input, c_prime);

    // Check match
    EXPECT_EQ(c_prime, sig.c_tilde);
  }
}

TEST(MlDsaRefTest, VerifyFailureExamples) {
  for (const auto& ex : GetMlDsa44FailExamples()) {
    bool ok = true;
    PublicKey pub_key = pkDecode(ex.pkey);
    std::vector<uint8_t> tr(pub_key.tr.begin(), pub_key.tr.end());
    std::vector<uint8_t> m_prime = preprocess_message(ex.msg, ex.ctx);
    std::vector<uint8_t> input = tr;
    input.insert(input.end(), m_prime.begin(), m_prime.end());
    std::array<uint8_t, 64> mu;
    H(input, mu);
    auto maybe_sig = sigDecode(ex.sig);
    if (!maybe_sig.has_value()) {
      continue;  // Failed to decode signature, so verification fails (as
                 // expected)
    }
    Signature sig = maybe_sig.value();

    // check infinity norm of z
    // gamma1 - beta = 131072 - 78 = 130994
    for (size_t i = 0; i < L; ++i) {
      for (size_t j = 0; j < N; ++j) {
        Elt e = sig.z[i][j];
        uint64_t val = Fq.from_montgomery(e).limb_[0];
        int64_t sval = static_cast<int64_t>(val);
        if (sval > Q / 2) sval -= Q;
        if (std::abs(sval) >= GAMMA_1 - BETA) {
          ok = false;
          break;
        }
      }
      if (!ok) break;
    }

    Rq c = SampleInBall(sig.c_tilde);
    std::array<Rq, K> w_approx = ComputeWApprox(pub_key, sig.z, c);

    // 7. Recover w1 = UseHint(h, w_approx)
    std::array<Rq, K> w1;
    for (size_t r = 0; r < K; ++r) {
      for (size_t j = 0; j < N; ++j) {
        // w_approx[r][j] is Elt. Need to decompose/usehint on integers.
        uint64_t val = Fq.from_montgomery(w_approx[r][j]).limb_[0];
        // UseHint takes int32_t. Val is [0, q-1].
        uint32_t w1_val = UseHint(sig.h[r][j], static_cast<int32_t>(val));
        if (w1_val > 43) {
          ok = false;
          break;
        }
        w1[r][j] = Fq.of_scalar(w1_val);
      }
      if (!ok) break;
    }

    // 8. Compute c_prime = H(mu || w1Encode(w1))
    auto w1_bytes = w1Encode(w1);
    std::vector<uint8_t> c_prime_input;
    c_prime_input.insert(c_prime_input.end(), mu.begin(), mu.end());
    c_prime_input.insert(c_prime_input.end(), w1_bytes.begin(), w1_bytes.end());

    std::array<uint8_t, 32> c_prime;
    H(c_prime_input, c_prime);

    // Check match
    if (c_prime != sig.c_tilde) {
      ok = false;
    }
    EXPECT_FALSE(ok);
  }
}

TEST(MlDsaRefTest, UseHint) {
  auto tests = GetUseHintTestCases();
  for (size_t i = 0; i < tests.size(); ++i) {
    bool h = tests[i].h;
    int32_t r = tests[i].r;
    uint32_t expected = tests[i].expected;
    uint32_t result = UseHint(h, r);
    EXPECT_EQ(result, expected)
        << "Mismatch for UseHint at index " << i << " h=" << h << " r=" << r;
  }
}

TEST(MlDsaRefTest, W1Encode) {
  auto tests = GetW1EncodeTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    std::array<Rq, K> w1;
    for (size_t r = 0; r < K; ++r) {
      for (size_t i = 0; i < N; ++i) {
        w1[r][i] = Fq.of_scalar(tests[t].in[r][i]);
      }
    }

    auto encoded = w1Encode(w1);

    // Verify size
    // K * 256 * 6 bits = 4 * 1536 bits = 6144 bits = 768 bytes
    EXPECT_EQ(encoded.size(), K * 192);

    for (size_t i = 0; i < encoded.size(); ++i) {
      EXPECT_EQ(encoded[i], tests[t].out[i])
          << "Mismatch at test " << t << " byte " << i;
    }
  }
}

}  // namespace
}  // namespace ml_dsa
}  // namespace proofs
