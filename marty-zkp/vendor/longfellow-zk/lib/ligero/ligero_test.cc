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

#include <stdlib.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

#include "algebra/blas.h"
#include "algebra/convolution.h"
#include "algebra/fp.h"
#include "algebra/reed_solomon.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_prover.h"
#include "ligero/ligero_verifier.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field, class ReedSolomonFactory>
void ligero_test(const ReedSolomonFactory &rs_factory, const Field &F) {
  using Elt = typename Field::Elt;
  set_log_level(INFO);
  static const constexpr size_t nw = 300000;
  static const constexpr size_t nq = 30000;
  static const constexpr size_t nreq = 189;
  static const constexpr size_t nl = 7;
  LigeroParam<Field> param(nw, nq, /*rateinv=*/4, nreq);
  log(INFO, "%zd %zd %zd %zd %zd %zd\n", param.r, param.w, param.block,
      param.block_enc, param.nrow, param.nqtriples);

  std::vector<Elt> W(nw);
  std::vector<Elt> A(nw);
  for (size_t i = 0; i < nw; ++i) {
    W[i] = F.of_scalar_field(random());
    A[i] = F.of_scalar_field(random());
  }

  // Set up semi-random quadratic constraints.  For simplicity
  // of testing, say that the first NQ odd-index witnesses are
  // the product of two even-index witnesses
  std::vector<LigeroQuadraticConstraint> lqc(nq);
  for (size_t i = 0; i < nq; ++i) {
    lqc[i].z = 2 * i + 1;
    lqc[i].x = 2 * ((random() % nw) / 2);
    lqc[i].y = 2 * ((random() % nw) / 2);
    W[lqc[i].z] = F.mulf(W[lqc[i].x], W[lqc[i].y]);
  }

  // Generate NL linear constraints.
  std::vector<LigeroLinearConstraint<Field>> llterm;
  std::vector<Elt> b(nl);
  Blas<Field>::clear(nl, &b[0], 1, F);
  for (size_t w = 0; w < nw; ++w) {
    LigeroLinearConstraint<Field> term = {
        w % nl,  // c
        w,       // w
        A[w],    // k
    };
    llterm.push_back(term);
    F.add(b[term.c], F.mulf(W[w], term.k));
  }

  LigeroCommitment<Field> commitment;
  LigeroProof<Field> proof(&param);

  const LigeroHash hash_of_llterm{0xde, 0xad, 0xbe, 0xef};

  {
    log(INFO, "start prover");
    SecureRandomEngine rng;
    LigeroProver<Field, ReedSolomonFactory> prover(param);
    Transcript ts((uint8_t *)"test", 4);
    prover.commit(commitment, ts, &W[0], /*subfield_boundary=*/0, &lqc[0],
                  rs_factory, rng, F);
    prover.prove(proof, ts, nl, llterm.size(), &llterm[0], hash_of_llterm,
                 &lqc[0], rs_factory, F);
    log(INFO, "end prover");
  }

  {
    log(INFO, "start verifier");
    Transcript ts((uint8_t *)"test", 4);
    LigeroVerifier<Field, ReedSolomonFactory>::receive_commitment(commitment,
                                                                  ts);
    const char *why = "";
    bool ok = LigeroVerifier<Field, ReedSolomonFactory>::verify(
        &why, param, commitment, proof, ts, nl, llterm.size(), &llterm[0],
        hash_of_llterm, &b[0], &lqc[0], rs_factory, F);
    EXPECT_TRUE(ok);
    log(INFO, "end verifier");
  }
}

template <class Field, class RealInterpolator>
class BadInterpolator {
 public:
  using Elt = typename Field::Elt;
  BadInterpolator(std::unique_ptr<RealInterpolator> real, bool should_fail,
                  size_t n, size_t m)
      : real_(std::move(real)), should_fail_(should_fail), n_(n), m_(m) {}

  void interpolate(Elt y[]) const {
    real_->interpolate(y);
    if (should_fail_ && m_ > n_) {
      Elt first = y[n_];
      for (size_t i = n_; i < m_ - 1; ++i) {
        y[i] = y[i + 1];
      }
      y[m_ - 1] = first;
    }
  }

 private:
  std::unique_ptr<RealInterpolator> real_;
  bool should_fail_;
  size_t n_, m_;
};

template <class Field, class RealFactory>
class BadReedSolomonFactory {
 public:
  BadReedSolomonFactory(const RealFactory& real, int fail_idx)
      : real_(real), fail_idx_(fail_idx), calls_(std::make_shared<int>(0)) {}

  auto make(size_t n, size_t m) const {
    auto real_interp = real_.make(n, m);
    (*calls_)++;
    bool should_fail = (*calls_ == fail_idx_);
    using RealInterpolator = typename decltype(real_interp)::element_type;
    return std::make_unique<BadInterpolator<Field, RealInterpolator>>(
        std::move(real_interp), should_fail, n, m);
  }

 private:
  const RealFactory& real_;
  int fail_idx_;
  std::shared_ptr<int> calls_;
};

template <class Field, class ReedSolomonFactory>
void test_ligero_verifier_failures(const ReedSolomonFactory& rs_factory,
                                   const Field& F) {
  using Elt = typename Field::Elt;
  static const constexpr size_t nw = 300;
  static const constexpr size_t nq = 30;
  static const constexpr size_t nreq = 18;
  static const constexpr size_t nl = 7;
  LigeroParam<Field> param(nw, nq, /*rateinv=*/4, nreq);

  std::vector<Elt> W(nw);
  std::vector<Elt> A(nw);
  for (size_t i = 0; i < nw; ++i) {
    W[i] = F.of_scalar_field(random());
    A[i] = F.of_scalar_field(random());
  }

  std::vector<LigeroQuadraticConstraint> lqc(nq);
  for (size_t i = 0; i < nq; ++i) {
    lqc[i].z = 3 * i + 2;
    lqc[i].x = 3 * i;
    lqc[i].y = 3 * i + 1;
    W[lqc[i].z] = F.mulf(W[lqc[i].x], W[lqc[i].y]);
  }

  std::vector<LigeroLinearConstraint<Field>> llterm;
  std::vector<Elt> b(nl);
  Blas<Field>::clear(nl, &b[0], 1, F);
  for (size_t w = 0; w < nw; ++w) {
    LigeroLinearConstraint<Field> term = {w % nl, w, A[w]};
    llterm.push_back(term);
    F.add(b[term.c], F.mulf(W[w], term.k));
  }

  LigeroCommitment<Field> commitment;
  LigeroProof<Field> proof(&param);
  const LigeroHash hash_of_llterm{0xde, 0xad, 0xbe, 0xef};

  SecureRandomEngine rng;
  LigeroProver<Field, ReedSolomonFactory> prover(param);
  Transcript ts_prove((uint8_t*)"test", 4);
  prover.commit(commitment, ts_prove, &W[0], 0, &lqc[0], rs_factory, rng, F);
  prover.prove(proof, ts_prove, nl, llterm.size(), &llterm[0], hash_of_llterm,
               &lqc[0], rs_factory, F);

  const char* why = "";

  // 1. why == nullptr
  Transcript ts1((uint8_t*)"test", 4);
  LigeroVerifier<Field, ReedSolomonFactory>::receive_commitment(commitment,
                                                                ts1);
  EXPECT_FALSE((LigeroVerifier<Field, ReedSolomonFactory>::verify(
      nullptr, param, commitment, proof, ts1, nl, llterm.size(), &llterm[0],
      hash_of_llterm, &b[0], &lqc[0], rs_factory, F)));

  // 2. merkle_check failed
  Transcript ts2((uint8_t*)"test", 4);
  LigeroCommitment<Field> bad_comm = commitment;
  bad_comm.root.data[0] ^= 1;
  LigeroVerifier<Field, ReedSolomonFactory>::receive_commitment(bad_comm, ts2);
  EXPECT_FALSE((LigeroVerifier<Field, ReedSolomonFactory>::verify(
      &why, param, bad_comm, proof, ts2, nl, llterm.size(), &llterm[0],
      hash_of_llterm, &b[0], &lqc[0], rs_factory, F)));
  EXPECT_STREQ(why, "merkle_check failed");

  // 3. dot_check failed (wrong dot product)
  Transcript ts3((uint8_t*)"test", 4);
  LigeroVerifier<Field, ReedSolomonFactory>::receive_commitment(commitment,
                                                                ts3);
  std::vector<Elt> bad_b = b;
  F.add(bad_b[0], F.one());
  EXPECT_FALSE((LigeroVerifier<Field, ReedSolomonFactory>::verify(
      &why, param, commitment, proof, ts3, nl, llterm.size(), &llterm[0],
      hash_of_llterm, &bad_b[0], &lqc[0], rs_factory, F)));
  EXPECT_STREQ(why, "wrong dot product");

  // 4. dot_check failed (bad constraint)
  Transcript ts4((uint8_t*)"test", 4);
  LigeroVerifier<Field, ReedSolomonFactory>::receive_commitment(commitment,
                                                                ts4);
  std::vector<LigeroLinearConstraint<Field>> bad_llterm = llterm;
  F.add(bad_llterm[0].k, F.one());
  EXPECT_FALSE((LigeroVerifier<Field, ReedSolomonFactory>::verify(
      &why, param, commitment, proof, ts4, nl, bad_llterm.size(),
      &bad_llterm[0], hash_of_llterm, &b[0], &lqc[0], rs_factory, F)));
  EXPECT_STREQ(why, "dot_check failed");

  // 5. low_degree_check failed
  Transcript ts5((uint8_t*)"test", 4);
  LigeroVerifier<Field, ReedSolomonFactory>::receive_commitment(commitment,
                                                                ts5);
  BadReedSolomonFactory<Field, ReedSolomonFactory> bad_rs_1(rs_factory, 1);
  EXPECT_FALSE(
      (LigeroVerifier<Field, BadReedSolomonFactory<Field, ReedSolomonFactory>>::
           verify(&why, param, commitment, proof, ts5, nl, llterm.size(),
                  &llterm[0], hash_of_llterm, &b[0], &lqc[0], bad_rs_1, F)));
  EXPECT_STREQ(why, "low_degree_check failed");

  // 6. quadratic_check failed
  Transcript ts6((uint8_t*)"test", 4);
  LigeroVerifier<Field, ReedSolomonFactory>::receive_commitment(commitment,
                                                                ts6);
  BadReedSolomonFactory<Field, ReedSolomonFactory> bad_rs_4(rs_factory, 4);
  EXPECT_FALSE(
      (LigeroVerifier<Field, BadReedSolomonFactory<Field, ReedSolomonFactory>>::
           verify(&why, param, commitment, proof, ts6, nl, llterm.size(),
                  &llterm[0], hash_of_llterm, &b[0], &lqc[0], bad_rs_4, F)));
  EXPECT_STREQ(why, "quadratic_check failed");
}

TEST(Ligero, Fp) {
  using Field = Fp<1>;
  using ConvolutionFactory = FFTConvolutionFactory<Field>;
  using ReedSolomonFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  const Field F("18446744069414584321");
  const ConvolutionFactory conv_factory(F, F.of_scalar(1753635133440165772ull),
                                        1ull << 32);
  const ReedSolomonFactory rs_factory(conv_factory, F);

  ligero_test(rs_factory, F);
  test_ligero_verifier_failures(rs_factory, F);
}

TEST(Ligero, GF2_128) {
  using Field = GF2_128<>;
  const Field F;
  using ReedSolomonFactory = LCH14ReedSolomonFactory<Field>;
  const ReedSolomonFactory rs_factory(F);

  ligero_test(rs_factory, F);
  test_ligero_verifier_failures(rs_factory, F);
}

TEST(Ligero, BlockEncUnderflowInLayout) {
  using Field = Fp<1>;
  // We need to trigger the condition: block_enc < dblock on line 224 of
  // ligero_param.h. This happens when block == 0 and dblock (2*block - 1)
  // underflows to SIZE_MAX. By setting nreq (and thus r) to 0, we can bypass
  // the check (block < r), allowing block to be 0 for small values of block_enc
  // (e.g. block_enc = 1).
  LigeroParam<Field> param(300, 30, 4, /*nreq=*/0);

  // Test block_enc = 1 which yields block = (1+1)/(2+4) = 0.
  // dblock underflows to SIZE_MAX, and layout should return SIZE_MAX.
  EXPECT_EQ(param.layout(1), SIZE_MAX);
}

}  // namespace
}  // namespace proofs
