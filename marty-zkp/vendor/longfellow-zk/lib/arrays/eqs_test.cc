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

#include "arrays/eqs.h"

#include <stddef.h>

#include <vector>

#include "algebra/bogorng.h"
#include "algebra/fp.h"
#include "arrays/affine.h"
#include "arrays/dense.h"
#include "arrays/eq.h"
#include "arrays/sparse.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = Fp<4>;
using Elt = typename Field::Elt;
using index_t = Sparse<Field>::index_t;

static const Field F(
    "21888242871839275222246405745257275088548364400416034343698204186575808495"
    "617");

class RandomSlice {
 public:
  std::vector<Elt> r_;
  explicit RandomSlice(size_t n) : r_(n) {
    Bogorng<Field> rng(&F);
    for (size_t i = 0; i < n; ++i) {
      r_[i] = rng.next();
    }
  }
};

// V[T] = EQ[T|i] V[i]
void one_test_eqs_bind(size_t logn, corner_t n) {
  RandomSlice T(logn);
  Eqs<Field> EQ(logn, n, T.r_.data(), F);
  auto V = Dense<Field>(n, 1);
  V.clear(F);

  Elt rhs = F.zero();
  for (corner_t i = 0; i < n; i++) {
    F.add(rhs, F.mulf(EQ.at(i), V.v_[i]));
  }

  V.bind_all(logn, T.r_.data(), F);
  Elt lhs = V.scalar();

  EXPECT_EQ(lhs, rhs);
}

// EQ[A|B] = EQ[A|i] EQ[i|B]
void one_test_eqs_decomposition(size_t logn, corner_t n) {
  RandomSlice A(logn);
  RandomSlice B(logn);
  Eqs<Field> EQA(logn, n, A.r_.data(), F);
  Eqs<Field> EQB(logn, n, B.r_.data(), F);

  Elt rhs = F.zero();
  for (corner_t i = 0; i < n; i++) {
    F.add(rhs, F.mulf(EQA.at(i), EQB.at(i)));
  }

  Elt lhs = Eq<Field>::eval(logn, n, A.r_.data(), B.r_.data(), F);
  EXPECT_EQ(lhs, rhs);
}

TEST(Eqs, All) {
  for (size_t logn = 0; logn < 8; logn++) {
      for (size_t i = 1; i <= (1 << logn); i++) {
        one_test_eqs_bind(logn, corner_t(i));
        one_test_eqs_decomposition(logn, corner_t(i));
      }
  }
}

// recursive implementation of bindv(EQ[], .) as described in the
// RFC, so that we can verify equivalence with our implementation.
std::vector<Elt> bindeq(size_t l, const Elt X[/*l*/]) {
  size_t n = size_t(1) << l;
  std::vector<Elt> B(n);
  if (l == 0) {
    B[0] = F.one();
  } else {
    auto A = bindeq(l - 1, X + 1);
    for (size_t i = 0; 2 * i < n; ++i) {
      B[2 * i] = F.mulf(F.subf(F.one(), X[0]), A[i]);
      B[2 * i + 1] = F.mulf(X[0], A[i]);
    }
  }
  return B;
}

TEST(Eqs, RFC) {
  size_t logn = 11;
  size_t n = size_t(1) << logn;
  RandomSlice X(logn);
  auto RFC = bindeq(logn, X.r_.data());
  Eqs<Field> EQ(logn, n, X.r_.data(), F);
  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(RFC[i], EQ.at(i));
  }

  // truncating N truncates bindv(EQ, .) with no other ill effects
  size_t n2 = n - 7;
  Eqs<Field> EQ2(logn, n2, X.r_.data(), F);
  for (size_t i = 0; i < n2; ++i) {
    EXPECT_EQ(RFC[i], EQ2.at(i));
  }
}

TEST(Eqs, RawEq2) {
  Bogorng<Field> rng(&F);
  for (size_t logn = 0; logn < 6; logn++) {
    for (corner_t n = 1; n <= (corner_t(1) << logn); n++) {
      RandomSlice G0(logn);
      RandomSlice G1(logn);
      Elt alpha = rng.next();

      auto eq =
          Eqs<Field>::raw_eq2(logn, n, G0.r_.data(), G1.r_.data(), alpha, F);
      Eqs<Field> EQ0(logn, n, G0.r_.data(), F);
      Eqs<Field> EQ1(logn, n, G1.r_.data(), F);

      ASSERT_EQ(eq.size(), n);
      for (corner_t i = 0; i < n; i++) {
        Elt expected = F.addf(EQ0.at(i), F.mulf(alpha, EQ1.at(i)));
        EXPECT_EQ(eq[i], expected)
            << "logn=" << logn << ", n=" << n << ", i=" << i;
      }
    }
  }
}
}  // namespace
}  // namespace proofs
