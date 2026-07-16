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

#include "algebra/interpolation.h"

#include <cstddef>

#include "algebra/fp.h"
#include "algebra/poly.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = Fp<1>;
using Elt = typename Field::Elt;
static constexpr size_t N = 37;

using Interpolation = Interpolation<N, Field>;
using Poly = Poly<N, Field>;
const Field F("18446744073709551557");

TEST(Interpolation, Simple) {
  Poly X, M;

  // arbitrary points and coefficients
  for (size_t i = 0; i < N; ++i) {
    X[i] = F.of_scalar(i * i + 3 * i + 37);
    M[i] = F.of_scalar(i * i * i + (i & 0xF) + (i ^ (i << 2)));
  }

  // lagrange basis
  Poly L;
  for (size_t i = 0; i < N; ++i) {
    L[i] = Interpolation::eval_monomial(M, X[i], F);
  }

  // newton basis
  auto Newton = Interpolation::newton_of_lagrange(L, X, F);

  // evaluation in newton and monomial bases must agree
  for (size_t i = 0; i < 1000; ++i) {
    Elt x = F.of_scalar(i);
    EXPECT_EQ(Interpolation::eval_newton(Newton, X, x, F),
              Interpolation::eval_monomial(M, x, F));
  }

  auto M2 = Interpolation::monomial_of_newton(Newton, X, F);

  // monomial coefficients must agree
  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(M[i], M2[i]);
  }

  auto M3 = Interpolation::monomial_of_lagrange(L, X, F);

  // monomial coefficients must agree
  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(M[i], M3[i]);
  }
}
}  // namespace
}  // namespace proofs

