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

#include "circuits/logic/polynomial.h"

#include <stddef.h>

#include "algebra/fp.h"
#include "algebra/poly.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = Fp<1>;
using Elt = typename Field::Elt;
const Field F("18446744073709551557");

using EvaluationBackend = EvaluationBackend<Field>;
using Logic = Logic<Field, EvaluationBackend>;
using EltW = Logic::EltW;

TEST(Polynomial, Eval) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  constexpr size_t N = 17;
  using Poly = Poly<N, Field>;
  const Polynomial<Logic> P(L);

  Poly M;
  // arbitrary coefficients
  for (size_t i = 0; i < N; ++i) {
    M[i] = F.of_scalar(i * i + 37 * i + 122);
  }

  // evaluate at 1000 points
  for (size_t k = 0; k < 1000; ++k) {
    Elt pt = F.of_scalar(k);
    Elt want = M.eval_monomial(pt, F);

    EltW got = P.eval(M, L.konst(pt));
    EXPECT_EQ(got.elt(), want);

    EltW got_horner = P.eval_horner(M, L.konst(pt));
    EXPECT_EQ(got_horner.elt(), want);
  }
}
}  // namespace
}  // namespace proofs

