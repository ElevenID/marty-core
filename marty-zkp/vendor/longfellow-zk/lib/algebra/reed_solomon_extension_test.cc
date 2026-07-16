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

#include "algebra/reed_solomon_extension.h"

#include <cstddef>
#include <memory>

#include "algebra/fp24.h"
#include "algebra/fp24_6.h"
#include "algebra/interpolation.h"
#include "algebra/poly.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

static constexpr size_t N = 10;
static constexpr size_t M = 30;

TEST(ReedSolomonExtensionTest, Extension6) {
  using BaseField = Fp24;
  using ExtField = Fp24_6;
  using BaseElt = BaseField::Elt;
  using ExtElt = ExtField::Elt;

  const BaseField base(8380417);
  const ExtField ext(base, 7);

  using Poly = Poly<N, BaseField>;
  using Interpolation = Interpolation<N, BaseField>;
  using RSExtFactory = ReedSolomonExtensionFactory;

  Poly P[6];
  for (size_t d = 0; d < 6; ++d) {
    for (size_t i = 0; i < N; ++i) {
      P[d][i] = base.of_scalar(i * i * i + d * i + (i ^ (i << 2)));
    }
  }

  ExtElt L[M];
  for (size_t i = 0; i < M; ++i) {
    BaseElt x = base.of_scalar(i);
    for (size_t d = 0; d < 6; ++d) {
      L[i].e[d] = Interpolation::eval_monomial(P[d], x, base);
    }
  }

  ExtElt L2[M];
  for (size_t i = 0; i < N; ++i) {
    L2[i] = L[i];
  }

  RSExtFactory rs_ext_factory(base);

  auto r = rs_ext_factory.make(N, M);
  r->interpolate(L2);

  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(L2[i], L[i]);
  }
}

}  // namespace
}  // namespace proofs
