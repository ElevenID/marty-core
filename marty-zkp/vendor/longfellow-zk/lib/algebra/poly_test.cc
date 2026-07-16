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

#include "algebra/poly.h"

#include <cstddef>

#include "algebra/blas.h"
#include "algebra/bogorng.h"
#include "algebra/fp.h"
#include "algebra/static_string.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
static const StaticString primes[] = {
    StaticString("18446744073709551557"),
    StaticString("340282366920938463463374607431768211297"),
    StaticString("6277101735386680763835789423207666416102355444464034512659"),
    StaticString("1157920892373161954235709850086879078532699846656405640394575"
                 "84007913129639747"),
    StaticString("2135987035920910082395021706169552114602704522356652769947041"
                 "607822219725780640550022962086936379"),
    StaticString("3940200619639447921227904010014361380507973927046544666794829"
                 "3404245721771497210611414266254884915640806627990306499"),
};

template <size_t N, size_t W>
void one_test_eval_lagrange() {
  using Field = Fp<W>;
  using T = Poly<N, Field>;
  using Elt = typename Field::Elt;
  const Field F(primes[W - 1]);
  Bogorng<Field> rng(&F);
  const typename T::dot_interpolation dot_interp(F);

  T C, L;
  for (size_t iter = 0; iter < 10; ++iter) {
    for (size_t i = 0; i < N; ++i) {
      C[i] = rng.next();
    }

    for (size_t i = 0; i < N; ++i) {
      // Lagrange basis
      L[i] = C.eval_monomial(F.poly_evaluation_point(i), F);
    }

    for (size_t iter1 = 0; iter1 < 10; iter1++) {
      auto r = rng.next();
      Elt got_val = L.eval_lagrange(r, F);
      Elt want_val = C.eval_monomial(r, F);
      EXPECT_EQ(got_val, want_val);

      T coef = dot_interp.coef(r, F);
      Elt got_dot = Blas<Field>::dot(N, &coef[0], 1, &L[0], 1, F);
      EXPECT_EQ(got_dot, want_val);
    }
  }
}

template <size_t N, size_t W>
void one_test_extend() {
  using Field = Fp<W>;
  using T2 = Poly<2, Field>;
  using FT = Poly<N, Field>;
  using Elt = typename Field::Elt;
  const Field F(primes[W - 1]);
  Bogorng<Field> rng(&F);

  // Test the linear extension.  Start with a polynomial
  // L2 of degree <2, and extend it to a polynomial L
  // of degree <N, then evaluate both at random points.
  for (size_t iter = 0; iter < 10; ++iter) {
    T2 L2;
    L2[0] = rng.next();
    L2[1] = rng.next();

    FT L = FT::extend(L2, F);

    for (size_t iter1 = 0; iter1 < 10; iter1++) {
      auto r = rng.next();
      Elt got = L.eval_lagrange(r, F);
      Elt got2 = L2.eval_lagrange(r, F);
      EXPECT_EQ(got, got2);
    }
  }
}

template <size_t W>
void oneW() {
  one_test_eval_lagrange<2, W>();
  one_test_eval_lagrange<3, W>();
  one_test_eval_lagrange<4, W>();
  one_test_eval_lagrange<5, W>();
  one_test_eval_lagrange<6, W>();
  one_test_extend<2, W>();
  one_test_extend<3, W>();
  one_test_extend<4, W>();
  one_test_extend<5, W>();
  one_test_extend<6, W>();
}

TEST(Poly, All) {
  oneW<1>();
  oneW<2>();
  oneW<3>();
  oneW<4>();
  oneW<5>();
  oneW<6>();
}
}  // namespace
}  // namespace proofs
