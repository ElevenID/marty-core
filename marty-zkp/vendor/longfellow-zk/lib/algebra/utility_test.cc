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

#include "algebra/utility.h"

#include "algebra/bogorng.h"
#include "algebra/compare.h"
#include "algebra/fp.h"
#include "algebra/hash.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = Fp<4>;
using Elt = typename Field::Elt;

TEST(Utility, BatchInverse) {
  const Field F(
      "218882428718392752222464057452572750885483644004160343436982041865758084"
      "95617");
  Bogorng<Field> rng(&F);

  constexpr size_t n = 133, da = 3, db = 5;
  Elt a[n * da], b[n * db];
  for (size_t i = 0; i < n; ++i) {
    b[i * db] = rng.nonzero();
  }
  AlgebraUtil<Fp<4>>::batch_invert(n, a, da, b, db, F);
  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(F.mulf(a[i * da], b[i * db]), F.one());
    EXPECT_EQ(a[i * da], F.invertf(b[i * db]));
    EXPECT_EQ(b[i * db], F.invertf(a[i * da]));
  }
}

//------------------------------------------------------------

// a[i] /= i!, without doing too many inversions
void scale_inverse_factorial(size_t n, Elt* a, const Field& F) {
  auto p = F.one();
  auto fi = F.one();
  for (size_t i = 1; i < n; ++i) {
    F.mul(p, fi);
    F.add(fi, F.one());
  }
  // now p=(n-1)!, fi=of_scalar(n)

  F.invert(p);
  for (size_t i = n; i-- > 1;) {
    F.mul(a[i], p);
    F.sub(fi, F.one());
    F.mul(p, fi);
  }
}

TEST(Utility, Factorial) {
  constexpr size_t n = 37;
  const Field F(
      "218882428718392752222464057452572750885483644004160343436982041865758084"
      "95617");
  Bogorng<Field> rng(&F);

  Elt A[n], B[n];
  for (size_t i = 0; i < n; ++i) {
    A[i] = B[i] = rng.next();
  }
  scale_inverse_factorial(n, A, F);
  for (size_t i = 0; i < n; ++i) {
    Elt fact = AlgebraUtil<Field>::factorial(i, F);
    EXPECT_EQ(B[i], F.mulf(A[i], fact));
  }
}

TEST(Utility, CompareAndHash) {
  const Field F(
      "218882428718392752222464057452572750885483644004160343436982041865758084"
      "95617");
  auto a = F.of_scalar(1);
  auto b = F.of_scalar(2);

  EXPECT_TRUE(elt_less_than(a, b, F));
  EXPECT_FALSE(elt_less_than(b, a, F));
  EXPECT_FALSE(elt_less_than(a, a, F));

  auto h1 = elt_hash(a, F);
  auto h2 = elt_hash(b, F);
  EXPECT_NE(h1, h2);
}

}  // namespace
}  // namespace proofs
