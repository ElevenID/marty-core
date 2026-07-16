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

#include "sumcheck/quad.h"

#include <stddef.h>

#include <memory>
#include <utility>
#include <vector>

#include "algebra/bogorng.h"
#include "algebra/fp.h"
#include "arrays/affine.h"
#include "arrays/sparse.h"
#include "sumcheck/equad.h"
#include "sumcheck/hquad.h"
#include "sumcheck/quad_builder.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
typedef Fp<1> Field;
static const Field F("18446744073709551557");
typedef Field::Elt Elt;
Bogorng<Field> rng(&F);
typedef EQuad<Field>::quad_corner_t quad_corner_t;
typedef EQuad<Field>::index_t index_t;

class RandomSlice {
 public:
  std::vector<Elt> r_;
  explicit RandomSlice(size_t n) : r_(n) {
    for (size_t i = 0; i < n; ++i) {
      r_[i] = rng.next();
    }
  }
};

Elt lagrange(quad_corner_t p, size_t logn, const Elt* R) {
  Elt l = F.one();
  for (size_t i = 0; i < logn; i++) {
    if ((p & (quad_corner_t(1) << i)) != quad_corner_t(0)) {
      F.mul(l, R[i]);
    } else {
      F.mul(l, F.subf(F.one(), R[i]));
    }
  }
  return l;
}

void one_bind_g(index_t n, size_t logn) {
  RandomSlice R(logn);
  RandomSlice R2(logn);
  auto EQUAD = std::make_unique<EQuad<Field>>(n);
  Elt s = F.zero();
  Elt s2 = F.zero();
  Elt alpha = rng.next();
  for (index_t i = 0; i < n; ++i) {
    quad_corner_t p = quad_corner_t(13 * i);
    Elt r = rng.next();
    EQUAD->ec_[i] = EQuad<Field>::ecorner{
        .g = p, .h = {quad_corner_t(0), quad_corner_t(0)}, .v = r};
    F.add(s, F.mulf(r, lagrange(p, logn, R.r_.data())));
    F.add(s2, F.mulf(r, lagrange(p, logn, R2.r_.data())));
  }

  auto QUAD = QuadBuilder<Field>::compress(EQUAD.get(), F);
  auto HQUAD =
      QUAD->bind_g(logn, R.r_.data(), R2.r_.data(), alpha, F.zero(), F);
  EXPECT_EQ(HQUAD->scalar(), F.addf(s, F.mulf(alpha, s2)));
}

TEST(EQuad, BindG) {
  one_bind_g(index_t(666), 10 + 4);
  one_bind_g(index_t(1), 9 + 4);
  for (size_t i = 200; i < 300; i++) {
    one_bind_g(index_t(i), 9 + 4);
  }
  one_bind_g(index_t(467), 9 + 4);
  one_bind_g(index_t(512), 9 + 4);
}

// compare interleaved binding of quad<> with
// a pair of bind_all() of Sparse<>.
void one_bind_h(index_t n, size_t logn) {
  auto EQUAD = std::make_unique<EQuad<Field>>(n);
  auto S = Sparse<Field>(n);
  RandomSlice R0(logn);
  RandomSlice R1(logn);
  size_t mask = (size_t(1) << logn) - 1;
  for (index_t i = 0; i < n; ++i) {
    quad_corner_t h0 = quad_corner_t((13 * i + 4) & mask);
    quad_corner_t h1 = quad_corner_t((23 * i + 3) & mask);

    // EQuad<Field> canonicalizes h0, h1 because
    // they are only used for a commutative F.mul,
    // but Sparse<Field> does not, so we canonicalize
    // h0, h1 in advance
    if (h0 > h1) {
      std::swap(h0, h1);
    }

    Elt r = rng.next();
    EQUAD->ec_[i] =
        EQuad<Field>::ecorner{.g = quad_corner_t(0), .h = {h0, h1}, .v = r};
    S.c_[i] = Sparse<Field>::corner{
        .p0 = 0, .p1 = corner_t(h0), .p2 = corner_t(h1), .v = r};
  }

  EQUAD->canonicalize(F);
  S.canonicalize(F);
  S.reshape();

  S.bind_all(logn, R0.r_.data(), F);
  S.reshape();
  S.bind_all(logn, R1.r_.data(), F);
  auto QUAD = QuadBuilder<Field>::compress(EQUAD.get(), F);
  auto HQUAD = QUAD->bind_g(/*logv=*/0, nullptr, nullptr, /*alpha=*/F.zero(),
                            /*beta=*/F.zero(), F);

  for (size_t round = 0; round < logn; ++round) {
    HQUAD->bind_h(R0.r_[round], /*hand=*/0, F);
    HQUAD->bind_h(R1.r_[round], /*hand=*/1, F);
  }

  EXPECT_EQ(HQUAD->scalar(), S.scalar());
}

TEST(EQuad, BindH) {
  one_bind_h(index_t(666), 10);
  one_bind_h(index_t(1), 9);
  for (size_t i = 200; i < 300; i++) {
    for (size_t logn = 1; logn < 20; ++logn) {
      one_bind_h(index_t(i), logn);
    }
  }
  one_bind_h(index_t(467), 9);
  one_bind_h(index_t(512), 9);
  one_bind_h(index_t(512), 33);
}

TEST(ApproximateDeltaTableBuilder, Basic) {
  ApproximateDeltaTableBuilder<Field> db(10);
  // These three should be different and likely hash to different buckets,
  // but if they collide it's also fine for the builder's correctness.
  db.dedup(quad_corner_t(1), quad_corner_t(2), quad_corner_t(3), 4);
  db.dedup(quad_corner_t(5), quad_corner_t(6), quad_corner_t(7), 8);
  db.dedup(quad_corner_t(1), quad_corner_t(2), quad_corner_t(3), 4);

  auto table = db.delta_table();
  // If no collision, size should be 2. If collision, size could be 3.
  EXPECT_GE(table->size(), 2);
  EXPECT_LE(table->size(), 3);
}

}  // namespace
}  // namespace proofs
