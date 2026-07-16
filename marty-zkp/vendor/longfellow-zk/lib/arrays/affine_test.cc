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

#include "arrays/affine.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <vector>

#include "algebra/bogorng.h"
#include "algebra/fp.h"
#include "arrays/dense.h"
#include "arrays/sparse.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = Fp<4>;
static const Field F(
    "21888242871839275222246405745257275088548364400416034343698204186575808495"
    "617");
using Elt = typename Field::Elt;
using index_t = Sparse<Field>::index_t;

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

Elt lagrange(corner_t p, size_t logn, const Elt* R) {
  Elt l = F.one();
  for (size_t i = 0; i < logn; i++) {
    if ((p & (corner_t(1) << i)) != 0) {
      F.mul(l, R[i]);
    } else {
      F.mul(l, F.subf(F.one(), R[i]));
    }
  }
  return l;
}

void one_bind3D(corner_t n0, corner_t n1, corner_t n2, size_t logn0,
                size_t logn1, size_t logn2) {
  RandomSlice R0(logn0);
  RandomSlice R1(logn1);
  RandomSlice R2(logn2);
  auto D = Dense<Field>(n0, n2 * n1);
  auto S = Sparse<Field>(n2 * n1 * n0);
  Bogorng<Field> rng(&F);
  Elt s = F.zero();
  index_t i = 0;
  for (corner_t p2 = 0; p2 < n2; p2++) {
    for (corner_t p1 = 0; p1 < n1; p1++) {
      for (corner_t p0 = 0; p0 < n0; p0++) {
        Elt v = rng.next();
        D.v_[p2 * n1 * n0 + p1 * n0 + p0] = v;
        S.c_[i] = Sparse<Field>::corner{.p0 = p0, .p1 = p1, .p2 = p2, .v = v};
        i++;

        F.add(s, F.mulf(v, F.mulf(lagrange(p2, logn2, R2.r_.data()),
                                  F.mulf(lagrange(p1, logn1, R1.r_.data()),
                                         lagrange(p0, logn0, R0.r_.data())))));
      }
    }
  }

  // evaluate S, D at R via successive binding
  D.bind_all(logn0, R0.r_.data(), F);
  S.bind_all(logn0, R0.r_.data(), F);
  D.reshape(n1);
  S.reshape();

  D.bind_all(logn1, R1.r_.data(), F);
  S.bind_all(logn1, R1.r_.data(), F);
  D.reshape(n2);
  S.reshape();

  D.bind_all(logn2, R2.r_.data(), F);
  S.bind_all(logn2, R2.r_.data(), F);
  EXPECT_EQ(D.scalar(), s);
  EXPECT_EQ(S.scalar(), s);
}

void all_bind3D(corner_t n0, corner_t n1, corner_t n2, size_t logn0,
                size_t logn1, size_t logn2) {
  one_bind3D(n0, n1, n2, logn0, logn1, logn2);
  one_bind3D(n1, n2, n0, logn1, logn2, logn0);
  one_bind3D(n2, n0, n1, logn2, logn0, logn1);
  one_bind3D(n2, n1, n0, logn2, logn1, logn0);
  one_bind3D(n1, n0, n2, logn1, logn0, logn2);
  one_bind3D(n0, n2, n1, logn0, logn2, logn1);
}

void one_bind(corner_t n, size_t logn) {
  one_bind3D(1, 1, n, 0, 0, logn);
  one_bind3D(1, n, 1, 0, logn, 0);
  one_bind3D(n, 1, 1, logn, 0, 0);
}

TEST(Affine, Bind) {
  one_bind(corner_t(666), 10);
  one_bind(corner_t(1), 9);
  one_bind(corner_t(255), 9);
  one_bind(corner_t(256), 9);
  one_bind(corner_t(257), 9);
  one_bind(corner_t(467), 9);
  one_bind(corner_t(512), 9);

  all_bind3D(corner_t(7), corner_t(13), corner_t(19), 3, 4, 5);
  all_bind3D(corner_t(8), corner_t(16), corner_t(32), 3, 4, 5);
  all_bind3D(corner_t(8), corner_t(13), corner_t(19), 3, 4, 5);
  all_bind3D(corner_t(8), corner_t(13), corner_t(32), 3, 4, 5);
  all_bind3D(corner_t(13), corner_t(13), corner_t(32), 4, 4, 5);
}

void one_sparse_bind(index_t n, size_t logn) {
  RandomSlice R(logn);
  RandomSlice R2(logn);
  auto S = Sparse<Field>(n);
  auto D = Dense<Field>(1 << logn, 1);
  D.clear(F);
  Bogorng<Field> rng(&F);

  Elt s = F.zero();
  Elt s2 = F.zero();
  for (index_t i = 0; i < n; ++i) {
    corner_t p = corner_t(13 * i);
    Elt r = rng.next();
    D.v_[p] = r;
    S.c_[i] = Sparse<Field>::corner{.p0 = p, .v = r};
    F.add(s, F.mulf(r, lagrange(p, logn, R.r_.data())));
    F.add(s2, F.mulf(r, lagrange(p, logn, R2.r_.data())));
  }
  auto S1 = S.clone_testing_only();
  auto SC = S.clone_testing_only();
  auto DC = D.clone();

  D.bind_all(logn, R.r_.data(), F);
  S.bind_all(logn, R.r_.data(), F);
  EXPECT_EQ(D.scalar(), s);
  EXPECT_EQ(S.scalar(), s);

  DC->bind_all(logn, R.r_.data(), F);
  SC->bind_all(logn, R.r_.data(), F);
  EXPECT_EQ(DC->scalar(), s);
  EXPECT_EQ(SC->scalar(), s);
}

TEST(Affine, SparseBind) {
  one_sparse_bind(index_t(666), 10 + 4);
  one_sparse_bind(index_t(1), 9 + 4);
  for (size_t i = 200; i < 300; i++) {
    one_sparse_bind(index_t(i), 9 + 4);
  }
  one_sparse_bind(index_t(467), 9 + 4);
  one_sparse_bind(index_t(512), 9 + 4);
}

TEST(Affine, Canonicalize) {
  constexpr corner_t n0 = 31, n1 = 47, n2 = 128;
  constexpr corner_t d0 = 2, d1 = 5, d2 = 17;

  // array of expected sums
  uint64_t expected[(n0 + d0 - 1) / d0][(n1 + d1 - 1) / d1]
                   [(n2 + d2 - 1) / d2] = {};

  // create a n0 x n1 x n2 array in the "wrong" order, with duplicates
  auto S = Sparse<Field>(n0 * n1 * n2);

  index_t wr = 0;
  for (corner_t p0 = 0; p0 < n0; p0++) {
    for (corner_t p1 = 0; p1 < n1; p1++) {
      for (corner_t p2 = 0; p2 < n2; p2++) {
        uint64_t v = p0 + 171 * p1 + 333 * p2;
        expected[p0 / d0][p1 / d1][p2 / d2] += v;
        S.c_[wr] = Sparse<Field>::corner{.p0 = p0 / d0,
                                          .p1 = p1 / d1,
                                          .p2 = p2 / d2,
                                          .v = F.of_scalar(v)};
        wr++;
      }
    }
  }

  S.canonicalize(F);

  index_t rd = 0;
  for (corner_t p2 = 0; p2 < (n2 + d2 - 1) / d2; p2++) {
    for (corner_t p1 = 0; p1 < (n1 + d1 - 1) / d1; p1++) {
      for (corner_t p0 = 0; p0 < (n0 + d0 - 1) / d0; p0++) {
        Sparse<Field>::corner want = {
            p0, p1, p2, F.of_scalar(expected[p0][p1][p2])};
        EXPECT_EQ(want, S.c_[rd]);
        rd++;
      }
    }
  }
  EXPECT_EQ(S.n_, rd);
}
}  // namespace
}  // namespace proofs
