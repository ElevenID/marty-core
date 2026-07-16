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

#include <stddef.h>

#include <vector>

#include "algebra/bogorng.h"
#include "algebra/fp.h"
#include "algebra/fp2.h"
#include "algebra/nussbaumer.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field0 = Fp<1>;
// 2^61-1
static const Field0 F0("2305843009213693951");

using Field = Fp2<Field0>;
using Elt = Field::Elt;
static const Field F(F0);

static void ref_negacyclic(size_t n, Elt z[/*n*/], const Elt x[/*n*/],
                           const Elt y[/*n*/]) {
  for (size_t k = 0; k < n; ++k) {
    Elt s = F.zero();
    for (size_t j = 0; j <= k; ++j) {
      F.add(s, F.mulf(x[j], y[k - j]));
    }
    for (size_t j = k + 1; j < n; ++j) {
      F.sub(s, F.mulf(x[j], y[n + k - j]));
    }
    z[k] = s;
  }
}

static void ref_linear(size_t n, Elt z[/*2*n*/], const Elt x[/*n*/],
                       const Elt y[/*n*/]) {
  // Really k<2*n-1, but we round up for consistency.  z[2*n-1] is
  // set to 0.
  for (size_t k = 0; k < 2 * n; ++k) {
    Elt s = F.zero();
    for (size_t j = 0; j <= k; ++j) {
      if (j < n && (k - j) < n) {
        F.add(s, F.mulf(x[j], y[k - j]));
      }
    }
    z[k] = s;
  }
}

// "middle-product" variant z[k] = sum_j x[n+k-j]*y[j]
static void ref_middle(size_t n, Elt z[/*n*/], const Elt x[/*2*n*/],
                       const Elt y[/*n*/]) {
  for (size_t k = 0; k < n; ++k) {
    Elt s = F.zero();
    for (size_t j = 0; j < n; ++j) {
      F.add(s, F.mulf(x[n + k - j], y[j]));
    }
    z[k] = s;
  }
}

constexpr size_t max_n = 1u << 12;

TEST(Nussbaumer, NegaCyclic) {
  Bogorng<Field> rng(&F);

  for (size_t n = 1; n < max_n; n *= 2) {
    std::vector<Elt> x(n);
    std::vector<Elt> y(n);
    std::vector<Elt> z(n);
    std::vector<Elt> zr(n);
    for (size_t i = 0; i < n; ++i) {
      x[i] = rng.next();
      y[i] = rng.next();
    }
    Nussbaumer<Field>::negacyclic(n, z.data(), x.data(), y.data(), F);
    ref_negacyclic(n, zr.data(), x.data(), y.data());
    for (size_t i = 0; i < n; ++i) {
      EXPECT_EQ(z[i], zr[i]);
    }
  }
}

TEST(Nussbaumer, Linear) {
  Bogorng<Field> rng(&F);
  for (size_t n = 1; n < max_n; n *= 2) {
    std::vector<Elt> x(n);
    std::vector<Elt> y(n);
    std::vector<Elt> z(2 * n);
    std::vector<Elt> zr(2 * n);
    for (size_t i = 0; i < n; ++i) {
      x[i] = rng.next();
      y[i] = rng.next();
    }
    ref_linear(n, zr.data(), x.data(), y.data());
    Nussbaumer<Field>::linear(n, z.data(), x.data(), y.data(), F);
    for (size_t i = 0; i < 2 * n; ++i) {
      EXPECT_EQ(z[i], zr[i]);
    }
  }
}

TEST(Nussbaumer, Middle) {
  Bogorng<Field> rng(&F);
  for (size_t n = 1; n < max_n; n *= 2) {
    std::vector<Elt> x(2 * n);
    std::vector<Elt> y(n);
    std::vector<Elt> z(n);
    std::vector<Elt> zr(n);
    for (size_t i = 0; i < n; ++i) {
      x[i] = rng.next();
      x[i + n] = rng.next();
      y[i] = rng.next();
    }
    ref_middle(n, zr.data(), x.data(), y.data());
    Nussbaumer<Field>::middle(n, z.data(), x.data(), y.data(), F);
    for (size_t i = 0; i < n; ++i) {
      EXPECT_EQ(z[i], zr[i]);
    }
  }
}

}  // namespace
}  // namespace proofs
