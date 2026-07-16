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

#include <cstddef>
#include <memory>
#include <random>

#include "algebra/fp.h"
#include "circuits/compiler/compiler.h"
#include "sumcheck/circuit.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
typedef Fp<1> Field;
const Field F("18446744073709551557");

TEST(Compiler, CanonicalizationSimple) {
  std::unique_ptr<Circuit<Field>> c0;
  std::unique_ptr<Circuit<Field>> c1;
  // generate (a * b) * (c * d) in two different ways

  {
    QuadCircuit<Field> Q(F);

    size_t a = Q.input_wire();
    size_t b = Q.input_wire();
    size_t c = Q.input_wire();
    size_t d = Q.input_wire();
    size_t ab = Q.mul(a, b);
    size_t cd = Q.mul(c, d);
    size_t out = Q.mul(ab, cd);
    Q.output_wire(out, 0);
    c0 = Q.mkcircuit(1);
  }
  {
    QuadCircuit<Field> Q(F);

    size_t a = Q.input_wire();
    size_t b = Q.input_wire();
    size_t c = Q.input_wire();
    size_t d = Q.input_wire();
    size_t cd = Q.mul(c, d);
    size_t ab = Q.mul(b, a);
    // introduce spurious unused results just to confuse things
    // even more
    Q.add(a, b);
    Q.sub(d, ab);
    size_t out = Q.mul(ab, cd);
    Q.output_wire(out, 0);
    c1 = Q.mkcircuit(1);
  }
  for (size_t i = 0; i < sizeof(c0->id); ++i) {
    EXPECT_EQ(c0->id[i], c1->id[i]);
  }
}

constexpr size_t kN = 13;

// A *= B
void matmul_ij(size_t A[kN][kN], const size_t B[kN][kN],
               QuadCircuit<Field> &Q) {
  size_t C[kN][kN];

  // C = A * B
  for (size_t i = 0; i < kN; ++i) {
    for (size_t j = 0; j < kN; ++j) {
      size_t s = Q.mul(A[i][0], B[0][j]);
      for (size_t k = 1; k < kN; ++k) {
        s = Q.add(s, Q.mul(A[i][k], B[k][j]));
      }
      C[i][j] = s;
    }
  }
  // A = C
  for (size_t i = 0; i < kN; ++i) {
    for (size_t j = 0; j < kN; ++j) {
      A[i][j] = C[i][j];
    }
  }
}

void matmul_ji(size_t A[kN][kN], const size_t B[kN][kN],
               QuadCircuit<Field> &Q) {
  size_t C[kN][kN];

  // C = A * B
  for (size_t j = 0; j < kN; ++j) {
    for (size_t i = 0; i < kN; ++i) {
      size_t s = Q.mul(A[i][0], B[0][j]);
      for (size_t k = 1; k < kN; ++k) {
        s = Q.add(s, Q.mul(A[i][k], B[k][j]));
      }
      C[i][j] = s;
    }
  }
  // A = C
  for (size_t i = 0; i < kN; ++i) {
    for (size_t j = 0; j < kN; ++j) {
      A[i][j] = C[i][j];
    }
  }
}

TEST(Compiler, CanonicalizationMatMul) {
  std::mt19937 rng;
  std::uniform_int_distribution<> dist(0, 1);
  size_t pwr = 10;
  std::unique_ptr<Circuit<Field>> c0;

  // Test matrix multiplication in IJ order
  // versus .5 IJ + .5 JI order.
  {
    QuadCircuit<Field> Q(F);
    size_t A[kN][kN], B[kN][kN];
    for (size_t i = 0; i < kN; ++i) {
      for (size_t j = 0; j < kN; ++j) {
        A[i][j] = Q.input_wire();
        B[i][j] = Q.input_wire();
      }
    }

    for (size_t n = 0; n < pwr; ++n) {
      matmul_ij(A, B, Q);
    }

    size_t nout = 0;
    for (size_t i = 0; i < kN; ++i) {
      for (size_t j = 0; j < kN; ++j) {
        Q.output_wire(A[i][j], nout++);
      }
    }

    c0 = Q.mkcircuit(1);
  }

  // repeat a few times since the test is randomized
  for (size_t repeat = 0; repeat < 10; ++repeat) {
    QuadCircuit<Field> Q(F);
    size_t A[kN][kN], B[kN][kN];
    for (size_t i = 0; i < kN; ++i) {
      for (size_t j = 0; j < kN; ++j) {
        A[i][j] = Q.input_wire();
        B[i][j] = Q.input_wire();
      }
    }

    for (size_t n = 0; n < pwr; ++n) {
      if (dist(rng) == 0) {
        matmul_ij(A, B, Q);
      } else {
        matmul_ji(A, B, Q);
      }
    }

    size_t nout = 0;
    for (size_t i = 0; i < kN; ++i) {
      for (size_t j = 0; j < kN; ++j) {
        Q.output_wire(A[i][j], nout++);
      }
    }

    std::unique_ptr<Circuit<Field>> c = Q.mkcircuit(1);

    for (size_t i = 0; i < sizeof(c0->id); ++i) {
      EXPECT_EQ(c0->id[i], c->id[i]);
    }
  }
}

}  // namespace
}  // namespace proofs
