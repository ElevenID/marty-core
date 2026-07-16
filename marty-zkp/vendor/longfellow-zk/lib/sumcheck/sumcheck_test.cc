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

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <utility>
#include <vector>

#include "algebra/bogorng.h"
#include "algebra/fp.h"
#include "arrays/affine.h"
#include "arrays/dense.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/equad.h"
#include "sumcheck/prover.h"
#include "sumcheck/quad.h"
#include "sumcheck/quad_builder.h"
#include "sumcheck/verifier.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = Fp<4>;
static const Field F(
    "11579208923731619542357098500868790785326998466564056403945758400790883467"
    "1663");
using Elt = typename Field::Elt;

Bogorng<Field> rng(&F);
using index_t = Quad<Field>::index_t;
using ecorner = EQuad<Field>::ecorner;
using quad_corner_t = Quad<Field>::quad_corner_t;

/* From https://eprint.iacr.org/2015/1060.pdf Algorithm 7: Complete,
   projective point addition for prime order j-invariant 0 short
   Weierstrass curves E/Fq : y^2 = x^3 + b.

   X3 = (X1 Y2 + X2 Y1)(Y1 Y2 - 3b Z1 Z2) - 3b(Y1 Z2 + Y2 Z1)(X1 Z2 + X2 Z1)
   Y3 = (Y1 Y2 + 3b Z1 Z2)(Y1 Y2 - 3b Z1 Z2) + 9b X1 X2 (X1 Z2 + X2 Z1)
   Z3 = (Y1 Z2 + Y2 Z1)(Y1 Y2 + 3b Z1 Z2) + 3 X1 X2(X1 Y2 + X2 Y1)
*/

constexpr uint64_t b = 7;
Elt kone = F.one(), k3 = F.of_scalar(3), k3b = F.of_scalar(3 * b),
    k9b = F.of_scalar(9 * b);

void addE(Elt* X3, Elt* Y3, Elt* Z3, const Elt& X1, const Elt& Y1,
          const Elt& Z1, const Elt& X2, const Elt& Y2, const Elt& Z2) {
  // after common-subexpression elimination:
  Elt t0 = F.mulf(X2, Y1);
  Elt t1 = F.mulf(X1, Y2);
  Elt t2 = F.addf(t1, t0);
  Elt t3 = F.mulf(Y1, Y2);
  Elt t4 = F.mulf(Z1, Z2);
  Elt t5 = F.mulf(Y1, Z2);
  Elt t6 = F.mulf(Y2, Z1);
  Elt t7 = F.addf(t5, t6);
  Elt t8 = F.mulf(X1, Z2);
  Elt t9 = F.mulf(X2, Z1);
  Elt t10 = F.addf(t8, t9);
  Elt t11 = F.mulf(X1, X2);
  Elt t12 = F.mulf(k3b, t4);
  Elt t13 = F.addf(t3, t12);
  Elt t14 = F.subf(t3, t12);

  *X3 = F.subf(F.mulf(t2, t14), F.mulf(k3b, F.mulf(t7, t10)));
  *Y3 = F.addf(F.mulf(t13, t14), F.mulf(k9b, F.mulf(t11, t10)));
  *Z3 = F.addf(F.mulf(t7, t13), F.mulf(k3, F.mulf(t11, t2)));
}

/* Rewrite as quadratic forms in two layers:

L2:
   t0 = (Y1 Y2 + 3b Z1 Z2)
   t1 = (X1 Y2 + X2 Y1)
   t2 = (Y1 Y2 - 3b Z1 Z2)
   t3 = (Y1 Z2 + Y2 Z1)
   t4 = (X1 Z2 + X2 Z1)
   t5 = X1 X2

L1:
   X3 = t1 t2 - 3b t3 t4
   Y3 = t0 t2 + 9b t5 t4
   Z3 = t3 t0 + 3 t5 t1
*/

// input wires
enum { wX1, wY1, wZ1, wX2, wY2, wZ2 };

// t[i] implicitly i

// output wires
enum {
  wX3,
  wY3,
  wZ3,
};

struct testquad {
  Elt coef;
  size_t g, l, r;
};

std::unique_ptr<Quad<Field>> sparse_of_testquad(size_t n,
                                                const struct testquad* q) {
  auto S = std::make_unique<EQuad<Field>>(n);

  for (size_t i = 0; i < n; i++) {
    auto l = q[i].l, r = q[i].r;

    // canonicalize to l <= r
    if (l > r) {
      std::swap(l, r);
    }

    S->ec_[i] = ecorner{.g = quad_corner_t(q[i].g),
                        .h = {quad_corner_t(r), quad_corner_t(l)},
                        .v = q[i].coef};
  }

  S->canonicalize(F);
  return QuadBuilder<Field>::compress(S.get(), F);
}

#define NELEM(x) (sizeof(x) / sizeof(x[0]))

std::unique_ptr<Quad<Field>> addE_quad0() {
  testquad Q[] = {
      // X3 = t1 t2 - 3b t3 t4
      {kone, wX3, 1, 2},
      {F.negf(k3b), wX3, 3, 4},

      // Y3 = t0 t2 + 9b t5 t4
      {kone, wY3, 0, 2},
      {k9b, wY3, 5, 4},

      // Z3 = t3 t0 + 3 t5 t1
      {kone, wZ3, 3, 0},
      {k3, wZ3, 5, 1},
  };
  return sparse_of_testquad(NELEM(Q), Q);
}

std::unique_ptr<Quad<Field>> addE_quad1() {
  testquad Q[] = {
      // t0 = (Y1 Y2 + 3b Z1 Z2)
      {kone, 0, wY1, wY2},
      {k3b, 0, wZ1, wZ2},

      // t1 = (X1 Y2 + X2 Y1)
      {kone, 1, wX1, wY2},
      {kone, 1, wX2, wY1},

      // t2 = (Y1 Y2 - 3b Z1 Z2)
      {kone, 2, wY1, wY2},
      {F.negf(k3b), 2, wZ1, wZ2},

      // t3 = (Y1 Z2 + Y2 Z1)
      {kone, 3, wY1, wZ2},
      {kone, 3, wY2, wZ1},

      // t4 = (X1 Z2 + X2 Z1)
      {kone, 4, wX1, wZ2},
      {kone, 4, wX2, wZ1},

      // t5 = X1 X2
      {kone, 5, wX1, wX2},
  };
  return sparse_of_testquad(NELEM(Q), Q);
}

std::unique_ptr<Circuit<Field>> addE_circuit(size_t logc, corner_t nc) {
  std::unique_ptr<Circuit<Field>> c = std::make_unique<Circuit<Field>>();
  *c = Circuit<Field>{
      .nv = 3,  // outputs
      .logv = 2,
      .nc = nc,
      .logc = logc,
      .nl = 2,
  };
  c->l.push_back(Layer<Field>{.nw = 6, .logw = 3, .quad = addE_quad0()});
  c->l.push_back(Layer<Field>{.nw = 6, .logw = 3, .quad = addE_quad1()});

  return c;
}

TEST(Sumcheck, EvalCircuit) {
  size_t logc = 8;
  corner_t nc = 209;
  auto CIRCUIT = addE_circuit(logc, nc);
  auto W = std::make_unique<Dense<Field>>(nc, 6);
  for (corner_t i = 0; i < W->n0_ * W->n1_; ++i) {
    W->v_[i] = rng.next();
  }
  Prover<Field>::inputs in;
  Prover<Field> prover(F);
  auto Wclone = W->clone();
  const Dense<Field>* Wsave = &*Wclone;
  auto V = prover.eval_circuit(&in, CIRCUIT.get(), std::move(Wclone), F);

  EXPECT_EQ(Wclone.get(), nullptr);  // moved to in(nl-1)
  EXPECT_EQ(in[1].get(), Wsave);

  for (corner_t i = 0; i < nc; ++i) {
    Elt Xw, Yw, Zw;
    addE(&Xw, &Yw, &Zw, (W->v_[i + nc * 0]), (W->v_[i + nc * 1]),
         (W->v_[i + nc * 2]), (W->v_[i + nc * 3]), (W->v_[i + nc * 4]),
         (W->v_[i + nc * 5]));

    Elt X3 = V->v_[i + nc * 0], Y3 = (V->v_[i + nc * 1]),
        Z3 = (V->v_[i + nc * 2]);
    EXPECT_EQ(X3, Xw);
    EXPECT_EQ(Y3, Yw);
    EXPECT_EQ(Z3, Zw);
  }

  // create a proof for the side-effect of invoking the constructor/destructor
  // to detect memory leaks
  Proof<Field> P(CIRCUIT->nl);
}

void one_test_sumcheck_without_com(const Circuit<Field>* CIRCUIT) {
  auto nc = CIRCUIT->nc;
  auto nl = CIRCUIT->nl;

  // random inputs
  auto Wprover = std::make_unique<Dense<Field>>(nc, CIRCUIT->l[nl - 1].nw);
  for (corner_t i = 0; i < Wprover->n0_ * Wprover->n1_; ++i) {
    Wprover->v_[i] = rng.next();
  }
  auto Wverifier = Wprover->clone();

  Proof<Field> proof(CIRCUIT->nl);
  Prover<Field>::inputs in;
  Prover<Field> prover(F);
  auto V = prover.eval_circuit(&in, CIRCUIT, std::move(Wprover), F);

  Transcript tsp((uint8_t *)"test", 4);
  prover.prove(&proof, nullptr, CIRCUIT, in, tsp);

  const char* why;
  Transcript tsv((uint8_t *)"test", 4);
  bool ok = Verifier<Field>::verify(&why, CIRCUIT, &proof, std::move(V),
                                    std::move(Wverifier), tsv, F);
  EXPECT_EQ(ok, true);
  EXPECT_EQ(why, "ok");
}

void one_test_sumcheck(const Circuit<Field>* CIRCUIT) {
  one_test_sumcheck_without_com(CIRCUIT);
}

TEST(Sumcheck, SumcheckAddE) {
  auto CIRCUIT = addE_circuit(8, corner_t(177));
  one_test_sumcheck(CIRCUIT.get());
}

TEST(Sumcheck, SumcheckAddEOneCopy) {
  auto CIRCUIT = addE_circuit(0, corner_t(1));
  one_test_sumcheck(CIRCUIT.get());
}

// ------------------------------------------------------------
// tests with random circuits
size_t around(size_t n) { return n + (std::rand() % n); }
quad_corner_t rand_corner(size_t n) { return quad_corner_t(std::rand()) % n; }

std::unique_ptr<Quad<Field>> random_quad(index_t n, corner_t nv, corner_t nw) {
  auto S = std::make_unique<EQuad<Field>>(n);
  for (index_t i = 0; i < n; i++) {
    S->ec_[i] = ecorner{
        .g = rand_corner(nv),
        .h = {rand_corner(nw), rand_corner(nw)},
        .v = rng.next(),
    };
  }
  S->canonicalize(F);
  return QuadBuilder<Field>::compress(S.get(), F);
}

std::unique_ptr<Circuit<Field>> random_circuit() {
  std::unique_ptr<Circuit<Field>> CIRCUIT = std::make_unique<Circuit<Field>>();
  *CIRCUIT = Circuit<Field>{
      .nv = around(7),
      .logv = 4,
      .nc = around(12),
      .logc = 5,
      .nl = around(5),
  };
  size_t nv = CIRCUIT->nv;
  for (size_t ly = 0; ly < CIRCUIT->nl; ++ly) {
    corner_t nw = around(20);
    CIRCUIT->l.push_back(Layer<Field>{
        .nw = nw,
        .logw = 6,
        .quad = random_quad(around(300), nv, nw),
    });
    nv = nw;  // outputs of next layer == inputs of this layer
  }
  return CIRCUIT;
}

TEST(Sumcheck, RandomCircuit) {
  for (size_t i = 0; i < 10; ++i) {
    auto CIRCUIT = random_circuit();
    one_test_sumcheck(CIRCUIT.get());
  }
}
}  // namespace
}  // namespace proofs
