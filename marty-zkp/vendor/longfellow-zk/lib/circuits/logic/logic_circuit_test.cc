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

#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
typedef GF2_128<> Field;
const Field F;

std::unique_ptr<Circuit<Field>> mk_add_circuit(size_t w, size_t nc,
                                               size_t kind) {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using BitWC = LogicCircuit::BitW;

  QuadCircuit<Field> Q(F);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);

  std::vector<BitWC> a(w);
  std::vector<BitWC> b(w);
  std::vector<BitWC> c(w + 1);
  for (size_t i = 0; i < w; ++i) {
    a[i] = LC.input();
  }
  for (size_t i = 0; i < w; ++i) {
    b[i] = LC.input();
  }
  BitWC carry;
  const char* name;
  switch (kind) {
    case 0:
      carry = LC.ripple_carry_add(w, c.data(), a.data(), b.data());
      name = "ripple_carry_add";
      break;
    case 1:
      carry = LC.ripple_carry_sub(w, c.data(), a.data(), b.data());
      name = "ripple_carry_sub";
      break;
    case 2:
      carry = LC.parallel_prefix_add(w, c.data(), a.data(), b.data());
      name = "parallel_prefix_add";
      break;
    case 3:
      carry = LC.parallel_prefix_sub(w, c.data(), a.data(), b.data());
      name = "parallel_prefix_sub";
      break;
  }
  for (size_t i = 0; i < w; ++i) {
    LC.output(c[i], i);
  }
  LC.output(carry, w);

  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info<Field>(name, w, Q);

  return CIRCUIT;
}

TEST(Logic_Circuit, AddSub) {
  using EvaluationBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvaluationBackend>;
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  set_log_level(INFO);
  constexpr size_t nc = 1;

  for (size_t kind = 0; kind < 4; ++kind) {
    // for all widths w + w -> w+1
    for (size_t w = 1; w <= 8; ++w) {
      auto CIRCUIT = mk_add_circuit(w, nc, kind);

      for (size_t a = 0; a < (1 << w); ++a) {
        for (size_t b = 0; b < (1 << w); ++b) {
          auto W = std::make_unique<Dense<Field>>(
              nc, /*constant one*/ 1 + /*a*/ w + /*b*/ w);
          W->v_[0] = F.one();
          for (size_t i = 0; i < w; ++i) {
            W->v_[1 + i] = L.eval(L.bit((a >> i) & 1)).elt();
            W->v_[w + 1 + i] = L.eval(L.bit((b >> i) & 1)).elt();
          }

          Prover<Field>::inputs in;
          Prover<Field> prover(F);
          auto V = prover.eval_circuit(&in, CIRCUIT.get(), W->clone(), F);

          size_t c = (kind & 1) ? (a - b) : (a + b);
          for (size_t i = 0; i < w + 1; ++i) {
            EXPECT_EQ(V->v_[i], L.eval(L.bit((c >> i) & 1)).elt());
          }
        }
      }
    }
  }
}

TEST(Logic_Circuit, AddSubSize) {
  set_log_level(INFO);
  constexpr size_t nc = 1;

  for (size_t kind = 0; kind < 4; ++kind) {
    for (size_t w = 1; w <= 64; ++w) {
      // for the side-effect of logging the circuit size
      (void)mk_add_circuit(w, nc, kind);
    }
  }
}

std::unique_ptr<Circuit<Field>> mk_multiplier_circuit(size_t w, size_t nc) {
  QuadCircuit<Field> Q(F);
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using BitWC = LogicCircuit::BitW;

  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);

  std::vector<BitWC> a(w);
  std::vector<BitWC> b(w);
  std::vector<BitWC> c(2 * w);
  for (size_t i = 0; i < w; ++i) {
    a[i] = LC.input();
  }
  for (size_t i = 0; i < w; ++i) {
    b[i] = LC.input();
  }
  LC.multiplier(w, c.data(), a.data(), b.data());
  for (size_t i = 0; i < 2 * w; ++i) {
    LC.output(c[i], i);
  }
  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info<Field>("multiplier", w, Q);
  return CIRCUIT;
}

TEST(Logic_Circuit, Multiplier) {
  using EvaluationBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvaluationBackend>;
  using BitW = Logic::BitW;

  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  set_log_level(INFO);
  constexpr size_t nc = 1;

  BitW ab[64], bb[64], cb[128];

  // for all widths w x w -> 2w
  for (size_t w = 1; w <= 8; ++w) {
    log(INFO, "w: %zu", w);
    auto CIRCUIT = mk_multiplier_circuit(w, nc);

    // Test 1: verify the circuit for all w-bit boolean inputs
    // a and b
    for (size_t a = 0; a < (1 << w); ++a) {
      for (size_t b = 0; b < (1 << w); ++b) {
        auto W = std::make_unique<Dense<Field>>(
            nc, /*constant one*/ 1 + /*a*/ w + /*b*/ w);
        W->v_[0] = F.one();
        for (size_t i = 0; i < w; ++i) {
          W->v_[1 + i] = L.eval(L.bit((a >> i) & 1)).elt();
          W->v_[w + 1 + i] = L.eval(L.bit((b >> i) & 1)).elt();
          ab[i] = BitW(L.konst((a >> i) & 1), F);
          bb[i] = BitW(L.konst((b >> i) & 1), F);
        }

        Prover<Field>::inputs in;
        Prover<Field> prover(F);
        auto V = prover.eval_circuit(&in, CIRCUIT.get(), W->clone(), F);
        L.multiplier(w, cb, ab, bb);

        size_t c = a * b;
        size_t outputw = (w == 1) ? 1 : 2 * w;
        // For the special case of w == 1, the assert_bit checks add outputs.
        if (w > 1) { EXPECT_EQ(outputw, V->n1_); }
        for (size_t i = 0; i < outputw; ++i) {
          EXPECT_EQ(V->v_[i], L.eval(L.bit((c >> i) & 1)).elt());
          EXPECT_EQ(V->v_[i], L.eval(cb[i]).elt());
        }
      }
    }
  }
}

TEST(Logic_Circuit, Comparison) {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using BitWC = LogicCircuit::BitW;

  set_log_level(INFO);
  for (size_t kind = 0; kind < 3; ++kind) {
    for (size_t n = 1; n <= 64; ++n) {
      QuadCircuit<Field> Q(F);
      const CompilerBackend cbk(&Q);
      const LogicCircuit LC(&cbk, F);

      std::vector<BitWC> a(n), b(n);

      for (size_t i = 0; i < n; ++i) {
        a[i] = LC.input();
        b[i] = LC.input();
      }

      BitWC r;
      const char* name;
      switch (kind) {
        case 0:
          name = "eq";
          r = LC.eq(n, a.data(), b.data());
          break;
        case 1:
          name = "lt";
          r = LC.lt(n, a.data(), b.data());
          break;
        case 2:
          name = "leq";
          r = LC.leq(n, a.data(), b.data());
          break;
      }

      LC.output(r, 0);

      auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
      dump_info<Field>(name, n, Q);
    }
  }
}

template <class Field>
void mk_gf2_polymul(size_t w, const Field& f) {
  QuadCircuit<Field> Q(f);
  const CompilerBackend<Field> cbk(&Q);
  using LogicCircuit = Logic<Field, CompilerBackend<Field>>;
  const LogicCircuit LC(&cbk, f);
  typename LogicCircuit::v128 a, b;
  typename LogicCircuit::v256 c2;
  for (size_t i = 0; i < w; ++i) {
    a[i] = LC.input();
    b[i] = LC.input();
  }
  LC.gf2_polynomial_multiplier_karat(w, c2.data(), a.data(), b.data());
  for (size_t i = 0; i < 2 * w; ++i) {
    LC.output(c2[i], i);
  }
  auto CIRCUIT = Q.mkcircuit(1);
  dump_info<Field>("GF2^k mul", w, Q);
}

TEST(Logic_Circuit, GF2k_PolymultSize_p256) {
  mk_gf2_polymul<Fp256Base>(128, p256_base);
  mk_gf2_polymul<Fp256Base>(64, p256_base);
  mk_gf2_polymul<Fp256Base>(32, p256_base);
  mk_gf2_polymul<Fp256Base>(16, p256_base);
  mk_gf2_polymul<Fp256Base>(8, p256_base);
  mk_gf2_polymul<Fp256Base>(4, p256_base);
}

TEST(Logic_Circuit, GF2k_PolymultSizeSize) { mk_gf2_polymul<Field>(128, F); }

template <class Field>
void mk_gf2_modmul(size_t w, const Field& f) {
  QuadCircuit<Field> Q(f);
  const CompilerBackend<Field> cbk(&Q);
  using LogicCircuit = Logic<Field, CompilerBackend<Field>>;
  const LogicCircuit LC(&cbk, f);
  typename LogicCircuit::v128 a = LC.template vinput<128>(),
                              b = LC.template vinput<128>(), c;
  LC.gf2_128_mul(c, a, b);
  LC.voutput(c, 0);
  auto CIRCUIT = Q.mkcircuit(1);
  dump_info<Field>("GF_2^128 modmul", w, Q);
}

TEST(Logic_Circuit, GF2k_ModmulSize_p256) {
  mk_gf2_modmul<Fp256Base>(128, p256_base);
}

TEST(Logic_Circuit, GF2k_ModmulSize) { mk_gf2_modmul<Field>(128, F); }


}  // namespace
}  // namespace proofs
