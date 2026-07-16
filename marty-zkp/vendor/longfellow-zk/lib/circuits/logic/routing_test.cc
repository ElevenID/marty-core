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

#include "circuits/logic/routing.h"

#include <stddef.h>

#include <vector>

#include "algebra/fp.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp<1>;
using CompilerBackend = CompilerBackend<Field>;
using LogicCircuit = Logic<Field, CompilerBackend>;
using BitWC = LogicCircuit::BitW;
using EltWC = LogicCircuit::EltW;

using EvaluationBackend = EvaluationBackend<Field>;
using Logic = Logic<Field, EvaluationBackend>;
using BitW = Logic::BitW;
using EltW = Logic::EltW;

template <size_t N>
void expect_vequal(const Logic& L, const Logic::bitvec<N>& a,
                   const Logic::bitvec<N>& b) {
  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(L.eval(a[i]), L.eval(b[i]));
  }
}

static void one_test(size_t logn, size_t n, size_t k, size_t shift,
                     size_t unroll, bool unshift, const Logic& L) {
  const Routing<Logic> R(L);
  constexpr size_t W = 3;
  typedef Logic::bitvec<W> bv;

  // "randomize" the default
  BitW ldefault = L.bit((logn ^ n ^ k ^ shift ^ unroll) & 1);
  EltW bdefault = L.konst(12345678);
  bv bvdefault = L.vbit<W>(12345678);

  std::vector<BitW> lA(n);
  std::vector<EltW> bA(n);
  std::vector<bv> bvA(n);
  for (size_t i = 0; i < n; ++i) {
    // random-ish bit
    lA[i] = L.bit((i ^ (i >> 2) ^ (i >> 5)) & 1);
    bA[i] = L.konst(i + 42);
    bvA[i] = L.vbit<W>(i + 42);
  }

  std::vector<BitW> lwant(k), lgot(k);
  std::vector<EltW> bwant(k), bgot(k);
  std::vector<bv> bvwant(k), bvgot(k);

  // The circuit takes logn bits of shift amount, so it
  // shifts by (SHIFT mod 2**LOGN)
  size_t real_shift = shift % (1 << logn);
  if (unshift) {
    for (size_t i = 0; i < k; ++i) {
      if (i >= real_shift && i < n + real_shift) {
        lwant[i] = lA[i - real_shift];
        bwant[i] = bA[i - real_shift];
        bvwant[i] = bvA[i - real_shift];
      } else {
        lwant[i] = ldefault;
        bwant[i] = bdefault;
        bvwant[i] = bvdefault;
      }
    }
  } else {
    for (size_t i = 0; i < k; ++i) {
      if (i + real_shift < n) {
        lwant[i] = lA[i + real_shift];
        bwant[i] = bA[i + real_shift];
        bvwant[i] = bvA[i + real_shift];
      } else {
        lwant[i] = ldefault;
        bwant[i] = bdefault;
        bvwant[i] = bvdefault;
      }
    }
  }

  std::vector<BitW> shiftbits(logn);
  L.bits(logn, shiftbits.data(), shift);

  if (unshift) {
    R.unshift(logn, shiftbits.data(), k, lgot.data(), n, lA.data(), ldefault,
              unroll);
    R.unshift(logn, shiftbits.data(), k, bgot.data(), n, bA.data(), bdefault,
              unroll);
    R.unshift(logn, shiftbits.data(), k, bvgot.data(), n, bvA.data(), bvdefault,
              unroll);
  } else {
    R.shift(logn, shiftbits.data(), k, lgot.data(), n, lA.data(), ldefault,
            unroll);
    R.shift(logn, shiftbits.data(), k, bgot.data(), n, bA.data(), bdefault,
            unroll);
    R.shift(logn, shiftbits.data(), k, bvgot.data(), n, bvA.data(), bvdefault,
            unroll);
  }
  for (size_t i = 0; i < k; ++i) {
    EXPECT_EQ(L.eval(lgot[i]), L.eval(lwant[i]));
    EXPECT_EQ(bgot[i], bwant[i]);
    expect_vequal(L, bvgot[i], bvwant[i]);
  }
}

TEST(Routing, Simple) {
  const Field F("18446744073709551557");
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);

  // test small cases exhaustively
  for (size_t logn = 1; logn <= 5; ++logn) {
    for (size_t n = 1; n <= 16; ++n) {
      for (size_t k = 1; k <= 16; ++k) {
        for (size_t shift = 0; shift <= 16; ++shift)
          for (size_t unroll = 1; unroll <= 8; ++unroll) {
            one_test(logn, n, k, shift, unroll, true, L);
            one_test(logn, n, k, shift, unroll, false, L);
          }
      }
    }
  }

  // test large cases more sparsely
  size_t nn = 1;
  for (size_t logn = 1; logn <= 8; ++logn) {
    for (; nn <= (1 << logn); nn += 1 + (nn / 7)) {
      for (size_t k = 1; k <= nn; k += 1 + (k / 5)) {
        for (size_t shift = 0; shift < nn; shift += 1 + (shift / 3)) {
          for (size_t unroll = 1; unroll <= logn; ++unroll) {
            one_test(logn, nn, k, shift, unroll, true, L);
            one_test(logn, nn, k, shift, unroll, false, L);
          }
        }
      }
    }
  }
}

TEST(Routing, EltCircuitSize) {
  const Field F("18446744073709551557");
  set_log_level(INFO);
  for (size_t logn = 0; logn <= 10; ++logn) {
    for (size_t unroll = 1; unroll <= logn; unroll *= 2) {
      for (size_t unshift = 0; unshift < 2; ++unshift) {
        size_t n = (1 << logn), k = (1 << logn);
        QuadCircuit<Field> Q(F);
        const CompilerBackend cbk(&Q);
        const LogicCircuit LC(&cbk, F);
        const Routing<LogicCircuit> RC(LC);
        std::vector<BitWC> amount(logn);
        std::vector<EltWC> a(n);
        std::vector<EltWC> b(k);
        for (size_t i = 0; i < logn; ++i) {
          amount[i] = LC.input();
        }
        for (size_t i = 0; i < n; ++i) {
          a[i] = LC.eltw_input();
        }
        if (unshift) {
          RC.unshift(logn, amount.data(), k, b.data(), n, a.data(), LC.konst(0),
                     unroll);
        } else {
          RC.shift(logn, amount.data(), k, b.data(), n, a.data(), LC.konst(0),
                   unroll);
        }
        for (size_t i = 0; i < k; ++i) {
          LC.output(b[i], i);
        }

        auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
        dump_info(unshift ? "unshift_Elt" : "shift_Elt", n, k, unroll, Q);
      }
    }
  }
}

TEST(Routing, BitCircuitSize) {
  const Field F("18446744073709551557");
  set_log_level(INFO);
  for (size_t logn = 0; logn <= 10; ++logn) {
    for (size_t unroll = 1; unroll <= logn; unroll *= 2) {
      for (size_t unshift = 0; unshift < 2; ++unshift) {
        size_t n = (1 << logn), k = (1 << logn);
        QuadCircuit<Field> Q(F);
        const CompilerBackend cbk(&Q);
        const LogicCircuit LC(&cbk, F);
        const Routing<LogicCircuit> RC(LC);
        std::vector<BitWC> amount(logn);
        std::vector<BitWC> a(n);
        std::vector<BitWC> b(k);
        for (size_t i = 0; i < logn; ++i) {
          amount[i] = LC.input();
        }
        for (size_t i = 0; i < n; ++i) {
          a[i] = LC.input();
        }
        if (unshift) {
          RC.unshift(logn, amount.data(), k, b.data(), n, a.data(), LC.bit(0),
                     unroll);
        } else {
          RC.shift(logn, amount.data(), k, b.data(), n, a.data(), LC.bit(0),
                   unroll);
        }
        for (size_t i = 0; i < k; ++i) {
          LC.output(b[i], i);
        }

        auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
        dump_info(unshift ? "unshift_bit" : "shift_bit", n, k, unroll, Q);
      }
    }
  }
}
}  // namespace
}  // namespace proofs
