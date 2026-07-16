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

#include "circuits/logic/memcmp.h"

#include <stddef.h>
#include <stdint.h>

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

using Field = Fp<4, true>;
const Field F("18446744073709551557");

using EvaluationBackend = EvaluationBackend<Field>;

// test sequence
static size_t next(size_t a) {
  // test 0, 1, 2, 3, 4, 8, 16, 32, ..., 128
  if (a < 4)
    return a + 1;
  else
    return 2 * a;
}

TEST(Memcmp, Simple) {
  using Logic = Logic<Field, EvaluationBackend>;
  using v8 = Logic::v8;
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  const Memcmp<Logic> M(L);
  constexpr size_t n = 3;

  v8 a[n], b[n];

  for (size_t a0 = 0; a0 < 256; a0 = next(a0)) {
    for (size_t b0 = 0; b0 < 256; b0 = next(b0)) {
      for (size_t a1 = 0; a1 < 256; a1 = next(a1)) {
        for (size_t b1 = 0; b1 < 256; b1 = next(b1)) {
          for (size_t a2 = 0; a2 < 256; a2 = next(a2)) {
            for (size_t b2 = 0; b2 < 256; b2 = next(b2)) {
              a[0] = L.vbit<8>(a0);
              b[0] = L.vbit<8>(b0);
              a[1] = L.vbit<8>(a1);
              b[1] = L.vbit<8>(b1);
              a[2] = L.vbit<8>(a2);
              b[2] = L.vbit<8>(b2);
              // memcmp input is big-endian
              size_t xa = (a0 << 16) + (a1 << 8) + a2;
              size_t xb = (b0 << 16) + (b1 << 8) + b2;
              EXPECT_EQ(L.eval(M.lt(n, a, b)), L.konst(xa < xb));
              EXPECT_EQ(L.eval(M.leq(n, a, b)), L.konst(xa <= xb));
            }
          }
        }
      }
    }
  }
}

TEST(Memcmp, Date) {
  using Logic = Logic<Field, EvaluationBackend>;
  using v8 = Logic::v8;
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  const Memcmp<Logic> M(L);

  constexpr size_t date_len = 20;
  constexpr size_t num_tests = 3;

  // keep tests in this order: dates[0] < dates[1] < dates[2]
  uint8_t dates[num_tests][date_len] = {
      // 2023-10-11T13:18:15Z
      {'2', '0', '2', '3', '-', '1', '0', '-', '1', '1',
       'T', '1', '3', ':', '1', '8', ':', '1', '5', 'Z'},
      // 2023-10-11T13:18:16Z
      {'2', '0', '2', '3', '-', '1', '0', '-', '1', '1',
       'T', '1', '3', ':', '1', '8', ':', '1', '6', 'Z'},
      // 2024-10-11T13:18:15Z
      {'2', '0', '2', '4', '-', '1', '0', '-', '1', '1',
       'T', '1', '3', ':', '1', '8', ':', '1', '5', 'Z'},
  };

  v8 vdates[num_tests][date_len];
  for (size_t i = 0; i < date_len; ++i) {
    for (size_t d = 0; d < num_tests; ++d) {
      vdates[d][i] = L.vbit<8>(dates[d][i]);
    }
  }

  for (size_t d1 = 0; d1 < 3; ++d1) {
    for (size_t d2 = 0; d2 < 3; ++d2) {
      EXPECT_EQ(L.eval(M.lt(date_len, vdates[d1], vdates[d2])),
                L.konst(d1 < d2 ? 1 : 0));
      EXPECT_EQ(L.eval(M.leq(date_len, vdates[d1], vdates[d2])),
                L.konst(d1 <= d2 ? 1 : 0));
    }
  }
}

TEST(Memcmp, size) {
  set_log_level(INFO);
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;

  QuadCircuit<Field> Q(F);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);
  typedef Memcmp<LogicCircuit> memc;

  const memc MEMC(LC);

  std::vector<LogicCircuit::v8> a(20), b(20);

  for (size_t i = 0; i < 20; ++i) {
    a[i] = LC.vinput<8>();
    b[i] = LC.vinput<8>();
  }

  LC.assert1(MEMC.lt(20, a.data(), b.data()));

  auto CIRCUIT = Q.mkcircuit(1);
  dump_info<Field>("memcmp lt", Q);
}
}  // namespace
}  // namespace proofs
