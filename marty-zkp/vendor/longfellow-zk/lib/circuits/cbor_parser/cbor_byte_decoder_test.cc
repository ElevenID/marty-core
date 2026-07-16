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

#include "circuits/cbor_parser/cbor_byte_decoder.h"

#include <stddef.h>

#include "algebra/fp.h"
#include "circuits/logic/counter.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void test_decode_one_v8(const Field& F) {
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using CounterL = Counter<Logic>;

  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const CounterL CTR(L);

  using CborBD = CborByteDecoder<Logic>;
  const CborBD CBORBD(L);
  for (size_t type = 0; type < 8; ++type) {
    for (size_t count = 0; count < 32; ++count) {
      size_t v_as_size_t = (type << 5) | count;
      typename Logic::v8 v = L.template vbit<8>(v_as_size_t);
      auto ds = CBORBD.decode_one_v8(v);

      bool atomp = (type == 0) || (type == 1);
      bool stringp = (type == 2) || (type == 3);
      bool arrayp = (type == 4);
      bool mapp = (type == 5);
      bool itemsp = arrayp || mapp;
      bool tagp = (type == 6);
      bool specialp = (type == 7);
      bool simple_specialp = specialp && (20 <= count && count < 24);
      bool count0_23 = (count < 24);
      bool count24_27 = (24 <= count) && (count < 28);
      bool count24 = (count == 24);
      bool count25 = (count == 25);
      bool count26 = (count == 26);
      bool count27 = (count == 27);

      bool length_plus_next_v8 = false;
      bool count_is_next_v8 = false;
      bool invalid = false;
      size_t length = ~0;  // bogus
      size_t count_as_counter = count;
      if (atomp || tagp) {
        if (count0_23) {
          length = 1;
        } else if (count24) {
          length = 1 + 1;
        } else if (count25) {
          length = 1 + 2;
        } else if (count26) {
          length = 1 + 4;
        } else if (count27) {
          length = 1 + 8;
        } else {
          invalid = true;
        }
      } else if (itemsp) {
        if (count0_23) {
          length = 1;
        } else if (count24) {
          length = 2;
          count_is_next_v8 = true;
        } else {
          invalid = true;
        }
      } else if (stringp) {
        if (count0_23) {
          length = 1 + count;
        } else if (count24) {
          length = 2;
          length_plus_next_v8 = true;
        } else {
          invalid = true;
        }
      } else if (simple_specialp) {
        length = 1;
      } else {
        invalid = true;
      }

      EXPECT_EQ(L.eval(ds.atomp), L.eval(L.bit(atomp)));
      EXPECT_EQ(L.eval(ds.itemsp), L.eval(L.bit(itemsp)));
      EXPECT_EQ(L.eval(ds.stringp), L.eval(L.bit(stringp)));
      EXPECT_EQ(L.eval(ds.arrayp), L.eval(L.bit(arrayp)));
      EXPECT_EQ(L.eval(ds.mapp), L.eval(L.bit(mapp)));
      EXPECT_EQ(L.eval(ds.tagp), L.eval(L.bit(tagp)));
      EXPECT_EQ(L.eval(ds.specialp), L.eval(L.bit(specialp)));
      EXPECT_EQ(L.eval(ds.simple_specialp), L.eval(L.bit(simple_specialp)));

      EXPECT_EQ(L.eval(ds.count0_23), L.eval(L.bit(count0_23)));
      EXPECT_EQ(L.eval(ds.count24_27), L.eval(L.bit(count24_27)));
      EXPECT_EQ(L.eval(ds.count24), L.eval(L.bit(count24)));
      EXPECT_EQ(L.eval(ds.count25), L.eval(L.bit(count25)));
      EXPECT_EQ(L.eval(ds.count26), L.eval(L.bit(count26)));
      EXPECT_EQ(L.eval(ds.count27), L.eval(L.bit(count27)));
      EXPECT_EQ(L.eval(ds.length_plus_next_v8),
                L.eval(L.bit(length_plus_next_v8)));
      EXPECT_EQ(L.eval(ds.count_is_next_v8), L.eval(L.bit(count_is_next_v8)));
      EXPECT_EQ(L.eval(ds.invalid), L.eval(L.bit(invalid)));

      if (!invalid) {
        // the length is don't care unless valid
        EXPECT_EQ(ds.length.e, CTR.as_counter(length).e);
      }

      EXPECT_EQ(ds.count_as_counter.e, CTR.as_counter(count_as_counter).e);
      EXPECT_EQ(ds.as_counter.e, CTR.as_counter(v_as_size_t).e);
      EXPECT_EQ(ds.as_scalar, L.konst(v_as_size_t));
      for (size_t k = 0; k < 8; ++k) {
        EXPECT_EQ(L.eval(ds.as_bits[k]), L.eval(L.bit((v_as_size_t >> k) & 1)));
      }
    }
  }
}

TEST(CborByteDecoder, PrimeField) {
  test_decode_one_v8(Fp<1>("18446744073709551557"));
}

TEST(CborByteDecoder, BinaryField) { test_decode_one_v8(GF2_128<>()); }

}  // namespace
}  // namespace proofs
