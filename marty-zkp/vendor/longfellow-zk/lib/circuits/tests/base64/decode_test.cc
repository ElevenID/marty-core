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

#include "circuits/tests/base64/decode.h"

#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void test_each_symbol(const Field& F) {
  using EvaluationBackend = EvaluationBackend<Field>;
  using v8 = typename Logic<Field, EvaluationBackend>::v8;
  using v6 = typename Logic<Field, EvaluationBackend>::template bitvec<6>;
  const EvaluationBackend ebk(F, false);
  const Logic<Field, EvaluationBackend> L(&ebk, F);
  Base64Decoder<Logic<Field, EvaluationBackend> > bd(L);

  v6 out, want;
  v8 in;

  std::string valid =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  // Loop over all input symbols.
  for (size_t c = 0; c < 256; ++c) {
    in = L.template vbit<8>(c);
    size_t ind = valid.find(c);
    if (ind != std::string::npos) {
      want = L.template vbit<6>(ind);
      bd.decode(in, out);
      EXPECT_EQ(L.eval(L.veq(out, want)), L.konst(1));
    } else {
      bd.decode(in, out);
      bool failed = ebk.assertion_failed();
      if (!failed) {
        log(INFO, "expected failure on %x", c);
      }
      EXPECT_TRUE(failed);
    }
  }
}

template <class Field>
void test_strings(const Field& F) {
  using EvaluationBackend = EvaluationBackend<Field>;
  using v8 = typename Logic<Field, EvaluationBackend>::v8;
  const EvaluationBackend ebk(F, false);
  const Logic<Field, EvaluationBackend> L(&ebk, F);
  Base64Decoder<Logic<Field, EvaluationBackend> > bd(L);

  struct test {
    const char *want, *b64;
  };

  struct test cases[] = {
      {"hello", "aGVsbG8"},
      {"s", "cw"},
      {"ab", "YWI"},
      {"333", "MzMz"},
      {"4444", "NDQ0NA"},
      {"55555", "NTU1NTU"},
      {"{\"json\":\"woohoo\"}", "eyJqc29uIjoid29vaG9vIn0"},
      {"{\"g\":{\"foo\":\"hh\"}}", "eyJnIjp7ImZvbyI6ImhoIn19"},
  };

  for (auto tc : cases) {
    size_t n = strlen(tc.b64);
    size_t on = n * 6 / 8;
    EXPECT_EQ(strlen(tc.want), on);
    std::vector<v8> inp(n), got(n);
    for (size_t i = 0; i < n; ++i) {
      inp[i] = L.template vbit<8>(tc.b64[i]);
    }
    bd.base64_rawurl_decode(inp.data(), got.data(), n);
    for (size_t i = 0; i < on; ++i) {
      EXPECT_EQ(L.eval(L.veq(got[i], L.template vbit<8>(tc.want[i]))),
                L.konst(1));
    }
  }
}

TEST(Base64, DecodeSymbol) {
  using EvaluationBackend = EvaluationBackend<Fp256Base>;
  const EvaluationBackend ebk(p256_base);
  test_each_symbol(p256_base);
}

TEST(Base64, DecodeBase64) {
  using EvaluationBackend = EvaluationBackend<Fp256Base>;
  const EvaluationBackend ebk(p256_base, false);
  const Logic<Fp256Base, EvaluationBackend> L(&ebk, p256_base);
  Base64Decoder<Logic<Fp256Base, EvaluationBackend> > bd(L);
  test_strings(p256_base);
}

}  // namespace
}  // namespace proofs
