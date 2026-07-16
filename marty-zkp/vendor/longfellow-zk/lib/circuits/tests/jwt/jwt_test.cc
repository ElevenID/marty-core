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

#include "circuits/tests/jwt/jwt.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "algebra/static_string.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/jwt/jwt_constants.h"
#include "circuits/tests/jwt/jwt_witness.h"
#include "ec/p256.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

struct jwtest {
  std::string jwt;
  size_t len; /* length of the jwt msg */
  StaticString pkx;
  StaticString pky;
  StaticString e2; /* hash of the public key-binding message */
  std::vector<OpenedAttribute> attrs;
};

static const std::vector<jwtest>* tests = new std::vector<jwtest>(
    {{"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJpc3MiOiJodHRwczovL2JtaS5idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwi"
      "c3ViIjoidXNlcjEyMzQ1IiwiZXhwIjoxNzU0MDM5ODMwLCJpYXQiOjE3NTQwMzYyMzAsImdp"
      "dmVuX25hbWUiOiJFcmlrYSIsImFnZV9vdmVyXzE4Ijp0cnVlLCJjbmYiOnsiandrIjp7Imt0"
      "eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoicXB2czMyeXpDOGhZYXdOV181UUR5U2E4eFJf"
      "SUtCaTdSX1E1Tm5iYXVPZyIsInkiOiJCakxDb3M1eFZGMTJWSTdWSTAySUZMSGRzd1FLc0lK"
      "V0tOa1BuMFBaRFFnIn19fQ.U-"
      "2n0rGEYxGUGuQqNUPhe42rWZSJPR7ZccGRpqkzEoqnGDRmIauuA0hfLgwALkawWLSDETRR3v"
      "FzHfV6lNvb3Q~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiMitqd3QifQ."
      "eyJub25jZSI6IjEyMzEyMzEyMyIsImF1ZCI6IlJQIiwiaWF0IjoxNzU0MDM2MjMwfQ."
      "SjTqd6_LBXd0-fj9pk7P1VaimaEJh6TKKHKqxaPFEbiMPStEpZGE2BdyVghn0c-"
      "GUBnm8RV0k-jUkAk0bQAsxw",
      418,
      StaticString(
          "0x369b8ba929cf0f06be8272268f4091cfde4ef00fe35f1a25ff04e2d4293d692b"),
      StaticString(
          "0xbdf89d633ac7a622d73bee63bd00a68bcee5b3262054f4e767f7c25157182364"),
      StaticString(
          "0x7f9982db0d6de18b4c5a83044912062d8d48cca2120b3badb2b7948427360159"),
      {OpenedAttribute{{'g', 'i', 'v', 'e', 'n', '_', 'n', 'a', 'm', 'e'},
                       {'E', 'r', 'i', 'k', 'a'},
                       10,
                       5}}},

     {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJpc3MiOiJodHRwczovL2JtaS5idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwi"
      "c3ViIjoidXNlcjEyMzQ1IiwiZXhwIjoxNzUzOTkwNDQ5LCJpYXQiOjE3NTM5ODY4NDksImdp"
      "dmVuX25hbWUiOiJFcmlrYSIsImZhbWlseV9uYW1lIjoiTXVzdGVybWFubiIsImJpcnRoZGF0"
      "ZSI6IjE5NjMtMDgtMTIiLCJnZW5kZXIiOiJGIiwiYmlydGhfZmFtaWx5X25hbWUiOiJHYWJs"
      "ZXIiLCJhZ2Vfb3Zlcl8xOCI6dHJ1ZSwiYWdlX292ZXJfMjEiOnRydWUsImFnZV9vdmVyXzY1"
      "IjpmYWxzZSwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InY1"
      "d25RcElBMTdZd0JaNUlFMGk4ZlNiRldCSUQ4NkljVFBoRVpZam0wTmciLCJ5IjoiTkFhSDV1"
      "d3dFb2dnSkY5LU9mdUlYaVRWeGpfNjRmVGJETlpfU2hwclRoTSJ9fX0."
      "UlzoYNshYAT6GglIr2nXQ4e9ERO8VPcVNZOeFo28FwfdVNqKQZnEdQCLGftFCIH8Rhmmshf5"
      "-PAPn5g5c_u2TQ~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiMitqd3QifQ."
      "eyJub25jZSI6IjEyMzEyMzEyMyIsImF1ZCI6IlJQIiwiaWF0IjoxNzUzOTg2ODQ5fQ."
      "7eGDLcwBKfMj7d5p57FSVh9PeKqY66iN6-WSUL5mZQm4SoNElzAF-HMMwmy-jESy-"
      "97vUIe5DwwVSmc0Dk1Gyg",
      597,
      StaticString(
          "0x3cce3bae0dd16e8a98e4d7647b449db9a170afc2c1fe0ce263a3768d9ba790b9"),
      StaticString(
          "0x462c7dd391d504e15bc6cdee6218ed495da244a198cf19da9217c796d58ab8aa"),
      StaticString(
          "0xaf246c556bba9ab47e3ce2802c3ae6901e7dd3deedf9557cc66d5b1050324b68"),
      {OpenedAttribute{{'g', 'i', 'v', 'e', 'n', '_', 'n', 'a', 'm', 'e'},
                       {'E', 'r', 'i', 'k', 'a'},
                       10,
                       5}}}});

static const std::vector<jwtest>* failure_tests = new std::vector<jwtest>({
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9",
     100,
     StaticString("319540339297497309659735349722677581826823855703704722323"
                  "40378963542000270086"),
     StaticString("142227698647555729114796598391911037110557658140642077047"
                  "21481731130688302439"),
     StaticString("0"),
     {OpenedAttribute{{'n', 'a', 'm', 'e'},
                      {'J', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I",
     100,
     StaticString("319540339297497309659735349722677581826823855703704722323"
                  "40378963542000270086"),
     StaticString("142227698647555729114796598391911037110557658140642077047"
                  "21481731130688302439"),
     StaticString("0"),
     {OpenedAttribute{{'n', 'a', 'm', 'e'},
                      {'J', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
    // Missing ~
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm"
     "lhdCI6MTUxNjIzOTAyMn0.tyh-"
     "VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_"
     "3cYHBw7AhHale5wky6-sVA",
     300,
     StaticString("785054073011785553737731015056414053471306735754112123272"
                  "1010766305002029006"),
     StaticString("653163126446534636442103222018715994775539593566383279465"
                  "30363791985981247174"),
     StaticString("0"),
     {OpenedAttribute{{'n', 'a', 'm', 'e'},
                      {'J', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
    // Bad base64 in payload.
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzd#IiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm"
     "lhdCI6MTUxNjIzOTAyMn0.tyh-"
     "VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_"
     "3cYHBw7AhHale5wky6-sVA~",
     300,
     StaticString("785054073011785553737731015056414053471306735754112123272"
                  "1010766305002029006"),
     StaticString("653163126446534636442103222018715994775539593566383279465"
                  "30363791985981247174"),
     StaticString("0"),
     {OpenedAttribute{{'n', 'a', 'm', 'e'},
                      {'J', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
    // Bad base64 in signature.
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm"
     "lhdCI6MTUxNjIzOTAyMn0.tyh-"
     "VfuzIxCyGY(DlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_"
     "3cYHBw7AhHale5wky6-sVA~",
     300,
     StaticString("785054073011785553737731015056414053471306735754112123272"
                  "1010766305002029006"),
     StaticString("653163126446534636442103222018715994775539593566383279465"
                  "30363791985981247174"),
     StaticString("0"),
     {OpenedAttribute{{'n', 'a', 'm', 'e'},
                      {'J', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
    // Sig too small, fails.
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm"
     "lhdCI6MTUxNjIzOTAyMn0.tyh-"
     "VfuzIxCyGYA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_"
     "3cYHBw7AhHale5wky6-sVA~",
     300,
     StaticString("785054073011785553737731015056414053471306735754112123272"
                  "1010766305002029006"),
     StaticString("653163126446534636442103222018715994775539593566383279465"
                  "30363791985981247174"),
     StaticString("0"),
     {OpenedAttribute{{'n', 'a', 'm', 'e'},
                      {'J', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
    // Sig fails.
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm"
     "lhdCI6MTUxNjIzOTAyMn0.tyh-"
     "VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqVSLPNY2N0mpHb3nk5K17HWP_"
     "3cYHBw7AhHale5wky6-sVA~",
     300,
     StaticString("785054073011785553737731015056414053471306735754112123272"
                  "1010766305002029006"),
     StaticString("653163126446534636442103222018715994775539593566383279465"
                  "30363791985981247174"),
     StaticString("0"),
     {OpenedAttribute{{'n', 'a', 'm', 'e'},
                      {'J', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
    // Bad attribute id.
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm"
     "lhdCI6MTUxNjIzOTAyMn0.tyh-"
     "VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_"
     "3cYHBw7AhHale5wky6-sVA~",
     300,
     StaticString("785054073011785553737731015056414053471306735754112123272"
                  "1010766305002029006"),
     StaticString("653163126446534636442103222018715994775539593566383279465"
                  "30363791985981247174"),
     StaticString("0"),
     {OpenedAttribute{{'f', 'a', 'm', 'e'},
                      {'J', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
    // Bad attribute value.
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm"
     "lhdCI6MTUxNjIzOTAyMn0.tyh-"
     "VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_"
     "3cYHBw7AhHale5wky6-sVA~",
     300,
     StaticString("785054073011785553737731015056414053471306735754112123272"
                  "1010766305002029006"),
     StaticString("653163126446534636442103222018715994775539593566383279465"
                  "30363791985981247174"),
     StaticString("0"),
     {OpenedAttribute{{'n', 'a', 'm', 'e'},
                      {'K', 'o', 'h', 'n', ' ', 'D', 'o', 'e'},
                      4,
                      8}}},
});

constexpr static size_t kSHAEvalTest = 11;
using EvaluationBackend = EvaluationBackend<Fp256Base>;
using JWTE =
    JWT<Logic<Fp256Base, EvaluationBackend>, Fp256Base, P256, kSHAEvalTest>;
using JWW = JWTE::Witness;
using RJWW = JWTWitness<P256, Fp256Scalar, kSHAEvalTest>;

void fill_eval_witness(RJWW& rvw, JWW& vw,
                       const Logic<Fp256Base, EvaluationBackend>& L) {
  vw.e_ = L.konst(rvw.e_);
  vw.dpkx_ = L.konst(rvw.dpkx_);
  vw.dpky_ = L.konst(rvw.dpky_);
  vw.jwt_sig_.rx = L.konst(rvw.sig_.rx_);
  vw.jwt_sig_.ry = L.konst(rvw.sig_.ry_);
  vw.jwt_sig_.rx_inv = L.konst(rvw.sig_.rx_inv_);
  vw.jwt_sig_.s_inv = L.konst(rvw.sig_.s_inv_);
  vw.jwt_sig_.pk_inv = L.konst(rvw.sig_.pk_inv_);

  vw.kb_sig_.rx = L.konst(rvw.kb_sig_.rx_);
  vw.kb_sig_.ry = L.konst(rvw.kb_sig_.ry_);
  vw.kb_sig_.rx_inv = L.konst(rvw.kb_sig_.rx_inv_);
  vw.kb_sig_.s_inv = L.konst(rvw.kb_sig_.s_inv_);
  vw.kb_sig_.pk_inv = L.konst(rvw.kb_sig_.pk_inv_);

  for (size_t i = 0; i < 8; ++i) {
    vw.jwt_sig_.pre[i] = L.konst(rvw.sig_.pre_[i]);
    vw.kb_sig_.pre[i] = L.konst(rvw.kb_sig_.pre_[i]);
  }
  for (size_t i = 0; i < p256.kBits; ++i) {
    vw.jwt_sig_.bi[i] = L.konst(rvw.sig_.bi_[i]);
    vw.kb_sig_.bi[i] = L.konst(rvw.kb_sig_.bi_[i]);
    if (i < p256.kBits - 1) {
      vw.jwt_sig_.int_x[i] = L.konst(rvw.sig_.int_x_[i]);
      vw.jwt_sig_.int_y[i] = L.konst(rvw.sig_.int_y_[i]);
      vw.jwt_sig_.int_z[i] = L.konst(rvw.sig_.int_z_[i]);

      vw.kb_sig_.int_x[i] = L.konst(rvw.kb_sig_.int_x_[i]);
      vw.kb_sig_.int_y[i] = L.konst(rvw.kb_sig_.int_y_[i]);
      vw.kb_sig_.int_z[i] = L.konst(rvw.kb_sig_.int_z_[i]);
    }
  }

  // sha
  for (size_t i = 0; i < 64 * kSHAEvalTest; ++i) {
    vw.preimage_[i] = L.vbit<8>(rvw.preimage_[i]);
  }
  vw.nb_ = L.vbit<8>(rvw.numb_);

  BitPluckerEncoder<Fp256Base, kSHAJWTPluckerBits> BPENC(p256_base);

  for (size_t i = 0; i < kSHAEvalTest; ++i) {
    for (size_t k = 0; k < 48; ++k) {
      vw.sha_[i].outw[k] = L.konst(BPENC.mkpacked_v32(rvw.sha_bw_[i].outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      vw.sha_[i].oute[k] = L.konst(BPENC.mkpacked_v32(rvw.sha_bw_[i].oute[k]));
      vw.sha_[i].outa[k] = L.konst(BPENC.mkpacked_v32(rvw.sha_bw_[i].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      vw.sha_[i].h1[k] = L.konst(BPENC.mkpacked_v32(rvw.sha_bw_[i].h1[k]));
    }
  }

  // ebits
  for (size_t i = 0; i < Fp256Base::kBits; ++i) {
    vw.e_bits_[i] = L.bit(rvw.e_bits_[i]);
  }

  vw.payload_len_ = L.vbit<kJWTIndexBits>(rvw.payload_len_);
  vw.payload_ind_ = L.vbit<kJWTIndexBits>(rvw.payload_ind_);
  for (size_t i = 0; i < rvw.na_; ++i) {
    vw.attr_ind_.push_back(L.vbit<kJWTIndexBits>(rvw.attr_ind_[i]));
  }
}

template <class Field>
void fill_bit_string(DenseFiller<Field>& filler, const uint8_t s[/*len*/],
                     size_t len, size_t max, const Field& Fs) {
  for (size_t i = 0; i < max && i < len; ++i) {
    filler.push_back(s[i], 8, Fs);
  }
}

TEST(jwt, EvalJWT) {
  const EvaluationBackend ebk(p256_base, true);
  const Logic<Fp256Base, EvaluationBackend> L(&ebk, p256_base);
  JWTE jwtc(L, p256, n256_order);
  JWW vw;

  RJWW rvw(p256, p256_scalar);

  auto t0 = tests->at(0);
  auto jwt = t0.jwt;
  auto pkX = p256_base.of_string(t0.pkx);
  auto pkY = p256_base.of_string(t0.pky);
  auto e2 = p256_base.of_string(t0.e2);

  std::vector<JWTE::OpenedAttribute> oa2;
  for (size_t i = 0; i < t0.attrs.size(); ++i) {
    JWTE::OpenedAttribute oa2i;
    size_t pi = 0;
    oa2i.pattern[pi++] = L.vbit<8>('"');
    for (size_t j = 0; j < 32 && j < t0.attrs[i].id_len; ++j) {
      oa2i.pattern[pi++] = L.vbit<8>(t0.attrs[i].id[j]);
    }
    oa2i.pattern[pi++] = L.vbit<8>('"');
    oa2i.pattern[pi++] = L.vbit<8>(':');
    oa2i.pattern[pi++] = L.vbit<8>('"');
    for (size_t j = 0; j < 64 && j < t0.attrs[i].value_len; ++j) {
      oa2i.pattern[pi++] = L.vbit<8>(t0.attrs[i].value[j]);
    }
    oa2i.pattern[pi++] = L.vbit<8>('"');
    oa2i.len = L.vbit<8>(pi);
    for (; pi < 128; ++pi) {
      oa2i.pattern[pi] = L.vbit<8>(0);
    }

    oa2.push_back(std::move(oa2i));
  }

  EXPECT_TRUE(rvw.compute_witness(jwt, pkX, pkY, t0.attrs));
  fill_eval_witness(rvw, vw, L);

  jwtc.assert_jwt_attributes(L.konst(pkX), L.konst(pkY), L.konst(e2),
                             oa2.data(), vw);
}

TEST(jwt, EvalFailureJWT) {
  RJWW rvw(p256, p256_scalar);

  std::string long_jwt(kSHAEvalTest * 64 + 1, 'a');
  EXPECT_FALSE(
      rvw.compute_witness(long_jwt, p256_base.one(), p256_base.one(), {}));

  for (auto fail : *failure_tests) {
    auto pkX = p256_base.of_string(fail.pkx);
    auto pkY = p256_base.of_string(fail.pky);
    EXPECT_FALSE(rvw.compute_witness(fail.jwt, pkX, pkY, fail.attrs));
  }
}

template <size_t SHABlocks>
std::unique_ptr<Circuit<Fp256Base>> make_circuit(const Fp256Base& f) {
  using CompilerBackend = CompilerBackend<Fp256Base>;
  using LogicCircuit = Logic<Fp256Base, CompilerBackend>;

  using JWTC =
      JWT<Logic<Fp256Base, CompilerBackend>, Fp256Base, P256, SHABlocks>;
  using EltW = LogicCircuit::EltW;

  QuadCircuit<Fp256Base> Q(p256_base);
  const CompilerBackend cbk(&Q);
  const LogicCircuit lc(&cbk, p256_base);
  JWTC jwtc(lc, p256, n256_order);

  EltW pkX, pkY, e2;
  pkX = lc.eltw_input();
  pkY = lc.eltw_input();
  e2 = lc.eltw_input();

  std::vector<typename JWTC::OpenedAttribute> oa;
  for (size_t i = 0; i < 1; ++i) {
    typename JWTC::OpenedAttribute oa2i;
    oa2i.input(lc);
    oa.push_back(std::move(oa2i));
  }
  Q.private_input();
  typename JWTC::Witness vwc;
  vwc.input(lc, 1);

  jwtc.assert_jwt_attributes(pkX, pkY, e2, oa.data(), vwc);

  auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
  dump_info("mdoc revocation list", Q);

  return CIRCUIT;
}

template <size_t SHABlocks>
void fill_input(Dense<Fp256Base>& W, const jwtest& t0, const Fp256Base& f,
                bool prover = true) {
  JWTWitness<P256, Fp256Scalar, SHABlocks> rvw(p256, p256_scalar);

  auto jwt = t0.jwt;
  auto pkX = p256_base.of_string(t0.pkx);
  auto pkY = p256_base.of_string(t0.pky);
  auto e2 = p256_base.of_string(t0.e2);

  EXPECT_TRUE(rvw.compute_witness(jwt, pkX, pkY, t0.attrs));

  // ========= Fill witness
  DenseFiller<Fp256Base> filler(W);

  filler.push_back(p256_base.one());
  filler.push_back(pkX);
  filler.push_back(pkY);
  filler.push_back(e2);

  for (size_t i = 0; i < t0.attrs.size(); ++i) {
    fill_attribute(filler, t0.attrs[i], p256_base, 1);
  }

  if (prover) {
    rvw.fill_witness(filler);
  }
  log(INFO, "Fill done");
}

template <size_t SHABlocks>
void test_jwt_zk() {
  set_log_level(INFO);
  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT =
      make_circuit<SHABlocks>(p256_base);
  // ========= Fill witness
  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);

  auto t0 = tests->at(0);

  if (SHABlocks * 64 - 9 < t0.len) {
    log(INFO, "test too big, skipping");
    return;
  }

  fill_input<SHABlocks>(W, t0, p256_base);
  fill_input<SHABlocks>(pub, t0, p256_base, false);

  // =========== ZK test
  run2_test_zk(
      *CIRCUIT, W, pub, p256_base,
      p256_base.of_string("1126492241464102818735004576096902583730188404304894"
                          "08729223714171582664680802"), /* omega_x*/
      p256_base.of_string("8408799435854090769574046142781866056018216899718237"
                          "8749313018254450460212908"), /* omega_y */
      1ull << 31);
}

TEST(jwt, JwtZk7) { test_jwt_zk<7>(); }

TEST(jwt, JwtZk9) { test_jwt_zk<9>(); }

TEST(jwt, JwtZk11) { test_jwt_zk<11>(); }

TEST(jwt, JwtZk13) { test_jwt_zk<13>(); }

// ============ Benchmarks ====================================================
//
// To run the benchmarks:
//
// blaze run -c opt --dynamic_mode=off --copt=-gmlt \
//   //circuits/jwt:jwt_test -- --benchmark_filter=all
//

template <size_t SHABlocks>
void BM_JwtZKProver(benchmark::State& state) {
  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT =
      make_circuit<SHABlocks>(p256_base);

  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);

  auto t0 = tests->at(0);
  fill_input<SHABlocks>(W, t0, p256_base);

  using f2_p256 = Fp2<Fp256Base>;
  using Elt2 = f2_p256::Elt;
  using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
  using RSFactory = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;
  const f2_p256 p256_2(p256_base);

  // Root of unity for the f_p256^2 extension field.
  static constexpr char kRootX[] =
      "112649224146410281873500457609690258373018840430489408729223714171582664"
      "680802";
  static constexpr char kRootY[] =
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908";
  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory rsf(fft_b, p256_base);

  Transcript tp((uint8_t*)"test", 4);
  SecureRandomEngine rng;

  ZkProof<Fp256Base> zkpr(*CIRCUIT, 4, 128);
  ZkProver<Fp256Base, RSFactory> prover(*CIRCUIT, p256_base, rsf);

  for (auto s : state) {
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
  }
}

// Debian 11 does not support template usage in benchmarks.
void BM_JwtZKProver7(benchmark::State& state) {
  BM_JwtZKProver<7>(state);
}

void BM_JwtZKProver11(benchmark::State& state) {
  BM_JwtZKProver<11>(state);
}

void BM_JwtZKProver15(benchmark::State& state) {
  BM_JwtZKProver<15>(state);
}

BENCHMARK(BM_JwtZKProver7);
BENCHMARK(BM_JwtZKProver11);
BENCHMARK(BM_JwtZKProver15);

}  // namespace
}  // namespace proofs
