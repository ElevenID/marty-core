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

#include "proto/circuit.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/fp_p128.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "ec/p256.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void expect_same_id(const Circuit<Field>& c0, const Circuit<Field>& c1,
                    const Field& F) {
  std::array<uint8_t, 32> id0;
  circuit_id(id0.data(), c0, F);
  std::array<uint8_t, 32> id1;
  circuit_id(id1.data(), c1, F);
  EXPECT_EQ(id0, id1);
}

template <class FF>
void serialize_test2(const Circuit<FF>& circuit, const FF& F,
                     FieldID field_id) {
  std::vector<uint8_t> bytes;
  log(INFO, "Serializing2");
  CircuitRep<FF> cr(F, field_id);
  cr.to_bytes(circuit, bytes);
  size_t sz = bytes.size();
  log(INFO, "size: %zu", sz);

  CircuitRep<FF> cr2(F, field_id);

  log(INFO, "Deserializing2");
  ReadBuffer rb(bytes);
  auto c2 = cr2.from_bytes(rb, /*enforce_circuit_id=*/true);
  log(INFO, "Parsed from bytes");
  EXPECT_TRUE(c2 != nullptr);
  expect_same_id(*c2, circuit, F);

  // Test truncated inputs.
  ReadBuffer rb1(bytes.data(), sz - 1);
  auto bad = cr2.from_bytes(rb1, /*enforce_circuit_id=*/true);
  EXPECT_TRUE(bad == nullptr);

  ReadBuffer rb2(bytes.data() + 1, sz - 1);
  bad = cr2.from_bytes(rb2, /*enforce_circuit_id=*/true);
  EXPECT_TRUE(bad == nullptr);

  uint8_t tmp[32];
  // Test corrupted numconsts
  ReadBuffer rb3(bytes);
  size_t clobber = CircuitRep<FF>::kBytesPerSizeT * 7 - 1;
  tmp[0] = bytes[clobber];
  bytes[clobber] = 1;
  bad = cr2.from_bytes(rb3, /*enforce_circuit_id=*/true);
  EXPECT_TRUE(bad == nullptr);
  bytes[clobber] = tmp[0];

  // Test corrupted constant table Elt
  ReadBuffer rb4(bytes);
  for (size_t i = 0; i < 32; ++i) {
    tmp[i] = bytes[clobber + 1 + i];
    bytes[clobber + 1 + i] = 0xff;
  }
  bad = cr2.from_bytes(rb4, /*enforce_circuit_id=*/true);
  EXPECT_TRUE(bad == nullptr);
  for (size_t i = 0; i < 32; ++i) {
    bytes[clobber + 1 + i] = tmp[i];
  }
}

template <class FF>
void serialize_test3(Circuit<FF>& circuit, const FF& F, FieldID field_id) {
  // corrupt the circuit id
  circuit.id[0] ^= 1u;

  std::vector<uint8_t> bytes;
  log(INFO, "Serializing3");
  CircuitRep<FF> cr(F, field_id);
  cr.to_bytes(circuit, bytes);
  size_t sz = bytes.size();
  log(INFO, "size: %zu", sz);

  // restore circuit id
  circuit.id[0] ^= 1u;

  CircuitRep<FF> cr2(F, field_id);

  log(INFO, "Deserializing3");
  ReadBuffer rb(bytes);
  auto c2 = cr2.from_bytes(rb, /*enforce_circuit_id=*/true);
  log(INFO, "Parsed from bytes");
  EXPECT_TRUE(c2 == nullptr);
}

TEST(circuit_io, ecdsa) {
  using CompilerBackend = CompilerBackend<Fp256Base>;
  using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
  using EltW = LogicCircuit::EltW;
  using Verc = VerifyCircuit<LogicCircuit, Fp256Base, P256>;

  set_log_level(INFO);

  std::unique_ptr<Circuit<Fp256Base>> circuit;

  /*scope to delimit compile-time for ecdsa verification circuit */ {
    QuadCircuit<Fp256Base> Q(p256_base);
    CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, p256_base);

    using Nat = Fp256Base::N;
    const Nat order = Nat(
        "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    Verc verc(LC, p256, order);
    Verc::Witness vwc;

    EltW pkx = LC.eltw_input(), pky = LC.eltw_input(), e = LC.eltw_input();
    vwc.input(LC);

    verc.verify_signature3(pkx, pky, e, vwc);

    circuit = Q.mkcircuit(1);
    dump_info("ecdsa", 1, Q);
  }

  serialize_test2<Fp256Base>(*circuit, p256_base, P256_ID);
  serialize_test3<Fp256Base>(*circuit, p256_base, P256_ID);
}

TEST(circuit_io, SHA) {
  using Fp128 = Fp128<>;
  using CompilerBackend = CompilerBackend<Fp128>;
  using LogicCircuit = Logic<Fp128, CompilerBackend>;
  using v8C = LogicCircuit::v8;
  using FlatShaC = FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, 1>>;
  set_log_level(INFO);

  const Fp128 Fg;
  constexpr size_t kBlocks = 15;

  std::unique_ptr<Circuit<Fp128>> circuit;

  /*scope to delimit compile-time for sha hash circuit*/ {
    QuadCircuit<Fp128> Q(Fg);
    const CompilerBackend cbk(&Q);
    const LogicCircuit lc(&cbk, Fg);
    FlatShaC fsha(lc);

    v8C numbW = lc.vinput<8>();

    std::vector<v8C> inW(64 * kBlocks);
    for (size_t i = 0; i < kBlocks * 64; ++i) {
      inW[i] = lc.vinput<8>();
    }

    std::vector<FlatShaC::BlockWitness> bwW(kBlocks);
    for (size_t j = 0; j < kBlocks; j++) {
      bwW[j].input(lc);
    }

    fsha.assert_message(kBlocks, numbW, inW.data(), bwW.data());

    circuit = Q.mkcircuit(1);
    dump_info("assert_message", kBlocks, Q);
  }

  serialize_test2<Fp128>(*circuit, Fg, FP128_ID);
  serialize_test3<Fp128>(*circuit, Fg, FP128_ID);
}

}  // namespace
}  // namespace proofs
