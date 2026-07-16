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

#include "circuits/tests/mdoc/mdoc_1f.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/counter.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/mdoc/mdoc_examples.h"
#include "circuits/mdoc/mdoc_test_attributes.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/tests/mdoc/mdoc_1f_io.h"
#include "circuits/tests/mdoc/mdoc_1f_witness.h"
#include "ec/p256.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"  // For run2_test_zk
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

bool SanitizedMdocFixtures() {
  return kMdocExamplesSanitized || mdoc_tests[0].mdoc_size == 0;
}

template <class rsigw, class csigw, class Logic>
void copy_sig(csigw& cw, const rsigw& rw, const Logic& L) {
  cw.rx = L.konst(rw.rx_);
  cw.ry = L.konst(rw.ry_);
  cw.rx_inv = L.konst(rw.rx_inv_);
  cw.s_inv = L.konst(rw.s_inv_);
  cw.pk_inv = L.konst(rw.pk_inv_);
  for (size_t i = 0; i < 8; ++i) {
    cw.pre[i] = L.konst(rw.pre_[i]);
  }
  for (size_t i = 0; i < p256.kBits; ++i) {
    cw.bi[i] = L.konst(rw.bi_[i]);
    if (i < p256.kBits - 1) {
      cw.int_x[i] = L.konst(rw.int_x_[i]);
      cw.int_y[i] = L.konst(rw.int_y_[i]);
      cw.int_z[i] = L.konst(rw.int_z_[i]);
    }
  }
}

template <class ShaBlockWitness, class BlockWitness, class Logic>
void copy_sha(ShaBlockWitness sbw[], const BlockWitness bw[], const Logic& L,
              size_t num_sha_blocks) {
  BitPluckerEncoder<Fp256Base, kMdoc1SHAPluckerBits> BPENC(p256_base);

  for (size_t i = 0; i < num_sha_blocks; ++i) {
    for (size_t k = 0; k < 48; ++k) {
      sbw[i].outw[k] = L.konst(BPENC.mkpacked_v32(bw[i].outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      sbw[i].oute[k] = L.konst(BPENC.mkpacked_v32(bw[i].oute[k]));
      sbw[i].outa[k] = L.konst(BPENC.mkpacked_v32(bw[i].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      sbw[i].h1[k] = L.konst(BPENC.mkpacked_v32(bw[i].h1[k]));
    }
  }
}

template <class T, class S, class Logic>
void copy_index(T& to, const S& from, const Logic& L) {
  to = L.template vbit<kMdoc1CborIndexBits>(from);
}

template <class T, class S, class Logic>
void copy_cbor_index(T& to, const S& from, const Logic& L, size_t offset = 0) {
  to.k = L.template vbit<kMdoc1CborIndexBits>(from.k + offset);
  to.v = L.template vbit<kMdoc1CborIndexBits>(from.v + offset);
  to.ndx = L.template vbit<kMdoc1CborIndexBits>(from.ndx);
}

template <class MW, class RMW, class Logic>
void fill_eval_witness(MW& vw, const RMW& rvw, const Logic& L) {
  const Counter<Logic> CTR(L);
  vw.e_ = L.konst(rvw.e_);

  copy_sig(vw.sig_, rvw.ew_, L);
  copy_sig(vw.dpk_sig_, rvw.dkw_, L);
  vw.dpkx_ = L.konst(rvw.dpkx_);
  vw.dpky_ = L.konst(rvw.dpky_);

  // sha
  for (size_t i = kCose1PrefixLen; i < 64 * kMdoc1MaxSHABlocks; ++i) {
    vw.in_[i - kCose1PrefixLen] = L.template vbit<8>(rvw.signed_bytes_[i]);
  }
  vw.nb_ = L.template vbit<8>(rvw.numb_);

  copy_sha(vw.sig_sha_, rvw.bw_, L, kMdoc1MaxSHABlocks);

  // Cbor witnesses
  size_t prepad_offset = kMdoc1MaxMsoLen - rvw.pm_.t_mso_.len + 5;
  copy_index(vw.prepad_, prepad_offset, L);
  copy_index(vw.mso_len_, rvw.pm_.t_mso_.len - 5, L);
  for (size_t i = 0; i < kMdoc1MaxMsoLen; ++i) {
    vw.pwcb_[i].encoded_sel_header = L.konst(rvw.pwcb_[i].encoded_sel_header);
  }
  vw.gwcb_.invprod_decode = L.konst(rvw.gwcb_.invprod_decode);
  vw.gwcb_.cc0_counter = CTR.as_counter(rvw.gwcb_.cc0_counter);
  vw.gwcb_.invprod_parse = L.konst(rvw.gwcb_.invprod_parse);

  // The cbor indices need to be offset by the value of prepad because
  // the cbor string is shifted to be padded with zeroes.
  copy_cbor_index(vw.valid_, rvw.pm_.valid_, L, prepad_offset);
  copy_cbor_index(vw.valid_from_, rvw.pm_.valid_from_, L, prepad_offset);
  copy_cbor_index(vw.valid_until_, rvw.pm_.valid_until_, L, prepad_offset);
  copy_cbor_index(vw.dev_key_info_, rvw.pm_.dev_key_info_, L, prepad_offset);
  copy_cbor_index(vw.dev_key_, rvw.pm_.dev_key_, L, prepad_offset);
  copy_cbor_index(vw.dev_key_pkx_, rvw.pm_.dev_key_pkx_, L, prepad_offset);
  copy_cbor_index(vw.dev_key_pky_, rvw.pm_.dev_key_pky_, L, prepad_offset);
  copy_cbor_index(vw.value_digests_, rvw.pm_.value_digests_, L, prepad_offset);
  copy_cbor_index(vw.org_, rvw.pm_.org_, L, prepad_offset);

  // Attribute witnesses.
  for (size_t ai = 0; ai < vw.num_attr_; ++ai) {
    vw.attrb_[ai].resize(2 * 64);
    for (size_t i = 0; i < 2 * 64; ++i) {
      vw.attrb_[ai][i] = L.template vbit<8>(rvw.attr_bytes_[ai][i]);
    }
    copy_sha(vw.attr_sha_[ai].data(), rvw.atw_[ai].data(), L, 2);

    // In the case of attribute mso, push the value to avoid having to
    // deal with 1- or 2- byte key length.
    copy_cbor_index(vw.attr_mso_[ai], rvw.attr_mso_[ai], L, prepad_offset);
    copy_index(vw.attr_ei_[ai].offset, rvw.attr_ei_[ai].offset, L);
    copy_index(vw.attr_ei_[ai].len, rvw.attr_ei_[ai].len, L);
    copy_index(vw.attr_ev_[ai].offset, rvw.attr_ev_[ai].offset, L);
    copy_index(vw.attr_ev_[ai].len, rvw.attr_ev_[ai].len, L);
  }
}

TEST(jwt, EvalJWT) {
  if (SanitizedMdocFixtures()) {
    GTEST_SKIP() << "sanitized build omits mdoc proof fixtures";
  }

  using EvaluationBackend = EvaluationBackend<Fp256Base>;
  using MDL = mdoc_1f<Logic<Fp256Base, EvaluationBackend>, Fp256Base, P256, 1>;
  using MW = MDL::Witness;
  using RMW = mdoc_1f_witness<P256, Fp256Base, Fp256Scalar>;
  using v8 = typename Logic<Fp256Base, EvaluationBackend>::v8;

  const EvaluationBackend ebk(p256_base, true);
  const Logic<Fp256Base, EvaluationBackend> L(&ebk, p256_base);
  MDL mdoc_1f(L, p256, n256_order);
  MW mw(1);
  RMW rmw(1, p256, p256_scalar);

  auto t0 = mdoc_tests[0];
  auto pkX = p256_base.of_string(t0.pkx);
  auto pkY = p256_base.of_string(t0.pky);

  v8 now[kMdoc1DateLen];
  for (size_t i = 0; i < kMdoc1DateLen; ++i) {
    now[i] = L.vbit<8>(t0.now[i]);
  }

  std::vector<RequestedAttribute> oa;
  oa.push_back(test::age_over_18);

  uint8_t want[] = {0x6B, 'a', 'g', 'e',  '_', 'o', 'v', 'e', 'r',
                    '_',  '1', '8', 0x6C, 'e', 'l', 'e', 'm', 'e',
                    'n',  't', 'V', 'a',  'l', 'u', 'e', 0xF5};
  std::vector<MDL::OpenedAttribute> oa2;
  for (size_t i = 0; i < oa.size(); ++i) {
    MDL::OpenedAttribute oa2i;
    for (size_t j = 0; j < 96; ++j) {
      if (j < sizeof(want)) {
        oa2i.attr[j] = L.vbit<8>(want[j]);
      } else {
        oa2i.attr[j] = L.vbit<8>(0);
      }
      size_t len = sizeof(want);
      oa2i.len = L.vbit<8>(len);
    }
    oa2.push_back(std::move(oa2i));
  }

  EXPECT_TRUE(rmw.compute_witness(pkX, pkY, t0.mdoc, t0.mdoc_size,
                                  t0.transcript, t0.transcript_size, t0.now,
                                  oa.data(), oa.size()) == MDOC_PROVER_SUCCESS);
  fill_eval_witness(mw, rmw, L);
  mdoc_1f.assert_credential(L.konst(pkX), L.konst(pkY), L.konst(rmw.e2_),
                            oa2.data(), now, mw);
}

// Helper function to compile the mdoc_1f circuit.
std::unique_ptr<Circuit<Fp256Base>> make_mdoc1f_circuit(const Fp256Base& f) {
  using CompilerBackend = CompilerBackend<Fp256Base>;
  using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
  using MDL = mdoc_1f<LogicCircuit, Fp256Base, P256, 1>;
  using MW = MDL::Witness;
  using v8 = LogicCircuit::v8;

  using EltW = LogicCircuit::EltW;

  QuadCircuit<Fp256Base> Q(f);
  const CompilerBackend cbk(&Q);
  const LogicCircuit lc(&cbk, f);

  MDL mdoc(lc, p256, n256_order);

  // Define Public Inputs (example structure)
  EltW pkX = lc.eltw_input();
  EltW pkY = lc.eltw_input();
  EltW tr = lc.eltw_input();

  // Add opened attributes and now.
  MDL::OpenedAttribute oa2i[1];
  for (size_t j = 0; j < 1; ++j) {
    oa2i[j].input(lc);
  }

  v8 now[kMdoc1DateLen];
  for (size_t i = 0; i < kMdoc1DateLen; ++i) {
    now[i] = lc.vinput<8>();
  }

  Q.private_input();
  MW witness(1);
  witness.input(lc);

  mdoc.assert_credential(pkX, pkY, tr, oa2i, now, witness);

  auto circuit = Q.mkcircuit(/*nc=*/1);  // Assuming 1 constraint system
  dump_info("mdoc 1f circuit", Q);
  return circuit;
}

void fill_input(Dense<Fp256Base>& W, const MdocTests& t0, const Fp256Base& f,
                bool prover = true) {
  using RMW = mdoc_1f_witness<P256, Fp256Base, Fp256Scalar>;
  RMW rmw(1, p256, p256_scalar);
  auto pkX = p256_base.of_string(t0.pkx);
  auto pkY = p256_base.of_string(t0.pky);
  std::vector<RequestedAttribute> oa;
  oa.push_back(test::age_over_18);

  EXPECT_TRUE(rmw.compute_witness(pkX, pkY, t0.mdoc, t0.mdoc_size,
                                  t0.transcript, t0.transcript_size, t0.now,
                                  oa.data(), oa.size()) == MDOC_PROVER_SUCCESS);

  // ========= Fill witness
  DenseFiller<Fp256Base> filler(W);

  filler.push_back(p256_base.one());
  filler.push_back(pkX);
  filler.push_back(pkY);
  filler.push_back(rmw.e2_);

  for (size_t i = 0; i < oa.size(); ++i) {
    fill_attribute(filler, oa[i], f, 4);
  }

  for (size_t j = 0; j < kMdoc1DateLen; ++j) {
    filler.push_back(t0.now[j], 8, p256_base);
  }

  if (prover) {
    rmw.fill_witness(filler);
  }
}

TEST(Mdoc1fTest, RunsExamples) {
  if (SanitizedMdocFixtures()) {
    GTEST_SKIP() << "sanitized build omits mdoc proof fixtures";
  }

  set_log_level(INFO);

  // Compile the circuit
  std::unique_ptr<Circuit<Fp256Base>> circuit = make_mdoc1f_circuit(p256_base);

  // Now that small examples that use different namespaces have been added,
  // change this test to only try the "website explainer" example.
  const auto& test = mdoc_tests[0];

  log(INFO, "Running example size %zu", test.mdoc_size);

  // 2. Fill Witness (W) and Public Inputs (pub)
  auto W = Dense<Fp256Base>(1, circuit->ninputs);
  auto pub = Dense<Fp256Base>(1, circuit->npub_in);
  fill_input(W, test, p256_base);
  fill_input(pub, test, p256_base, /*prover=*/false);

  log(INFO, "Fill done");

  // 3. Run ZK Test
  run2_test_zk(
      *circuit, W, pub, p256_base,
      p256_base.of_string("1126492241464102818735004576096902583730188404304894"
                          "08729223714171582664680802"), /* omega_x*/
      p256_base.of_string("8408799435854090769574046142781866056018216899718237"
                          "8749313018254450460212908"), /* omega_y */
      1ull << 31);
}

// ============ Benchmarks =====================================================

void BM_Mdoc1fProver(benchmark::State& state) {
  if (SanitizedMdocFixtures()) {
    state.SkipWithError("sanitized build omits mdoc proof fixtures");
    return;
  }

  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT = make_mdoc1f_circuit(p256_base);

  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);

  auto t0 = mdoc_tests[0];
  fill_input(W, t0, p256_base);

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

  SecureRandomEngine rng;

  ZkProof<Fp256Base> zkpr(*CIRCUIT, 4, 128);
  ZkProver<Fp256Base, RSFactory> prover(*CIRCUIT, p256_base, rsf);

  for (auto s : state) {
    Transcript tp((uint8_t*)"test", 4);
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
  }
}
BENCHMARK(BM_Mdoc1fProver);

}  // namespace
}  // namespace proofs
