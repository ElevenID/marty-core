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

#include "circuits/tests/mdoc/mdoc_revocation.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "algebra/static_string.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/mdoc/mdoc_revocation_witness.h"
#include "ec/p256.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

TEST(mdoc, mdoc_revocation_list_test) {
  using Elt = Fp256Base::Elt;
  set_log_level(INFO);

  constexpr size_t kListSize = 50000;

  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT;

  // ======== compile time =========================
  {
    using CompilerBackend = CompilerBackend<Fp256Base>;
    using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
    using EltW = LogicCircuit::EltW;
    using MdocRevocation = MdocRevocationList<LogicCircuit>;
    QuadCircuit<Fp256Base> Q(p256_base);
    const CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, p256_base);

    MdocRevocation mdr(LC);
    EltW list[kListSize];
    for (size_t i = 0; i < kListSize; ++i) {
      list[i] = LC.eltw_input();
    }

    Q.private_input();
    EltW id = LC.eltw_input();
    EltW inv = LC.eltw_input();

    mdr.assert_not_on_list(list, kListSize, id, inv);

    CIRCUIT = Q.mkcircuit(/*nc=*/1);
    dump_info("mdoc revocation list", Q);
    log(INFO, "Compile done");
  }

  // ======== Witness
  // Generate a witness from the mdoc data structure to remain close
  // to the application use case.
  std::vector<Elt> list(kListSize);
  SecureRandomEngine rng;
  Elt id = rng.elt(p256_base);
  for (size_t i = 0; i < kListSize; ++i) {
    list[i] = rng.elt(p256_base);
  }
  Elt prodinv = compute_mdoc_revocation_list_witness(id, list.data(), kListSize,
                                                     p256_base);

  // ========= Fill witness
  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);
  DenseFiller<Fp256Base> filler(W);
  DenseFiller<Fp256Base> pub_filler(pub);

  filler.push_back(p256_base.one());
  pub_filler.push_back(p256_base.one());
  for (size_t i = 0; i < kListSize; ++i) {
    filler.push_back(list[i]);
    pub_filler.push_back(list[i]);
  }

  filler.push_back(id);
  filler.push_back(prodinv);

  log(INFO, "Fill done");

  // =========== ZK test
  run2_test_zk(
      *CIRCUIT, W, pub, p256_base,
      p256_base.of_string("1126492241464102818735004576096902583730188404304894"
                          "08729223714171582664680802"), /* omega_x*/
      p256_base.of_string("8408799435854090769574046142781866056018216899718237"
                          "8749313018254450460212908"), /* omega_y */
      1ull << 31);
}

typedef struct {
  StaticString pkx, pky; /* public key of the crl issuer */
  StaticString left, right;
  StaticString id;
  uint64_t epoch;
  StaticString e, r, s; /* sig on the span*/
} MdocRevocationSpanTests;

static const MdocRevocationSpanTests span_tests[] = {
    {
        StaticString("0x3cef945f99f65a1fd5d917a4783dc4fc6078a723aae8bfee0e472e1"
                     "0b43d3b91"),
        StaticString("0x82480a801559d9bce4bf413e641178e64370ea80504f15f7b1efb10"
                     "56a784789"),
        StaticString("0x7fff"), /* left */
        StaticString("0x2f6038b853cf3ae407fb1a9845ea98ca5251fb41d088bb0bce5667d"
                     "25e9a1052"), /* right */
        StaticString("0x2f6038b853cf3ae407fb1a9845ea98ca5251fb41d088bb0bce5667d"
                     "25e9a1051"), /* id */
        1025,                      /* epoch */
        StaticString("0xa771beecd93838ed1a68e017b78a6d930153d2375158398ffe7cabf"
                     "8e591044c"),
        StaticString("0xc6e44683a459281f7cd07ce05a5c9d389659925aef90fa950a7007b"
                     "08a0adec9"),
        StaticString("0x35b3fc87f6e755acebc61efee92b1c6c6af68cdcb2c20ea9b1cbf8c"
                     "d11aae4d9"),
    },
};

std::unique_ptr<Circuit<Fp256Base>> make_circuit(const Fp256Base& f) {
  using CompilerBackend = CompilerBackend<Fp256Base>;
  using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
  using MdocRevocation = MdocRevocationSpan<LogicCircuit, Fp256Base, P256>;
  using EltW = LogicCircuit::EltW;

  QuadCircuit<Fp256Base> Q(p256_base);
  const CompilerBackend cbk(&Q);
  const LogicCircuit lc(&cbk, p256_base);

  MdocRevocation mdspan(lc, p256, n256_order);
  EltW crapkX, crapkY;
  crapkX = lc.eltw_input();
  crapkY = lc.eltw_input();

  Q.private_input();
  EltW id = lc.eltw_input();
  typename MdocRevocation::Witness vwc;
  vwc.input(lc);

  mdspan.assert_not_on_list(crapkX, crapkY, id, vwc);

  auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
  dump_info("mdoc revocation list", Q);

  return CIRCUIT;
}

void fill_input(Dense<Fp256Base>& W, const Fp256Base& f, bool prover = true) {
  using Nat = Fp256Base::N;
  using Elt = Fp256Base::Elt;
  using SpanWitness = MdocRevocationSpanWitness<P256, Fp256Scalar>;

  SpanWitness sw(p256, p256_scalar);
  size_t t_ind = 0;
  Elt pkX = p256_base.of_string(span_tests[t_ind].pkx);
  Elt pkY = p256_base.of_string(span_tests[t_ind].pky);
  Nat ne(span_tests[t_ind].e);
  Nat nr(span_tests[t_ind].r);
  Nat ns(span_tests[t_ind].s);
  Nat id(span_tests[t_ind].id);
  Nat ll(span_tests[t_ind].left);
  Nat rr(span_tests[t_ind].right);
  uint64_t epoch = span_tests[t_ind].epoch;
  bool ok = sw.compute_witness(pkX, pkY, ne, nr, ns, id, ll, rr, epoch);

  check(ok, "Could not compute signature witness");

  // ========= Fill witness
  DenseFiller<Fp256Base> filler(W);
  filler.push_back(p256_base.one());
  filler.push_back(pkX);
  filler.push_back(pkY);

  if (prover) {
    filler.push_back(p256_base.to_montgomery(id));
    sw.fill_witness(filler);
  }
  log(INFO, "Fill done");
}

TEST(mdoc, mdoc_revocation_span_test) {
  using Elt = Fp256Base::Elt;
  using Nat = Fp256Base::N;
  using SpanWitness = MdocRevocationSpanWitness<P256, Fp256Scalar>;

  set_log_level(INFO);

  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT = make_circuit(p256_base);

  // ======== Witness
  // Generate a witness from the mdoc data structure to remain close
  // to the application use case.
  SpanWitness sw(p256, p256_scalar);
  size_t t_ind = 0;
  Elt pkX = p256_base.of_string(span_tests[t_ind].pkx);
  Elt pkY = p256_base.of_string(span_tests[t_ind].pky);
  Nat ne(span_tests[t_ind].e);
  Nat nr(span_tests[t_ind].r);
  Nat ns(span_tests[t_ind].s);
  Nat id(span_tests[t_ind].id);
  Nat ll(span_tests[t_ind].left);
  Nat rr(span_tests[t_ind].right);
  uint64_t epoch = span_tests[t_ind].epoch;

  bool ok = sw.compute_witness(pkX, pkY, ne, nr, ns, id, ll, rr, epoch);

  check(ok, "Could not compute signature witness");

  // ========= Fill witness
  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);
  DenseFiller<Fp256Base> filler(W);
  DenseFiller<Fp256Base> pub_filler(pub);

  filler.push_back(p256_base.one());
  pub_filler.push_back(p256_base.one());

  filler.push_back(pkX);
  pub_filler.push_back(pkX);
  filler.push_back(pkY);
  pub_filler.push_back(pkY);

  filler.push_back(p256_base.to_montgomery(id));
  sw.fill_witness(filler);
  log(INFO, "Fill done");

  // =========== ZK test
  run2_test_zk(
      *CIRCUIT, W, pub, p256_base,
      p256_base.of_string("1126492241464102818735004576096902583730188404304894"
                          "08729223714171582664680802"), /* omega_x*/
      p256_base.of_string("8408799435854090769574046142781866056018216899718237"
                          "8749313018254450460212908"), /* omega_y */
      1ull << 31);
}

// ============ Benchmarks ====================================================
//
// To run the benchmarks:
//
// blaze run -c opt --dynamic_mode=off --copt=-gmlt \
//   //circuits/mdoc:mdoc_revocation_test --
//   --benchmark_filter=all
//

void BM_MdocRevocationProver(benchmark::State& state) {
  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT = make_circuit(p256_base);

  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);

  fill_input(W, p256_base);

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
BENCHMARK(BM_MdocRevocationProver);

}  // namespace
}  // namespace proofs
