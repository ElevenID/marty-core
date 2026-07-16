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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_ANONCRED_PTRCRED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_ANONCRED_PTRCRED_H_
#include <cstddef>
#include <vector>

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/memcmp.h"
#include "circuits/logic/routing.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/tests/anoncred/small_io.h"

namespace proofs {

// This class creates a circuit to verify the signatures in a "ptrcred".
// A ptr credential is a document formatted as:
//      n // 8 bits specifying the number of attributes
//      ind <table of n pointer, each of 10 bits>
//          each pointer references from the beginning of the document
//      A byte string containing keys and values.
//          A key consists of 3 bytes.
//          A value can be arbitrarily long.
template <class LogicCircuit, class Field, class EC, size_t kNumAttr>
class PtrCred {
  using EltW = typename LogicCircuit::EltW;
  using Elt = typename LogicCircuit::Elt;
  using Nat = typename Field::N;
  using Ecdsa = VerifyCircuit<LogicCircuit, Field, EC>;
  using EcdsaWitness = typename Ecdsa::Witness;

  using v8 = typename LogicCircuit::v8;
  using v32 = typename LogicCircuit::v32;
  static constexpr size_t kIndexBits = 5;
  static constexpr size_t kMaxSHABlocks = 3;
  static constexpr size_t kMaxMsoLen = kMaxSHABlocks * 64 - 9;

  using vind = typename LogicCircuit::template bitvec<kIndexBits>;
  using Flatsha = FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, 3>>;
  using RoutingL = Routing<LogicCircuit>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;

  const LogicCircuit& lc_;
  const EC& ec_;
  const Nat& order_;

 public:
  class Witness {
   public:
    EltW e_;
    EltW dpkx_, dpky_;

    EcdsaWitness sig_;
    EcdsaWitness dpk_sig_;

    v8 in_[64 * kMaxSHABlocks]; /* input bytes, 64 * MAX */
    v8 nb_; /* index of sha block that contains the real hash  */
    ShaBlockWitness sig_sha_[kMaxSHABlocks];

    void input(const LogicCircuit& lc) {
      e_ = lc.eltw_input();
      dpkx_ = lc.eltw_input();
      dpky_ = lc.eltw_input();

      sig_.input(lc);
      dpk_sig_.input(lc);

      nb_ = lc.template vinput<8>();

      // sha input init =========================
      for (size_t i = 0; i < 64 * kMaxSHABlocks; ++i) {
        in_[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < kMaxSHABlocks; j++) {
        sig_sha_[j].input(lc);
      }
    }
  };

  struct OpenedAttribute {
    v8 ind;    /* index of attribute */
    v8 len;    /* length of attribute, 1--32 */
    v8 v1[32]; /* attribute value */
    void input(const LogicCircuit& lc) {
      ind = lc.template vinput<8>();
      len = lc.template vinput<8>();
      for (size_t j = 0; j < 32; ++j) {
        v1[j] = lc.template vinput<8>();
      }
    }
  };

  EltW repack(const v8 in[], size_t ind) const {
    EltW h = lc_.konst(0);
    EltW base = lc_.konst(0x2);
    for (size_t i = 0; i < 32; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        auto t = lc_.mul(h, base);
        auto tin = lc_.eval(in[ind + i][7 - j]);
        h = lc_.add(tin, t);
      }
    }
    return h;
  }

  explicit PtrCred(const LogicCircuit& lc, const EC& ec, const Nat& order)
      : lc_(lc), ec_(ec), order_(order), sha_(lc), r_(lc) {}

  void assert_credential(EltW pkX, EltW pkY, EltW hash_tr,
                         OpenedAttribute oa[/* NUM_ATTR */],
                         const v8 now[/*kDateLen*/], const Witness& vw) const {
    Ecdsa ecc(lc_, ec_, order_);

    ecc.verify_signature3(pkX, pkY, vw.e_, vw.sig_);
    ecc.verify_signature3(vw.dpkx_, vw.dpky_, hash_tr, vw.dpk_sig_);
    sha_.assert_message(kMaxSHABlocks, vw.nb_, vw.in_, vw.sig_sha_);

    const Memcmp<LogicCircuit> CMP(lc_);
    // validFrom <= now
    lc_.assert1(CMP.leq(kDateLen, &vw.in_[84], &now[0]));

    // now <= validUntil
    lc_.assert1(CMP.leq(kDateLen, &now[0], &vw.in_[92]));

    // DPK_{x,y}
    EltW dpkx = repack(vw.in_, 100);
    EltW dpky = repack(vw.in_, 132);
    lc_.assert_eq(dpkx, vw.dpkx_);
    lc_.assert_eq(dpky, vw.dpky_);

    // Attributes parsing
    const v8 zz = lc_.template vbit<8>(0xff);  // cannot appear in strings
    std::vector<v8> cmp_buf(32);
    for (size_t ai = 0; ai < kNumAttr; ++ai) {
      r_.shift(oa[ai].ind, 32, &cmp_buf[0], kMaxMsoLen, vw.in_, zz, 3);
      assert_attribute(32, oa[ai].len, &cmp_buf[0], &oa[ai].v1[0]);
    }
  }

 private:
  // Checks that an attribute id or attribute value is as expected.
  // The len parameter holds the byte length of the expected id or value.
  void assert_attribute(size_t max, const v8& vlen, const v8 got[/*max*/],
                        const v8 want[/*max*/]) const {
    for (size_t j = 0; j < max; ++j) {
      auto ll = lc_.vlt(j, vlen);
      auto cmp = lc_.veq(got[j], want[j]);
      lc_.assert_implies(ll, cmp);
    }
  }

  Flatsha sha_;
  RoutingL r_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_ANONCRED_PTRCRED_H_
