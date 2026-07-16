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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/cbor_parser/cbor.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/counter.h"
#include "circuits/logic/routing.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/tests/mdoc/mdoc_1f_io.h"
#include "util/panic.h"
namespace proofs {

template <class LogicCircuit, class Field, class EC, size_t kNumAttr>
class mdoc_1f {
  using EltW = typename LogicCircuit::EltW;
  using Elt = typename LogicCircuit::Elt;
  using Nat = typename Field::N;
  using Ecdsa = VerifyCircuit<LogicCircuit, Field, EC>;
  using EcdsaWitness = typename Ecdsa::Witness;

  using v8 = typename LogicCircuit::v8;
  using v32 = typename LogicCircuit::v32;
  using v256 = typename LogicCircuit::v256;
  using Flatsha =
      FlatSHA256Circuit<LogicCircuit,
                        BitPlucker<LogicCircuit, kMdoc1SHAPluckerBits>>;
  using RoutingL = Routing<LogicCircuit>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using sha_packed_v32 = typename Flatsha::packed_v32;
  using CborL = Cbor<LogicCircuit, kMdoc1CborIndexBits>;
  using vind = typename CborL::vindex;

  const LogicCircuit& lc_;
  const EC& ec_;
  const Nat& order_;

 public:
  struct CborIndex {
    vind k, v, ndx;
    void input(const LogicCircuit& lc) {
      k = lc.template vinput<kMdoc1CborIndexBits>();
      v = lc.template vinput<kMdoc1CborIndexBits>();
      ndx = lc.template vinput<kMdoc1CborIndexBits>();
    }
  };

  struct AttrShift {
    vind offset;
    vind len;
    void input(const LogicCircuit& lc) {
      offset = lc.template vinput<kMdoc1CborIndexBits>();
      len = lc.template vinput<kMdoc1CborIndexBits>();
    }
  };

  class Witness {
   public:
    EltW e_;
    EltW dpkx_, dpky_;

    EcdsaWitness sig_;
    EcdsaWitness dpk_sig_;

    v8 in_[64 * kMdoc1MaxSHABlocks]; /* input bytes, 64 * MAX */
    v8 nb_; /* index of sha block that contains the real hash  */
    ShaBlockWitness sig_sha_[kMdoc1MaxSHABlocks];

    size_t num_attr_;

    std::vector<std::vector<ShaBlockWitness>> attr_sha_;
    std::vector<std::vector<v8>> attrb_;

    std::vector<CborIndex> attr_mso_;
    std::vector<AttrShift> attr_ei_;
    std::vector<AttrShift> attr_ev_;

    std::vector<v8> incb_;
    std::vector<typename CborL::position_witness> pwcb_;
    typename CborL::global_witness gwcb_;

    vind prepad_, mso_len_;

    CborIndex valid_, valid_from_, valid_until_;
    CborIndex dev_key_info_, dev_key_, dev_key_pkx_, dev_key_pky_;
    CborIndex value_digests_, org_;

    explicit Witness(size_t num_attr)
        : num_attr_(num_attr),
          attr_sha_(num_attr),
          attrb_(num_attr),
          attr_mso_(num_attr),
          attr_ei_(num_attr),
          attr_ev_(num_attr),
          incb_(kMdoc1MaxMsoLen),
          pwcb_(kMdoc1MaxMsoLen) {
      for (size_t i = 0; i < num_attr; ++i) {
        attr_sha_[i].resize(2);
      }
    }

    void input(const LogicCircuit& lc) {
      const Counter<LogicCircuit> CTRC(lc);

      e_ = lc.eltw_input();
      dpkx_ = lc.eltw_input();
      dpky_ = lc.eltw_input();

      sig_.input(lc);
      dpk_sig_.input(lc);

      nb_ = lc.template vinput<8>();

      // sha input init (skip the prefix) =========================
      for (size_t i = 0; i + kCose1PrefixLen < 64 * kMdoc1MaxSHABlocks; ++i) {
        in_[i] = lc.template vinput<8>();
      }

      for (size_t j = 0; j < kMdoc1MaxSHABlocks; j++) {
        sig_sha_[j].input(lc);
      }

      // Cbor input init: note, the inC array will be constructed in the
      // circuit.
      prepad_ = lc.template vinput<kMdoc1CborIndexBits>();
      mso_len_ = lc.template vinput<kMdoc1CborIndexBits>();
      for (size_t i = 0; i < kMdoc1MaxMsoLen; ++i) {
        pwcb_[i].encoded_sel_header = lc.eltw_input();
      }
      gwcb_.invprod_decode = lc.eltw_input();
      gwcb_.cc0_counter = CTRC.input();
      gwcb_.invprod_parse = lc.eltw_input();

      valid_.input(lc);
      valid_from_.input(lc);
      valid_until_.input(lc);
      dev_key_info_.input(lc);
      dev_key_.input(lc);
      dev_key_pkx_.input(lc);
      dev_key_pky_.input(lc);
      value_digests_.input(lc);
      org_.input(lc);

      // Attribute opening witnesses
      for (size_t ai = 0; ai < num_attr_; ++ai) {
        for (size_t i = 0; i < 64 * 2; ++i) {
          attrb_[ai].push_back(lc.template vinput<8>());
        }
        for (size_t j = 0; j < 2; j++) {
          attr_sha_[ai][j].input(lc);
        }
        attr_mso_[ai].input(lc);
        attr_ei_[ai].input(lc);
        attr_ev_[ai].input(lc);
      }
    }
  };

  struct OpenedAttribute {
    v8 attr[96];  // representing attribute name, elementValue delimiter, and
                  // finally the attribute value.
    v8 len;
    void input(const LogicCircuit& lc) {
      for (size_t j = 0; j < 96; ++j) {
        attr[j] = lc.template vinput<8>();
      }
      len = lc.template vinput<8>();
    }
  };

  struct PathEntry {
    CborIndex ind;
    size_t l;
    const uint8_t* name;
  };

  explicit mdoc_1f(const LogicCircuit& lc, const EC& ec, const Nat& order)
      : lc_(lc), ec_(ec), order_(order), sha_(lc), r_(lc), cbor_(lc) {}

  void assert_credential(EltW pkX, EltW pkY, EltW hash_tr,
                         OpenedAttribute oa[/* NUM_ATTR */],
                         const v8 now[/*kDateLen*/], const Witness& vw) const {
    Ecdsa ecc(lc_, ec_, order_);

    ecc.verify_signature3(pkX, pkY, vw.e_, vw.sig_);
    ecc.verify_signature3(vw.dpkx_, vw.dpky_, hash_tr, vw.dpk_sig_);

    // Construct the message to hash by concatenating the prefix and the input.
    std::vector<v8> bbuf(64 * kMdoc1MaxSHABlocks);
    for (size_t i = 0; i < 64 * kMdoc1MaxSHABlocks; ++i) {
      if (i < kCose1PrefixLen) {
        lc_.bits(8, bbuf[i].data(), kCose1Prefix[i]);
      } else {
        bbuf[i] = vw.in_[i - kCose1PrefixLen];
      }
    }
    sha_.assert_message(kMdoc1MaxSHABlocks, vw.nb_, bbuf.data(), vw.sig_sha_);
    // Verify that the hash of the mdoc is equal to e.
    assert_hash(vw.e_, vw);

    // Shift a portion of the MSO into buf and check it.
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings
    std::vector<v8> cmp_buf(kMdoc1MaxMsoLen);

    // Re-arrange the input wires to produce the <0 padded><mso> input
    // required for cbor parsing.  The subtracted 5 corresponds to the fix
    // length D8 18 <len2> prefix of the mso that we want to skip parsing.
    // The subtracted 2 corresponds to the length.
    std::vector<v8> in_cb(kMdoc1MaxMsoLen);
    r_.unshift(vw.prepad_, kMdoc1MaxMsoLen, in_cb.data(),
               kMdoc1MaxMsoLen - 5 - 2, vw.in_ + 5 + 2, zz, 3);

    std::vector<typename CborL::decode> dsC(kMdoc1MaxMsoLen);
    std::vector<typename CborL::parse_output> psC(kMdoc1MaxMsoLen);
    cbor_.decode_and_assert_decode_and_parse(kMdoc1MaxMsoLen, dsC.data(),
                                             psC.data(), in_cb.data(),
                                             vw.pwcb_.data(), vw.gwcb_);

    cbor_.assert_input_starts_at(kMdoc1MaxMsoLen, vw.prepad_, vw.mso_len_,
                                 dsC.data());

    // Validity
    PathEntry vk[2] = {{vw.valid_, kValidityInfoLen, kValidityInfoID},
                       {vw.valid_from_, kValidFromLen, kValidFromID}};
    assert_path(2, vk, vw, dsC, psC);
    cbor_.assert_date_before_at(kMdoc1MaxMsoLen, vw.valid_from_.v, now,
                                dsC.data());

    // validUntil is a key in validityInfo.
    cbor_.assert_map_entry(kMdoc1MaxMsoLen, vw.valid_.v, 1, vw.valid_until_.k,
                           vw.valid_until_.v, vw.valid_until_.ndx, dsC.data(),
                           psC.data());
    cbor_.assert_text_at(kMdoc1MaxMsoLen, vw.valid_until_.k, kValidUntilLen,
                         kValidUntilID, dsC.data());
    cbor_.assert_date_after_at(kMdoc1MaxMsoLen, vw.valid_until_.v, now,
                               dsC.data());

    PathEntry dk[2] = {
        {vw.dev_key_info_, kDeviceKeyInfoLen, kDeviceKeyInfoID},
        {vw.dev_key_, kDeviceKeyLen, kDeviceKeyID}};
    assert_path(2, dk, vw, dsC, psC);
    cbor_.assert_map_entry(kMdoc1MaxMsoLen, vw.dev_key_.v, 2, vw.dev_key_pkx_.k,
                           vw.dev_key_pkx_.v, vw.dev_key_pkx_.ndx, dsC.data(),
                           psC.data());
    cbor_.assert_map_entry(kMdoc1MaxMsoLen, vw.dev_key_.v, 2, vw.dev_key_pky_.k,
                           vw.dev_key_pky_.v, vw.dev_key_pky_.ndx, dsC.data(),
                           psC.data());
    cbor_.assert_negative_at(kMdoc1MaxMsoLen, vw.dev_key_pkx_.k, 1, dsC.data());
    cbor_.assert_negative_at(kMdoc1MaxMsoLen, vw.dev_key_pky_.k, 2, dsC.data());
    assert_elt_as_be_bytes_at(kMdoc1MaxMsoLen, vw.dev_key_pkx_.v, 32, vw.dpkx_,
                              dsC.data());
    assert_elt_as_be_bytes_at(kMdoc1MaxMsoLen, vw.dev_key_pky_.v, 32, vw.dpky_,
                              dsC.data());
    // Attributes parsing
    PathEntry ak[2] = {
        {vw.value_digests_, kValueDigestsLen, kValueDigestsID},
        {vw.org_, kOrgLen, kOrgID}};
    assert_path(2, ak, vw, dsC, psC);

    // Attributes: Equality of hash with MSO value
    for (size_t ai = 0; ai < vw.num_attr_; ++ai) {
      auto two = lc_.template vbit<8>(2);
      v8 B[96];
      sha_.assert_message(2, two, vw.attrb_[ai].data(),
                          vw.attr_sha_[ai].data());

      // Check the hash matches the value in the signed MSO.
      cbor_.assert_map_entry(kMdoc1MaxMsoLen, vw.org_.v, 2, vw.attr_mso_[ai].k,
                             vw.attr_mso_[ai].v, vw.attr_mso_[ai].ndx,
                             dsC.data(), psC.data());
      EltW h = repack32(vw.attr_sha_[ai][1].h1);
      assert_elt_as_be_bytes_at(kMdoc1MaxMsoLen, vw.attr_mso_[ai].v, 32, h,
                                dsC.data());

      // Check that the attribute_id and value occur in the hashed text.
      r_.shift(vw.attr_ei_[ai].offset, 96, B, 128, vw.attrb_[ai].data(), zz, 3);
      assert_attribute(96, oa[ai].len, B, oa[ai].attr);
    }
  }

 private:
  // TODO [matteof 2025-08-01] packing a SHA256 hash into an
  // EltW loses some soundness, and there is no reason to do it.
  // Get rid of repack32() and compare the individual bits/bytes.
  EltW repack32(const sha_packed_v32 H[]) const {
    EltW h = lc_.konst(0);
    Elt twok = lc_.one();
    for (size_t j = 8; j-- > 0;) {
      auto hj = sha_.bp_.unpack_v32(H[j]);
      for (size_t k = 0; k < 32; ++k) {
        h = lc_.axpy(h, twok, lc_.eval(hj[k]));
        lc_.f_.add(twok, twok);
      }
    }
    return h;
  }

  // Assert that the hash of the mdoc is equal to e.
  // The hash is encoded in the SHA witness, and thus the correct block
  // must be muxed for the comparison. Thus method first muxes the "packed"
  // encoding of the SHA witness, then unpacks it and compares it to e to
  // save a lot of work in the bit plucker.
  void assert_hash(const EltW& e, const Witness& vw) const {
    sha_packed_v32 x[8];
    for (size_t b = 0; b < kMdoc1MaxSHABlocks; ++b) {
      auto bt = lc_.veq(vw.nb_, b + 1); /* b is zero-indexed */
      auto ebt = lc_.eval(bt);
      for (size_t i = 0; i < 8; ++i) {
        for (size_t k = 0; k < sha_.bp_.kNv32Elts; ++k) {
          if (b == 0) {
            x[i][k] = lc_.mul(ebt, vw.sig_sha_[b].h1[i][k]);
          } else {
            auto maybe_sha = lc_.mul(ebt, vw.sig_sha_[b].h1[i][k]);
            x[i][k] = lc_.add(x[i][k], maybe_sha);
          }
        }
      }
    }

    EltW h = repack32(x);
    lc_.assert_eq(h, e);
  }

  // Checks that an attribute id or attribute value is as expected.
  // The len parameter holds the byte length of the expected id or value.
  void assert_attribute(size_t max, const v8& len, const v8 got[/*max*/],
                        const v8 want[/*max*/]) const {
    // auto two = lc_.konst(2);
    for (size_t j = 0; j < max; ++j) {
      auto ll = lc_.vlt(j, len);
      auto same = lc_.eq(8, got[j].data(), want[j].data());
      lc_.assert_implies(ll, same);
    }
  }

  void assert_path(size_t len, PathEntry p[], const Witness& vw,
                   std::vector<typename CborL::decode>& dsC,
                   std::vector<typename CborL::parse_output>& psC) const {
    vind start(vw.prepad_);
    for (size_t i = 0; i < len; ++i) {
      cbor_.assert_map_entry(kMdoc1MaxMsoLen, start, i, p[i].ind.k, p[i].ind.v,
                             p[i].ind.ndx, dsC.data(), psC.data());
      cbor_.assert_text_at(kMdoc1MaxMsoLen, p[i].ind.k, p[i].l, p[i].name,
                           dsC.data());
      start = p[i].ind.v;
    }
  }

  void assert_elt_as_be_bytes_at(size_t n, const vind& j, size_t len, EltW X,
                                 const typename CborL::decode ds[/*n*/]) const {
    const LogicCircuit& LC = lc_;  // shorthand

    std::vector<EltW> A(n);
    for (size_t i = 0; i < n; ++i) {
      A[i] = ds[i].bd.as_scalar;
    }
    EltW tx = LC.konst(0), k256 = LC.konst(256);

    std::vector<EltW> B(2 + len);
    size_t unroll = 3;
    size_t si = 1;
    r_.shift(j, len + 2, B.data(), n, A.data(), LC.konst(0), unroll);
    if (len < 24) {
      size_t expected_header = (2 << 5) + len;
      auto eh = LC.konst(expected_header);
      LC.assert_eq(B[0], eh);
    } else if (len < 256) {
      size_t expected_header = (2 << 5) + 24;
      auto eh = LC.konst(expected_header);
      LC.assert_eq(B[0], eh);
      LC.assert_eq(B[1], LC.konst(len));
      si = 2;
    } else {
      check(false, "len >= 256");
    }

    for (size_t i = 0; i < len; ++i) {
      auto tmp = LC.mul(tx, k256);
      tx = LC.add(tmp, B[i + si]);
    }

    LC.assert_eq(tx, X);
  }

  Flatsha sha_;
  RoutingL r_;
  CborL cbor_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_H_
