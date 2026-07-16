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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "arrays/dense.h"
#include "circuits/cbor_parser/cbor_witness.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/tests/mdoc/mdoc_1f_io.h"
namespace proofs {

template <typename EC, typename Field, class ScalarField>
class mdoc_1f_witness {
  using ECField = typename EC::Field;
  using ECElt = typename ECField::Elt;
  using ECNat = typename ECField::N;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  using EcdsaWitness = VerifyWitness3<EC, ScalarField>;
  using CborWitnessF = CborWitness<Field>;

 public:
  const EC ec_;
  Elt e_, e2_;      /* Issuer signature values. */
  Elt dpkx_, dpky_; /* device key */
  EcdsaWitness ew_, dkw_;
  uint8_t now_[kMdoc1DateLen]; /* CBOR-formatted time for expiry comparison. */

  FlatSHA256Witness::BlockWitness bw_[kMdoc1MaxSHABlocks];
  uint8_t signed_bytes_[kMdoc1MaxSHABlocks * 64];
  uint8_t numb_; /* Number of the correct sha block. */
  ParsedMdoc pm_;

  size_t num_attr_;
  std::vector<std::vector<uint8_t>> attr_bytes_;
  std::vector<std::vector<FlatSHA256Witness::BlockWitness>> atw_;

  std::vector<uint8_t> attr_n_; /* All attributes currently require 2 SHA. */
  std::vector<CborIndex> attr_mso_; /* The cbor indices of the attributes. */
  std::vector<AttrShift> attr_ei_;
  std::vector<AttrShift> attr_ev_;

  // Cbor parsing witnesses
  std::vector<typename CborWitnessF::v8> incb_;
  std::vector<typename CborWitnessF::position_witness> pwcb_;
  typename CborWitnessF::global_witness gwcb_;

  explicit mdoc_1f_witness(size_t num_attr, const EC& ec, const ScalarField& Fn)
      : ec_(ec),
        ew_(Fn, ec),
        dkw_(Fn, ec),
        num_attr_(num_attr),
        attr_bytes_(num_attr_),
        atw_(num_attr_),
        attr_n_(num_attr_),
        attr_mso_(num_attr_),
        attr_ei_(num_attr_),
        attr_ev_(num_attr_),
        incb_(kMdoc1MaxMsoLen),
        pwcb_(kMdoc1MaxMsoLen) {}

  void fill_sha(DenseFiller<Field>& filler,
                const FlatSHA256Witness::BlockWitness& bw) const {
    BitPluckerEncoder<Field, kMdoc1SHAPluckerBits> BPENC(ec_.f_);
    for (size_t k = 0; k < 48; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.oute[k]));
      filler.push_back(BPENC.mkpacked_v32(bw.outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.h1[k]));
    }
  }

  void fill_attr_shift(DenseFiller<Field>& df, const AttrShift& attr) const {
    df.push_back(attr.offset, kMdoc1CborIndexBits, ec_.f_);
    df.push_back(attr.len, kMdoc1CborIndexBits, ec_.f_);
  }

  // The cbor index that is computed by our witness maker is with reference
  // to the beginning of the cbor string. However the convention for the cbor
  // parser is to 0-pad from the left to fill the full cbor string buffer.
  // As a result, all cbor indices need to be offset by the padding length.
  void fill_cbor_index(DenseFiller<Field>& filler, const CborIndex& ind,
                       size_t padding_offset = 0) const {
    filler.push_back(ind.k + padding_offset, kMdoc1CborIndexBits, ec_.f_);
    filler.push_back(ind.v + padding_offset, kMdoc1CborIndexBits, ec_.f_);
    filler.push_back(ind.ndx, kMdoc1CborIndexBits, ec_.f_);
  }

  void fill_witness(DenseFiller<Field>& filler, bool small = false) const {
    filler.push_back(e_);
    filler.push_back(dpkx_);
    filler.push_back(dpky_);

    ew_.fill_witness(filler);
    dkw_.fill_witness(filler);

    filler.push_back(numb_, 8, ec_.f_);
    for (size_t i = kCose1PrefixLen; i < kMdoc1MaxSHABlocks * 64; ++i) {
      filler.push_back(signed_bytes_[i], 8, ec_.f_);
    }
    for (size_t j = 0; j < kMdoc1MaxSHABlocks; j++) {
      fill_sha(filler, bw_[j]);
    }

    size_t prepad = kMdoc1MaxMsoLen - pm_.t_mso_.len + 5;
    filler.push_back(prepad, kMdoc1CborIndexBits, ec_.f_);
    filler.push_back(pm_.t_mso_.len - 5, kMdoc1CborIndexBits, ec_.f_);
    for (size_t i = 0; i < kMdoc1MaxMsoLen; ++i) {
      filler.push_back(pwcb_[i].encoded_sel_header);
    }
    filler.push_back(gwcb_.invprod_decode);
    filler.push_back(gwcb_.cc0_counter.e);
    filler.push_back(gwcb_.invprod_parse);

    fill_cbor_index(filler, pm_.valid_, prepad);
    fill_cbor_index(filler, pm_.valid_from_, prepad);
    fill_cbor_index(filler, pm_.valid_until_, prepad);
    fill_cbor_index(filler, pm_.dev_key_info_, prepad);
    fill_cbor_index(filler, pm_.dev_key_, prepad);
    fill_cbor_index(filler, pm_.dev_key_pkx_, prepad);
    fill_cbor_index(filler, pm_.dev_key_pky_, prepad);
    fill_cbor_index(filler, pm_.value_digests_, prepad);
    fill_cbor_index(filler, pm_.org_, prepad);

    // Fill all attribute witnesses.
    for (size_t ai = 0; ai < num_attr_; ++ai) {
      for (size_t i = 0; i < 2 * 64; ++i) {
        filler.push_back(attr_bytes_[ai][i], 8, ec_.f_);
      }
      for (size_t j = 0; j < 2; j++) {
        fill_sha(filler, atw_[ai][j]);
      }

      // In the case of attribute mso, push the value to avoid having to
      // deal with 1- or 2- byte key length.
      // fill_cbor_index(filler, pm_.value_digests_);
      fill_cbor_index(filler, attr_mso_[ai], prepad);
      fill_attr_shift(filler, attr_ei_[ai]);
      fill_attr_shift(filler, attr_ev_[ai]);
    }
  }

  MdocProverErrorCode compute_witness(Elt pkX, Elt pkY,
                                      const uint8_t mdoc[/* len */], size_t len,
                                      const uint8_t transcript[/* tlen */],
                                      size_t tlen,
                                      const uint8_t tnow[/*kMdoc1DateLen*/],
                                      const RequestedAttribute attrs[],
                                      size_t attrs_len) {
    MdocProverErrorCode err = pm_.parse_device_response(len, mdoc);
    if (err != MDOC_PROVER_SUCCESS) {
      return err;
    }

    if (pm_.t_mso_.len >= kMdoc1MaxSHABlocks * 64 - 9 - kCose1PrefixLen) {
      return MDOC_PROVER_TAGGED_MSO_TOO_BIG;
    }

    Nat ne = nat_from_hash<Nat>(pm_.tagged_mso_bytes_.data(),
                                pm_.tagged_mso_bytes_.size());
    e_ = ec_.f_.to_montgomery(ne);

    // Parse (r,s).
    const size_t l = pm_.sig_.len;
    Nat nr = nat_from_be<Nat>(&mdoc[pm_.sig_.pos]);
    Nat ns = nat_from_be<Nat>(&mdoc[pm_.sig_.pos + l / 2]);
    if (!ew_.compute_witness(pkX, pkY, ne, nr, ns)) {
      return MDOC_PROVER_SIGNATURE_FAILURE;
    }

    Nat ne2 = compute_transcript_hash<Nat>(transcript, tlen, &pm_.doc_type_);
    const size_t l2 = pm_.dksig_.len;
    Nat nr2 = nat_from_be<Nat>(&mdoc[pm_.dksig_.pos]);
    Nat ns2 = nat_from_be<Nat>(&mdoc[pm_.dksig_.pos + l2 / 2]);
    size_t pmso = pm_.t_mso_.pos + 5; /* skip the tag */
    dpkx_ = ec_.f_.to_montgomery(
        nat_from_be<Nat>(&mdoc[pmso + pm_.dev_key_pkx_.pos]));
    dpky_ = ec_.f_.to_montgomery(
        nat_from_be<Nat>(&mdoc[pmso + pm_.dev_key_pky_.pos]));
    e2_ = ec_.f_.to_montgomery(ne2);
    if (!dkw_.compute_witness(dpkx_, dpky_, ne2, nr2, ns2)) {
      return MDOC_PROVER_DEVICE_SIGNATURE_FAILURE;
    }

    memcpy(now_, tnow, kMdoc1DateLen);
    std::vector<uint8_t> buf;

    buf.assign(std::begin(kCose1Prefix), std::end(kCose1Prefix));
    // Add 2-byte length
    buf.push_back((pm_.t_mso_.len >> 8) & 0xff);
    buf.push_back(pm_.t_mso_.len & 0xff);
    for (size_t i = 0; i < pm_.t_mso_.len; ++i) {
      buf.push_back(mdoc[pm_.t_mso_.pos + i]);
    }

    FlatSHA256Witness::transform_and_witness_message(
        buf.size(), buf.data(), kMdoc1MaxSHABlocks, numb_, signed_bytes_, bw_);

    // Cbor parsing.
    // The input is expected to be pre-padded with zeros.
    // The +5 corresponds to the D8 18 59 <len2> prefix.
    size_t prepad = kMdoc1MaxMsoLen - pm_.t_mso_.len + 5;
    // Pad with enough 0s.
    buf.erase(buf.begin(), buf.begin() + kCose1PrefixLen + 2 + 5);
    buf.insert(buf.begin(), prepad, 0);

    CborWitnessF cw(ec_.f_);
    cw.fill_witnesses(kMdoc1MaxMsoLen, pm_.t_mso_.len, buf.data(), incb_.data(),
                      pwcb_.data(), gwcb_);

    // initialize variables
    for (size_t i = 0; i < num_attr_; ++i) {
      attr_bytes_[i].resize(128);
      atw_[i].resize(2);
    }

    // Match the attributes with the witnesses from the deviceResponse.
    for (size_t i = 0; i < num_attr_; ++i) {
      bool found = false;
      for (auto fa : pm_.attributes_) {
        if (fa == attrs[i]) {
          FlatSHA256Witness::transform_and_witness_message(
              fa.tag_len, &fa.doc[fa.tag_ind], 2, attr_n_[i],
              &attr_bytes_[i][0], &atw_[i][0]);
          attr_mso_[i] = fa.mso;
          attr_ei_[i].offset = fa.id_ind - fa.tag_ind;

          // Apply the offset fix from cl/786482988. The length of the element
          // identifier is pre-pended to the attribute comparison string. This
          // requires adding either 1 or 2 bytes depending on the cbor encoding.
          attr_ei_[i].offset -= 1;
          if (fa.id_len > 23) {
            attr_ei_[i].offset -= 1;
          }
          attr_ei_[i].len = fa.witness_length(attrs[i]);
          attr_ev_[i].offset = fa.val_ind - fa.tag_ind;
          attr_ev_[i].len = fa.val_len;
          found = true;
          break;
        }
      }
      if (!found) {
        return MDOC_PROVER_ATTRIBUTE_NOT_FOUND;
      }
    }
    return MDOC_PROVER_SUCCESS;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_WITNESS_H_
