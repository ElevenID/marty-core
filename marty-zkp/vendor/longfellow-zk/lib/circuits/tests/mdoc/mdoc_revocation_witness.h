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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_REVOCATION_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_REVOCATION_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "arrays/dense.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/tests/mdoc/mdoc_revocation_constants.h"

namespace proofs {

template <class Field>
typename Field::Elt compute_mdoc_revocation_list_witness(
    typename Field::Elt id, const typename Field::Elt list[], size_t list_size,
    const Field& F) {
  typename Field::Elt prodinv = F.one();
  for (size_t i = 0; i < list_size; ++i) {
    prodinv = F.mulf(prodinv, F.subf(list[i], id));
  }
  F.invert(prodinv);
  return prodinv;
}

template <class EC, class ScalarField>
class MdocRevocationSpanWitness {
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  using EcdsaWitness = VerifyWitness3<EC, ScalarField>;
  const EC& ec_;

 public:
  Elt e_, r_, s_;
  EcdsaWitness sig_;
  uint8_t preimage_[64 * 2];
  uint8_t id_bits_[256];
  uint8_t e_bits_[256];
  FlatSHA256Witness::BlockWitness sha_bw_[2];

  explicit MdocRevocationSpanWitness(const EC& ec, const ScalarField& Fn)
      : ec_(ec), sig_(Fn, ec) {}

  void fill_witness(DenseFiller<Field>& filler) const {
    filler.push_back(r_);
    filler.push_back(s_);
    filler.push_back(e_);
    sig_.fill_witness(filler);

    // Write the span message.
    for (size_t i = 0; i < 64 * 2; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        filler.push_back((preimage_[i] >> j) & 0x1 ? ec_.f_.one()
                                                   : ec_.f_.zero());
      }
    }

    for (size_t i = 0; i < 256; ++i) {
      filler.push_back(id_bits_[i] ? ec_.f_.one() : ec_.f_.zero());
    }
    for (size_t i = 0; i < 256; ++i) {
      filler.push_back(e_bits_[i] ? ec_.f_.one() : ec_.f_.zero());
    }

    for (size_t j = 0; j < 2; j++) {
      fill_sha(filler, sha_bw_[j]);
    }
  }

  void fill_sha(DenseFiller<Field>& filler,
                const FlatSHA256Witness::BlockWitness& bw) const {
    BitPluckerEncoder<Field, kSHARevocationPluckerBits> BPENC(ec_.f_);
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

  bool compute_witness(Elt pkX, Elt pkY, Nat ne, Nat nr, Nat ns, Nat id, Nat ll,
                       Nat rr, uint64_t epoch) {
    e_ = ec_.f_.to_montgomery(ne);
    r_ = ec_.f_.to_montgomery(nr);
    s_ = ec_.f_.to_montgomery(ns);
    sig_.compute_witness(pkX, pkY, ne, nr, ns);

    std::vector<uint8_t> buf;
    for (size_t i = 0; i < 8; ++i) {
      buf.push_back(epoch & 0xff);
      epoch >>= 8;
    }
    uint8_t tmp[Field::kBytes];
    ll.to_bytes(tmp);
    buf.insert(buf.end(), tmp, tmp + Field::kBytes);
    rr.to_bytes(tmp);
    buf.insert(buf.end(), tmp, tmp + Field::kBytes);

    for (size_t i = 0; i < 256; ++i) {
      id_bits_[i] = id.bit(i);
      e_bits_[i] = ne.bit(i);
    }

    uint8_t numb = 0;
    FlatSHA256Witness::transform_and_witness_message(buf.size(), buf.data(), 2,
                                                     numb, preimage_, sha_bw_);

    return true;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_REVOCATION_WITNESS_H_
