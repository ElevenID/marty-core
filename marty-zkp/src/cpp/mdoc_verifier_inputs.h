// Verifier-only public-input helpers extracted from Longfellow's mdoc_witness.h.
// This intentionally excludes document parsing, private witnesses, prover state,
// signing material, and secure randomness from verifier-only builds.

#ifndef MARTY_ZKP_MDOC_VERIFIER_INPUTS_H_
#define MARTY_ZKP_MDOC_VERIFIER_INPUTS_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "util/crypto.h"
#include "util/log.h"
#include "util/panic.h"

namespace proofs {

template <typename GF, typename Field>
void fill_gf2k(const typename GF::Elt& m, DenseFiller<Field>& df,
               const Field& f) {
  for (size_t i = 0; i < GF::kBits; ++i) {
    df.push_back(m[i] ? f.one() : f.zero());
  }
}

template <class Nat>
Nat nat_from_be(const uint8_t be[/* Nat::kBytes */]) {
  uint8_t tmp[Nat::kBytes];
  for (size_t i = 0; i < Nat::kBytes; ++i) {
    tmp[i] = be[Nat::kBytes - i - 1];
  }
  return Nat::of_bytes(tmp);
}

template <typename Nat>
Nat nat_from_hash(const uint8_t data[], size_t len) {
  uint8_t hash[kSHA256DigestSize];
  SHA256 sha;
  sha.Update(data, len);
  sha.DigestData(hash);
  return nat_from_be<Nat>(hash);
}

static inline void append_bytes_len(std::vector<uint8_t>& buf, size_t len) {
  check(len < 65536, "Bytestring length too large");
  if (len < 24) {
    buf.push_back(0x40 + len);
  } else if (len < 256) {
    uint8_t ll[] = {0x58, static_cast<uint8_t>(len & 0xff)};
    buf.insert(buf.end(), ll, ll + 2);
  } else {
    uint8_t ll[] = {0x59, static_cast<uint8_t>((len >> 8) & 0xff),
                    static_cast<uint8_t>(len & 0xff)};
    buf.insert(buf.end(), ll, ll + 3);
  }
}

static inline void append_text_len(std::vector<uint8_t>& buf, size_t len) {
  check(len < 256, "Text length too large");
  if (len < 24) {
    buf.push_back(0x60 + len);
  } else {
    buf.push_back(0x78);
    buf.push_back(static_cast<uint8_t>(len));
  }
}

template <class Nat>
static Nat compute_transcript_hash(
    const uint8_t transcript[], size_t len,
    const std::vector<uint8_t>* docType = nullptr) {
  std::vector<uint8_t> deviceAuthentication = {
      0x84, 0x74, 'D', 'e', 'v', 'i', 'c', 'e', 'A', 'u', 't',
      'h',  'e',  'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n',
  };
  std::vector<uint8_t> docTypeBytes = {
      0x75, 'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8',
      '0',  '1', '3', '.', '5', '.', '1', '.', 'm', 'D', 'L',
  };
  const std::vector<uint8_t> deviceNameSpacesBytes = {0xD8, 0x18, 0x41, 0xA0};

  if (docType != nullptr && docType->size() < 256) {
    docTypeBytes.clear();
    append_text_len(docTypeBytes, docType->size());
    docTypeBytes.insert(docTypeBytes.end(), docType->begin(), docType->end());
  }

  std::vector<uint8_t> da(deviceAuthentication);
  da.insert(da.end(), transcript, transcript + len);
  da.insert(da.end(), docTypeBytes.begin(), docTypeBytes.end());
  da.insert(da.end(), deviceNameSpacesBytes.begin(), deviceNameSpacesBytes.end());

  std::vector<uint8_t> cose1{0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E,
                             0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
                             0x43, 0xA1, 0x01, 0x26, 0x40};
  const uint8_t tag[] = {0xD8, 0x18};
  const size_t l1 = da.size();
  const size_t l2 = l1 + (l1 < 256 ? 4 : 5);
  append_bytes_len(cose1, l2);
  cose1.insert(cose1.end(), tag, tag + 2);
  append_bytes_len(cose1, l1);
  cose1.insert(cose1.end(), da.begin(), da.end());
  return nat_from_hash<Nat>(cose1.data(), cose1.size());
}

template <class Field>
void fill_byte(std::vector<typename Field::Elt>& v, uint8_t b, size_t i,
               const Field& F) {
  for (size_t j = 0; j < 8; ++j) {
    v[i * 8 + j] = (b >> j & 0x1) ? F.one() : F.zero();
  }
}

template <class Field>
void fill_bit_string(DenseFiller<Field>& filler, const uint8_t s[/*len*/],
                     size_t len, size_t max, const Field& Fs) {
  std::vector<typename Field::Elt> v(max * 8, Fs.of_scalar(2));
  for (size_t i = 0; i < max && i < len; ++i) {
    fill_byte(v, s[i], i, Fs);
  }
  filler.push_back(v);
}

template <class Field>
MdocProverErrorCode fill_attribute(DenseFiller<Field>& filler,
                                   const RequestedAttribute& attr,
                                   const Field& F, size_t version) {
  std::vector<typename Field::Elt> v(96 * 8, F.zero());
  if (version >= 7) {
    std::vector<uint8_t> vbuf;
    append_text_len(vbuf, attr.id_len);
    vbuf.insert(vbuf.end(), attr.id, attr.id + attr.id_len);
    for (size_t j = 0; j < vbuf.size() && j < 32; ++j) {
      fill_byte(v, vbuf[j], j, F);
    }
    for (size_t j = 0; j < 64 && j < attr.cbor_value_len; ++j) {
      fill_byte(v, attr.cbor_value[j], 32 + j, F);
    }
    filler.push_back(v);
    filler.push_back(1 + 17 + 1 + attr.id_len, 8, F);
    filler.push_back(attr.cbor_value_len + 12 + 1, 8, F);
  } else {
    std::vector<uint8_t> vbuf;
    append_text_len(vbuf, attr.id_len);
    vbuf.insert(vbuf.end(), attr.id, attr.id + attr.id_len);
    append_text_len(vbuf, 12);
    const char* ev = "elementValue";
    vbuf.insert(vbuf.end(), ev, ev + 12);
    vbuf.insert(vbuf.end(), attr.cbor_value,
                attr.cbor_value + attr.cbor_value_len);
    if (vbuf.size() > 96) {
      log(ERROR, "Attribute %s is too long: %zu", attr.id, vbuf.size());
      return MDOC_PROVER_ATTRIBUTE_TOO_LONG;
    }
    size_t len = 0;
    for (size_t j = 0; j < vbuf.size() && len < 96; ++j, ++len) {
      fill_byte(v, vbuf[j], len, F);
    }
    filler.push_back(v);
    filler.push_back(len, 8, F);
  }
  return MDOC_PROVER_SUCCESS;
}

}  // namespace proofs

#endif  // MARTY_ZKP_MDOC_VERIFIER_INPUTS_H_
