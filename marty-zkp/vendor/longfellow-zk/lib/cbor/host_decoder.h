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

#ifndef PRIVACY_PROOFS_ZK_LIB_CBOR_HOST_DECODER_H_
#define PRIVACY_PROOFS_ZK_LIB_CBOR_HOST_DECODER_H_

#include <stddef.h>
#include <string.h>

#include <cstdint>
#include <vector>

#include "util/panic.h"

namespace proofs {

enum CborTag { UNSIGNED, NEGATIVE, BYTES, TEXT, ARRAY, MAP, TAG, PRIMITIVE };
enum CborPrimitive { CFALSE, CTRUE, CNULL };

namespace cbor_internal {

inline bool count_fits(size_t pos, size_t len, size_t count,
                       size_t items_per_entry) {
  return items_per_entry != 0 && pos <= len &&
         count <= (len - pos) / items_per_entry;
}

}  // namespace cbor_internal

// CBOR decoder for a subset of CBOR used in MDOC.
//
// The main advantage of this decoder is that it keeps
// offsets into the input, which is useful because we need to
// generate circuits that depend on input offsets.
//
// The other security advantage is the smaller codebase, versus
// relying on an imported CBOR parser that handles a larger subset of CBOR
// that may introduce issues.
//
// The decode function is used to process an untrusted array of bytes.
// The method returns false if the input is not processed exactly per the
// MDOC spec with only attributes in the org.iso.18013.5.1 namespace.
// The resulting CborDoc object is static, and it is assumed that neither the
// input doc, nor the tree structure changes. All of the lookup and index
// methods return const pointers to attempt to maintain this property.
class CborDoc {
 public:
  struct CborString {
    size_t pos;
    size_t len;
  };

  struct CborItems {
    size_t n;
    size_t nchildren;
  };

  struct LookupResult {
    const CborDoc* key;
    const CborDoc* val;
  };

  size_t header_pos() const { return header_pos_; }
  CborTag variant() const { return t_; }
  bool is_variant(CborTag target) const { return t_ == target; }

  uint64_t as_unsigned() const {
    check(t_ == UNSIGNED, "as_unsigned called on non-UNSIGNED type");
    return u_.u64;
  }

  CborPrimitive as_primitive() const {
    check(t_ == PRIMITIVE, "as_primitive called on non-PRIMITIVE type");
    return u_.p;
  }

  CborString as_bytes() const {
    check(t_ == BYTES, "as_bytes called on non-BYTES type");
    return u_.string;
  }

  CborString as_text() const {
    check(t_ == TEXT, "as_text called on non-TEXT type");
    return u_.string;
  }

  CborItems as_array() const {
    check(t_ == ARRAY, "as_array called on non-ARRAY type");
    return u_.items;
  }

  CborItems as_map() const {
    check(t_ == MAP, "as_map called on non-MAP type");
    return u_.items;
  }

  size_t as_tag() const {
    check(t_ == TAG, "as_tag called on non-TAG type");
    return u_.items.n;
  }

  const std::vector<CborDoc>& children() const {
    check(t_ == MAP || t_ == ARRAY, "children called on non-container type");
    return children_;
  }

  const CborDoc& tagged_value() const {
    check(t_ == TAG, "tagged_value called on non-TAG type");
    return children_[0];
  }

  // Returns the payload position and encoded value length for scalar mdoc
  // values. Unsupported containers and tags return false instead of aborting.
  bool value_span(size_t& position, size_t& length) const {
    switch (t_) {
      case UNSIGNED:
      case NEGATIVE: {
        uint64_t value = (t_ == UNSIGNED) ? u_.u64 : u_.n64;
        position = header_pos_;
        if (value < 24) {
          length = 1;
        } else if (value < 256) {
          length = 2;
        } else if (value < 65536) {
          length = 3;
        } else {
          length = 5;
        }
        return true;
      }
      case BYTES:
        position = as_bytes().pos;
        length = as_bytes().len;
        return true;
      case TEXT:
        position = as_text().pos;
        length = as_text().len;
        return true;
      case TAG: {
        const CborDoc& child = tagged_value();
        if (!child.is_variant(BYTES) && !child.is_variant(TEXT)) {
          return false;
        }
        return child.value_span(position, length);
      }
      case PRIMITIVE:
        position = header_pos_;
        length = 1;
        return true;
      default:
        return false;
    }
  }

  // Returns the complete encoded span, including the CBOR header, for scalar
  // values. This is useful when a caller must revalidate a nested value.
  bool encoded_span(size_t& position, size_t& length) const {
    position = header_pos_;
    size_t end;
    switch (t_) {
      case UNSIGNED:
      case NEGATIVE:
      case PRIMITIVE: {
        size_t value_position = 0;
        size_t value_length = 0;
        if (!value_span(value_position, value_length)) return false;
        end = value_position + value_length;
        break;
      }
      case BYTES:
        end = as_bytes().pos + as_bytes().len;
        break;
      case TEXT:
        end = as_text().pos + as_text().len;
        break;
      case TAG: {
        size_t child_position = 0;
        size_t child_length = 0;
        if (!tagged_value().encoded_span(child_position, child_length)) {
          return false;
        }
        end = child_position + child_length;
        break;
      }
      default:
        return false;
    }
    if (end < position) return false;
    length = end - position;
    return true;
  }

  // Parse a byte sequence into a CborDoc structure.
  //
  // Caller passes in the input sequence, the length of the
  // input, and pos and offset values. The offset value handles the case when
  // the input sequence is a sub-sequence of another string, as it is in
  // the MDOC and MSO parsing.
  //
  // This function can handle adversarial inputs, and returns false when the
  // input cannot be parsed.
  bool decode(const uint8_t in[], size_t len, size_t& pos, size_t offset) {
    /* invariant: pos is always compared with len before it is referenced. */
    header_pos_ = pos + offset;

    if (pos >= len) {
      return false;
    }
    uint8_t b = in[pos++];

    size_t type = (b >> 5) & 0x7u;
    size_t count0 = b & 0x1Fu;

    // variable-length count
    size_t count = 0;
    if (count0 < 24) {
      count = count0;
    } else if (count0 == 24) {
      if (pos >= len) {
        return false;
      }
      count = in[pos++];
    } else if (count0 == 25) {
      if (pos + 1 >= len) {
        return false;
      }
      count = in[pos] * 256 + in[pos + 1];
      pos += 2;
    } else if (count0 == 26) {
      if (pos + 3 >= len) {
        return false;
      }
      for (size_t i = 0; i < 4; ++i) {
        count *= 256;
        count += in[pos++];
      }
    } else {
      return false;
    }

    if ((count0 == 24 && count < 24) ||
        (count0 == 25 && count <= 0xff) ||
        (count0 == 26 && count <= 0xffff)) {
      return false;
    }

    switch (type) { /* type \in [0,7] by construction */
      case 0:
        t_ = UNSIGNED;
        u_.u64 = count;
        break;
      case 1:
        t_ = NEGATIVE;
        u_.n64 = count;
        break;

      case 2: /* BYTES */
      case 3: /* TEXT */
        if (!cbor_internal::count_fits(pos, len, count, 1)) {
          return false;
        }
        if (type == 3 && !valid_utf8(&in[pos], count)) {
          return false;
        }
        t_ = (type == 2) ? BYTES : TEXT;
        u_.string.pos = pos;
        u_.string.len = count;
        pos += count;
        break;

      case 4: /* ARRAY */
        if (!cbor_internal::count_fits(pos, len, count, 1)) {
          return false;
        }
        return decode_items(ARRAY, count, count, in, len, pos, offset);

      case 5: /* MAP, (key,val) pairs are stored as 2*children */
        if (!cbor_internal::count_fits(pos, len, count, 2)) {
          return false;
        }
        return decode_items(MAP, 2 * count, count, in, len, pos, offset);

      case 6: /* TAG */
        // Special cases for TAG
        if (count == 1004) {         // date in the form YYYY-MM-DD
          if (!cbor_internal::count_fits(pos, len, 11, 1)) {
            return false;
          }
        }
        return decode_items(TAG, 1, count, in, len, pos, offset);

      case 7: /* PRIMITIVE */
        t_ = PRIMITIVE;
        switch (count) {
          case 20:
            u_.p = CFALSE;
            break;
          case 21:
            u_.p = CTRUE;
            break;
          case 22:
            u_.p = CNULL;
            break;
          default:
            return false;
        }
        break;
    }

    return true;
  }

  // Lookup a child node in an array. Expects index to be within bounds.
  const CborDoc* aref(size_t index) const {
    if (t_ != ARRAY) return nullptr;
    if (index < u_.items.n) {
      return &children_[index];
    }
    return nullptr;
  }

  // Lookup a key in a map of type {bytes->elements}.
  // Returns null if the query is invalid.
  // The key is given as bytes with a length.
  // ndx is set to the child index of the located key.
  // The return pointer references the key, and the next object refers to
  // the value and is guaranteed to exist.
  LookupResult lookup(const uint8_t* const in, size_t len,
                      const uint8_t bytes[/*len*/], size_t& ndx) const {
    LookupResult result{nullptr, nullptr};
    if (t_ == MAP) {
      for (size_t i = 0; i < u_.items.n; ++i) {
        const CborDoc* key = &children_[2 * i];
        if (key->eq(in, len, bytes)) {
          if (result.key != nullptr) return LookupResult{nullptr, nullptr};
          ndx = i;
          result = LookupResult{key, &children_[2 * i + 1]};
        }
      }
    }
    return result;
  }

  // Lookup a key in a map of type {unsigned->object}.
  // Returns null if the query is invalid.
  LookupResult lookup_unsigned(uint64_t u64, size_t& ndx) const {
    LookupResult result{nullptr, nullptr};
    if (t_ == MAP) {
      for (size_t i = 0; i < u_.items.n; ++i) {
        const CborDoc* key = &children_[2 * i];
        if (key->t_ == UNSIGNED && key->u_.u64 == u64) {
          if (result.key != nullptr) return LookupResult{nullptr, nullptr};
          ndx = i;
          result = LookupResult{key, &children_[2 * i + 1]};
        }
      }
    }
    return result;
  }

  // Lookup a key in a map of type {negative->object}.
  // Returns null if the query is invalid.
  // N64 is the unsigned quantity stored in the CBOR document.
  // When interpreted as an integer, it encodes -1 - N64.
  LookupResult lookup_negative(uint64_t n64, size_t& ndx) const {
    LookupResult result{nullptr, nullptr};
    if (t_ == MAP) {
      for (size_t i = 0; i < u_.items.n; ++i) {
        const CborDoc* key = &children_[2 * i];
        if (key->t_ == NEGATIVE && key->u_.n64 == n64) {
          if (result.key != nullptr) return LookupResult{nullptr, nullptr};
          ndx = i;
          result = LookupResult{key, &children_[2 * i + 1]};
        }
      }
    }
    return result;
  }

  // Returns the index of the item with respect to the document bytes.
  // This function is only called once the input bytes are successfully
  // parsed; the check condition asserts this invariant.
  size_t position() const {
    size_t position = 0;
    size_t length = 0;
    check(value_span(position, length),
          "position() called on unsupported value type");
    return position;
  }

  // Returns the length of the item's value in bytes.
  // According to ISO 18013-5 7.2.1, the mDL data elements shall be encoded
  // as tstr, uint, bstr, bool, or tdate, so this function only handles those
  // cases. This function is only called after the source bytes have been
  // successfully parsed.
  size_t length() const {
    size_t position = 0;
    size_t length = 0;
    check(value_span(position, length),
          "length() called on unsupported value type");
    return length;
  }

 private:
  static bool valid_utf8(const uint8_t* input, size_t len) {
    size_t i = 0;
    while (i < len) {
      const uint8_t first = input[i++];
      if (first <= 0x7f) continue;

      size_t continuation_count;
      uint8_t second_min = 0x80;
      uint8_t second_max = 0xbf;
      if (first >= 0xc2 && first <= 0xdf) {
        continuation_count = 1;
      } else if (first >= 0xe0 && first <= 0xef) {
        continuation_count = 2;
        if (first == 0xe0) second_min = 0xa0;
        if (first == 0xed) second_max = 0x9f;
      } else if (first >= 0xf0 && first <= 0xf4) {
        continuation_count = 3;
        if (first == 0xf0) second_min = 0x90;
        if (first == 0xf4) second_max = 0x8f;
      } else {
        return false;
      }

      if (continuation_count > len - i || input[i] < second_min ||
          input[i] > second_max) {
        return false;
      }
      ++i;
      for (size_t j = 1; j < continuation_count; ++j, ++i) {
        if (input[i] < 0x80 || input[i] > 0xbf) return false;
      }
    }
    return true;
  }

  // A union used to store the attributes for singleton objects (i.e.,
  // UNSIGNED, NEGATIVE, PRIMITIVE), the start position and len of
  // TEXT and BYTES array, or the children information for ARRAY or
  // MAP objects.
  //
  // We store NEGATIVE data in a special way.  A NEGATIVE(N) datum is
  // interpreted as the negative integer -1-N64. However, since -1-N64
  // cannot be easily represented as a C type, we store N64 directly.
  // This is OK because the only operation on NEGATIVE data is
  // lookup_negative()
  union U {
    uint64_t u64;          // UNSIGNED.
    uint64_t n64;          // NEGATIVE.
    enum CborPrimitive p;  // PRIMITIVE

    // BYTES + TEXT, represented as offset in input + length
    CborString string;

    // arrays, maps, and tags: an array of children nodes.
    CborItems items;
  };

  // Decodes a sequence of children nodes.
  bool decode_items(CborTag t, size_t nchildren, size_t items_n,
                    const uint8_t in[], size_t len, size_t& pos,
                    size_t offset) {
    t_ = t;
    u_.items.n = items_n;
    u_.items.nchildren = nchildren;
    children_.resize(nchildren);
    for (size_t i = 0; i < nchildren; ++i) {
      if (!children_[i].decode(in, len, pos, offset)) return false;
    }
    return true;
  }

  // Compares a text node to a given string of bytes.
  bool eq(const uint8_t* const in, size_t len,
          const uint8_t bytes[/*len*/]) const {
    if (t_ == TEXT) {
      auto s = as_text();
      return s.len == len && memcmp(bytes, &in[s.pos], len) == 0;
    }
    return false;
  }

  size_t header_pos_;
  CborTag t_;
  union U u_;
  std::vector<CborDoc> children_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CBOR_HOST_DECODER_H_
