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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_V2_CBOR_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_V2_CBOR_WITNESS_H_

#include <stddef.h>
#include <stdint.h>

#include <array>

#include "arrays/dense.h"
#include "circuits/cbor_parser_v2/cbor_constants.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/unary_plucker_constants.h"
#include "util/panic.h"

namespace proofs {
template <class Field>
class CborWitness {
 public:
  using Elt = typename Field::Elt;
  using CElt = typename Field::CElt;
  static constexpr size_t kNCounters = CborConstants::kNCounters;
  static constexpr size_t kIndexBits = CborConstants::kIndexBits;
  using counters = std::array<size_t, kNCounters>;
  using vindex = std::array<Elt, kIndexBits>;

  struct position_witness {
    Elt encoded_header;
    Elt encoded_sel;
    size_t slen_next;
    counters cc_next;
    Elt invprod_decode;
    Elt invprod_parse;
  };

  using v8 = std::array<Elt, 8>;

  explicit CborWitness(const Field& F) : f_(F) {}

  void push_witnesses(DenseFiller<Field>& filler, size_t n,
                      const position_witness pw[/*n*/]) const {
    for (size_t i = 0; i < n; ++i) {
      filler.push_back(pw[i].encoded_header);
      filler.push_back(pw[i].encoded_sel);
      filler.push_back(f_.as_counter(pw[i].slen_next));
      for (size_t l = 0; l < kNCounters; ++l) {
        filler.push_back(f_.as_counter(pw[i].cc_next[l]));
      }
      if (i > 0) {
        filler.push_back(pw[i].invprod_decode);
        filler.push_back(pw[i].invprod_parse);
      }
    }
  }

  // Return an index as an array of Elt, which can be stored into W[]
  vindex index(size_t j) const {
    const Field& F = f_;  // shorthand
    vindex r;
    for (size_t i = 0; i < kIndexBits; ++i) {
      r[i] = F.of_scalar((j >> i) & 1);
    }
    return r;
  }

  // N: maximum input length (in bytes)
  // INPUT_LEN: actual input length
  void compute_witnesses(size_t n, size_t input_len, const uint8_t bytes[/*n*/],
                         v8 in[/*n*/], position_witness pw[/*n*/]) const {
    const Field& F = f_;  // shorthand
    BitPluckerEncoder<Field, 1> BPENC(F);

    proofs::check(input_len <= n, "input_len <= n");

    // First pass to compute the number of top-level items.  In the
    // second pass, we will use this value to that all counters are 0
    // at the end of the input.
    size_t top_level_items;
    {
      // start with a value of cc[0] guaranteed not to
      // underflow counter 0.
      counters cc{{n + 1}};

      size_t slen = 1;
      for (size_t i = 0; i < n; ++i) {
        bool overflow;
        bool header = (slen == 1);
        cc = counters_next(bytes[i], header,
                           /*have_nextb=*/(i + 1) < n,
                           /*nextb=*/(i + 1) < n ? bytes[i + 1] : 0, cc,
                           &overflow);
        proofs::check(!overflow, "!overflow");
        slen = next_slen(slen, n, bytes, i);
      }

      top_level_items = (n + 1) - cc[0];
    }

    // second pass starting with the correct counter values
    {
      counters cc{{top_level_items}};

      size_t slen = 1;
      for (size_t i = 0; i < n; ++i) {
        bool overflow;
        bool header = (slen == 1);
        bool in_input = (i >= n - input_len);

        // Require all bytes not in the input to be 0.
        if (!in_input) {
          proofs::check(bytes[i] == 0, "bytes[i] == 0");
        }

        // set up input
        for (size_t j = 0; j < 8; ++j) {
          in[i][j] = F.of_scalar((bytes[i] >> j) & 1);
        }

        // decode witness
        Elt prod_decode =
            header ? F.one() : F.znz_indicator(F.as_counter(slen - 1));

        // set up parse witness
        Elt prod_parse = F.one();
        size_t isel = kNCounters;
        for (size_t l = kNCounters; l-- > 0;) {
          if (cc[l] != 0) {
            if (i > 0) {
              F.mul(prod_parse, F.znz_indicator(F.as_counter(cc[l])));
            }
            isel = l;
            break;
          }
        }

        counters cc_next = counters_next(
            bytes[i], header,
            /*have_nextb=*/(i + 1) < n,
            /*nextb=*/(i + 1) < n ? bytes[i + 1] : 0, cc, &overflow);
        proofs::check(!overflow, "!overflow");
        pw[i].cc_next = cc_next;

        // set up decode witness
        size_t slen_next = next_slen(slen, n, bytes, i);
        pw[i].slen_next = slen_next;

        // encode witnesses
        pw[i].encoded_header = BPENC.encode(header);
        pw[i].encoded_sel = unary_plucker_point<Field, kNCounters>()(isel, F);
        pw[i].invprod_decode = F.invertf(prod_decode);
        pw[i].invprod_parse = F.invertf(prod_parse);

        slen = slen_next;
        cc = cc_next;
      }
    }
  }

 private:
  static size_t next_slen(size_t slen, size_t n, const uint8_t bytes[/*n*/],
                          size_t i) {
    size_t slenm1 = slen - 1;
    bool header = (slenm1 == 0);
    if (header) {
      if (i + 1 < n) {
        return item_length(bytes[i], true, bytes[i + 1]);
      } else {
        return item_length(bytes[i], false, 0);
      }
    } else {
      return slenm1;
    }
  }

  // TODO [matteof 2023-11-03] Should not panic() here.
  static size_t item_length(uint8_t b, bool valid_nextb, uint8_t nextb) {
    size_t type = (b >> 5) & 0x7u;
    size_t count = b & 0x1Fu;
    bool count0_23 = (count < 24);
    bool count24 = (count == 24);
    bool count25 = (count == 25);
    bool count26 = (count == 26);
    bool count27 = (count == 27);

    switch (type) {
      case 0: /* unsigned */
      case 1: /* negative integer */
      case 6: /* tag */
        if (count0_23) {
          return 1;
        } else if (count24) {
          return 2;
        } else if (count25) {
          return 3;
        } else if (count26) {
          return 5;
        } else if (count27) {
          return 9;
        } else {
          // Defensive: witness generation should always encode atom sizes via
          // one of the recognized count flags above.
          check(false, "unwitnessed count (atom)");
          return 0;
        }

      case 4: /* array */
      case 5: /* map */
        if (count0_23) {
          return 1;
        } else if (count24) {
          return 2;
        } else {
          // Defensive: arrays/maps in this witness path only support the
          // compact encodings handled above.
          check(false, "unwitnessed count (item)");
          return 0;
        }

      case 2: /* bytes */
      case 3: /* text */
        if (count0_23) {
          return 1 + count;
        } else if (count24) {
          if (valid_nextb) {
            return 2 + nextb;
          } else {
            // Defensive: `nextb` should already have been range-checked before
            // the witness path reaches this helper.
            check(false, "invalid nextb");
            return 0;
          }
        } else {
          // Defensive: byte/text witness generation should always select one of
          // the supported count encodings above.
          check(false, "unwitnessed count (bytes)");
          return 0;
        }

      case 7: /* special */
        // Defensive: special values are not expected in the current witness
        // generation flow.
        check(false, "unwitnessed special");
        return 0;

      default:
        // Unreachable: all CBOR major types are covered above.
        check(false, "can't happen");
        return 0;
    }
  }

  static size_t decode_count(size_t count_in_header, bool have_nextb,
                             uint8_t nextb) {
    if (count_in_header < 24) {
      return count_in_header;
    } else if (count_in_header == 24) {
      if (have_nextb) {
        return nextb;
      } else {
        // Defensive: the 24 marker requires a following byte to have been
        // supplied by the caller.
        check(false, "!have_nextb");
      }
    } else {
      // Defensive: this helper only supports the compact count encodings used
      // by the current witness generator.
      check(false, "count > 24");
    }
    return 0xdeadbeef;
  }

  static counters counters_next(uint8_t b, bool header, bool have_nextb,
                                uint8_t nextb, const counters& c,
                                bool* overflow) {
    size_t type = (b >> 5) & 0x7u;
    size_t count_in_header = b & 0x1Fu;
    bool tagp = (type == 6);
    bool arrayp = (type == 4);
    bool mapp = (type == 5);

    counters c1 = c;
    *overflow = false;

    for (size_t l = kNCounters; l-- > 0;) {
      if (c[l] != 0) {
        if (header) {
          c1[l] = c[l] - 1;

          if (tagp) {
            if (l + 1 < kNCounters) {
              c1[l + 1] = 1;
            } else {
              *overflow = true;
            }
          } else if (arrayp) {
            if (l + 1 < kNCounters) {
              c1[l + 1] = decode_count(count_in_header, have_nextb, nextb);
            } else {
              *overflow = true;
            }
          } else if (mapp) {
            if (l + 1 < kNCounters) {
              c1[l + 1] = 2 * decode_count(count_in_header, have_nextb, nextb);
            } else {
              *overflow = true;
            }
          }
        }
        break;
      }
    }

    return c1;
  }

 private:
  const Field& f_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_V2_CBOR_WITNESS_H_
