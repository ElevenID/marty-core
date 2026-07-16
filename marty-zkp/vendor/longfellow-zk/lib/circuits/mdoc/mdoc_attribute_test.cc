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

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "circuits/mdoc/mdoc_attribute_ids.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

// This test validates that the cbor encoding of an attribute is NOT a suffix
// of any other valid attribute id.  Therefore, finding the location of the
// cbor-encoded value of the attribute name is sufficient. We can be sure that
// the Prover is not able to forge an attribute by pointing to the suffix of
// another attribute id.
TEST(MdocAttributeTest, MdocAttributeIdsAreSuffixFree) {
  for (const auto& attr : kMdocAttributes) {
    // Form the cbor encoding of attr.
    size_t len = attr.identifier.size();
    std::vector<uint8_t> attr_enc;
    append_text_len(attr_enc, len);
    attr_enc.insert(attr_enc.end(), attr.identifier.begin(),
                    attr.identifier.end());
    std::string attr_enc_str(attr_enc.begin(), attr_enc.end());
    for (const auto& aj : kMdocAttributes) {
      if (aj.identifier.ends_with(attr_enc_str) &&
          aj.identifier != attr.identifier) {
        log(INFO, "identifier %s is a suffix of %s\n", aj.identifier.data(),
            attr.identifier.data());
      }
      EXPECT_TRUE(!aj.identifier.ends_with(attr_enc_str) ||
                  aj.identifier == attr.identifier);
    }
  }
}

TEST(MdocAttributeTest, DelimiterIsPresent) {
  // Verify that the delimiter "ier" never occurs in an attribute id.
  // Verify that elementValue never appears in any attribute id.
  for (const auto& attr : kMdocAttributes) {
    EXPECT_TRUE(attr.identifier.find("ier") == std::string::npos);
    EXPECT_TRUE(attr.identifier.find("elementValue") == std::string::npos);
  }
}

}  // namespace
}  // namespace proofs
