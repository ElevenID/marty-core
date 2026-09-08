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

#include "circuits/mdoc/mdoc_witness.h"

#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

namespace proofs {
namespace {

using Bytes = std::vector<uint8_t>;

void append(Bytes &destination, const Bytes &source) {
  destination.insert(destination.end(), source.begin(), source.end());
}

void append_header(Bytes &out, uint8_t major, size_t value) {
  if (value < 24) {
    out.push_back(static_cast<uint8_t>((major << 5) | value));
  } else if (value <= 0xff) {
    out.push_back(static_cast<uint8_t>((major << 5) | 24));
    out.push_back(static_cast<uint8_t>(value));
  } else if (value <= 0xffff) {
    out.push_back(static_cast<uint8_t>((major << 5) | 25));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
  } else {
    out.push_back(static_cast<uint8_t>((major << 5) | 26));
    for (int shift = 24; shift >= 0; shift -= 8) {
      out.push_back(static_cast<uint8_t>(value >> shift));
    }
  }
}

Bytes scalar(uint8_t major, size_t value) {
  Bytes out;
  append_header(out, major, value);
  return out;
}

Bytes text(const std::string &value) {
  Bytes out;
  append_header(out, 3, value.size());
  out.insert(out.end(), value.begin(), value.end());
  return out;
}

Bytes nonminimal_text(const std::string &value) {
  Bytes out = {0x78, static_cast<uint8_t>(value.size())};
  out.insert(out.end(), value.begin(), value.end());
  return out;
}

Bytes byte_string(const Bytes &value) {
  Bytes out;
  append_header(out, 2, value.size());
  append(out, value);
  return out;
}

Bytes array(std::initializer_list<Bytes> values) {
  Bytes out;
  append_header(out, 4, values.size());
  for (const Bytes &value : values)
    append(out, value);
  return out;
}

Bytes map(std::initializer_list<std::pair<Bytes, Bytes>> entries) {
  Bytes out;
  append_header(out, 5, entries.size());
  for (const auto &[key, value] : entries) {
    append(out, key);
    append(out, value);
  }
  return out;
}

Bytes map(const std::vector<std::pair<Bytes, Bytes>> &entries) {
  Bytes out;
  append_header(out, 5, entries.size());
  for (const auto &[key, value] : entries) {
    append(out, key);
    append(out, value);
  }
  return out;
}

Bytes tag(size_t tag_number, const Bytes &value) {
  Bytes out = scalar(6, tag_number);
  append(out, value);
  return out;
}

Bytes tagged_mso_bytes(const Bytes &mso) {
  Bytes out = {0xd8, 0x18, 0x59};
  out.push_back(static_cast<uint8_t>(mso.size() >> 8));
  out.push_back(static_cast<uint8_t>(mso.size()));
  append(out, mso);
  return out;
}

struct SyntheticOptions {
  bool trailing_attribute = false;
  bool trailing_mso = false;
  bool trailing_root = false;
  bool wrong_attribute_tag = false;
  bool wrong_mso_tag = false;
  bool mismatched_mso_length = false;
  bool duplicate_documents = false;
  bool duplicate_element_value = false;
  bool duplicate_mso_field = false;
  bool nonminimal_element_value_key = false;
};

Bytes synthetic_mdoc(const Bytes &element_value,
                     const SyntheticOptions &options = {}) {
  static const std::string kNamespace = "org.iso.18013.5.1";

  std::vector<std::pair<Bytes, Bytes>> attribute_entries = {
      {text("digestID"), scalar(0, 0)},
      {text("random"), byte_string(Bytes(16, 0x42))},
      {text("elementIdentifier"), text("synthetic_value")},
      {options.nonminimal_element_value_key ? nonminimal_text("elementValue")
                                            : text("elementValue"),
       element_value},
  };
  if (options.duplicate_element_value) {
    attribute_entries.push_back({text("elementValue"), scalar(0, 2)});
  }
  Bytes attribute = map(attribute_entries);
  if (options.trailing_attribute)
    attribute.push_back(0);

  const Bytes namespaces =
      map({{text(kNamespace),
            array({tag(options.wrong_attribute_tag ? 23 : 24,
                       byte_string(attribute))})}});

  const Bytes validity_info =
      map({{text("validFrom"), text("2024-01-01T00:00:00Z")},
           {text("validUntil"), text("2034-01-01T00:00:00Z")}});
  const Bytes device_key = map({{scalar(1, 1), byte_string(Bytes(32, 0x11))},
                                {scalar(1, 2), byte_string(Bytes(32, 0x22))}});
  const Bytes device_key_info = map({{text("deviceKey"), device_key}});
  const Bytes value_digests =
      map({{text(kNamespace),
            map({{scalar(0, 0), byte_string(Bytes(32, 0x33))}})}});

  std::vector<std::pair<Bytes, Bytes>> mso_entries = {
      {text("validityInfo"), validity_info},
      {text("deviceKeyInfo"), device_key_info},
      {text("valueDigests"), value_digests},
  };
  if (options.duplicate_mso_field) {
    mso_entries.push_back({text("validityInfo"), map({})});
  }
  Bytes mso = map(mso_entries);
  if (options.trailing_mso)
    mso.push_back(0);

  Bytes tagged_mso = tagged_mso_bytes(mso);
  if (options.wrong_mso_tag)
    tagged_mso[1] = 0x17;
  if (options.mismatched_mso_length)
    ++tagged_mso[4];
  const Bytes issuer_auth =
      array({scalar(0, 0), scalar(0, 0), byte_string(tagged_mso),
             byte_string(Bytes(64, 0x44))});
  const Bytes issuer_signed = map(
      {{text("issuerAuth"), issuer_auth}, {text("nameSpaces"), namespaces}});
  const Bytes device_signature = array(
      {scalar(0, 0), scalar(0, 0), scalar(0, 0), byte_string(Bytes(64, 0x55))});
  const Bytes device_signed =
      map({{text("deviceAuth"),
            map({{text("deviceSignature"), device_signature}})}});
  const Bytes document = map({{text("docType"), text("org.iso.18013.5.1.mDL")},
                              {text("issuerSigned"), issuer_signed},
                              {text("deviceSigned"), device_signed}});
  std::vector<std::pair<Bytes, Bytes>> root_entries = {
      {text("documents"), array({document})}};
  if (options.duplicate_documents) {
    root_entries.push_back({text("documents"), array({})});
  }
  Bytes root = map(root_entries);
  if (options.trailing_root)
    root.push_back(0);
  return root;
}

TEST(MdocParserTest, AcceptsNegativeElementValueEncodingBoundaries) {
  const Bytes values[] = {
      {0x20},
      {0x37},
      {0x38, 0x18},
      {0x38, 0xff},
      {0x39, 0x01, 0x00},
      {0x3a, 0x00, 0x01, 0x00, 0x00},
  };

  for (const Bytes &value : values) {
    const Bytes mdoc = synthetic_mdoc(value);
    ParsedMdoc parsed;
    ASSERT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
              MDOC_PROVER_SUCCESS);
    ASSERT_EQ(parsed.attributes_.size(), 1);
    EXPECT_EQ(parsed.attributes_[0].val_len, value.size());
  }
}

TEST(MdocParserTest, RejectsTaggedNonStringElementValueWithoutAborting) {
  const Bytes mdoc = synthetic_mdoc(tag(2, scalar(0, 0)));
  ParsedMdoc parsed;
  EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
            MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE);
}

TEST(MdocParserTest, RejectsTrailingRootItem) {
  SyntheticOptions options;
  options.trailing_root = true;
  const Bytes mdoc = synthetic_mdoc(scalar(0, 1), options);
  ParsedMdoc parsed;
  EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
            MDOC_PROVER_ROOT_DECODING_FAILURE);
}

TEST(MdocParserTest, RejectsTrailingIssuerSignedItemData) {
  SyntheticOptions options;
  options.trailing_attribute = true;
  const Bytes mdoc = synthetic_mdoc(scalar(0, 1), options);
  ParsedMdoc parsed;
  EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
            MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE);
}

TEST(MdocParserTest, RejectsTrailingMsoData) {
  SyntheticOptions options;
  options.trailing_mso = true;
  const Bytes mdoc = synthetic_mdoc(scalar(0, 1), options);
  ParsedMdoc parsed;
  EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
            MDOC_PROVER_MSO_DECODING_FAILURE);
}

TEST(MdocParserTest, RejectsNonCanonicalTag24Wrappers) {
  SyntheticOptions options;
  options.wrong_attribute_tag = true;
  Bytes mdoc = synthetic_mdoc(scalar(0, 1), options);
  ParsedMdoc parsed;
  EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
            MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE);

  options = SyntheticOptions{};
  options.wrong_mso_tag = true;
  mdoc = synthetic_mdoc(scalar(0, 1), options);
  EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
            MDOC_PROVER_MSO_DECODING_FAILURE);

  options = SyntheticOptions{};
  options.mismatched_mso_length = true;
  mdoc = synthetic_mdoc(scalar(0, 1), options);
  EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
            MDOC_PROVER_MSO_DECODING_FAILURE);
}

TEST(MdocParserTest, RejectsDuplicateFields) {
  struct TestCase {
    SyntheticOptions options;
    MdocProverErrorCode expected;
  };
  SyntheticOptions duplicate_documents;
  duplicate_documents.duplicate_documents = true;
  SyntheticOptions duplicate_element_value;
  duplicate_element_value.duplicate_element_value = true;
  SyntheticOptions duplicate_mso_field;
  duplicate_mso_field.duplicate_mso_field = true;
  const TestCase tests[] = {
      {duplicate_documents, MDOC_PROVER_DOCUMENTS_MISSING},
      {duplicate_element_value, MDOC_PROVER_ATTRIBUTE_EV_MISSING},
      {duplicate_mso_field, MDOC_PROVER_VALIDITY_INFO_MISSING},
  };

  for (const TestCase &test : tests) {
    const Bytes mdoc = synthetic_mdoc(scalar(0, 1), test.options);
    ParsedMdoc parsed;
    EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
              test.expected);
  }
}

TEST(MdocParserTest, RejectsNonMinimalIntegerElementValues) {
  const Bytes values[] = {{0x18, 0x17}, {0x38, 0x17}};
  for (const Bytes &value : values) {
    const Bytes mdoc = synthetic_mdoc(value);
    ParsedMdoc parsed;
    EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
              MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE);
  }
}

TEST(MdocParserTest, RejectsNonMinimalEmbeddedLengthEncodings) {
  const Bytes values[] = {{0x78, 0x01, 'a'}, {0x58, 0x01, 0x42}};
  for (const Bytes &value : values) {
    const Bytes mdoc = synthetic_mdoc(value);
    ParsedMdoc parsed;
    EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
              MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE);
  }

  SyntheticOptions options;
  options.nonminimal_element_value_key = true;
  const Bytes mdoc = synthetic_mdoc(scalar(0, 1), options);
  ParsedMdoc parsed;
  EXPECT_EQ(parsed.parse_device_response(mdoc.size(), mdoc.data()),
            MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE);
}

} // namespace
} // namespace proofs
