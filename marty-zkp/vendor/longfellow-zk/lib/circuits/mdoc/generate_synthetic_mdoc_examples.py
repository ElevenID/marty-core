#!/usr/bin/env python3
# Copyright 2026 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generate deterministic, synthetic mdoc examples for circuit tests.

The generated fixture is intentionally small and artificial.  It is not copied
from any issuer, DMV, wallet, relying party, or production conformance suite.
It exists only to keep the mdoc proof/hash/signature tests enabled after the
public tree removed broad third-party fixture bytes.
"""

from __future__ import annotations

import hashlib
import html
from pathlib import Path
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]
HEADER_PATH = REPO_ROOT / "lib" / "circuits" / "mdoc" / "mdoc_examples.h"
DOC_PATH = (
    REPO_ROOT
    / "docs"
    / "static"
    / "reference"
    / "cpp"
    / "mdoc__examples_8h_source.html"
)

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = -3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
INF: tuple[int, int] | None = None

PROTECTED_ES256 = bytes.fromhex("a10126")
DOC_TYPE = "org.iso.18013.5.1.mDL"
MDL_NS = "org.iso.18013.5.1"
NOW = "2025-01-01T00:00:00Z"
TRANSCRIPT = b"\xf6"  # CBOR null SessionTranscript for a synthetic test case.


def inv(x: int, mod: int) -> int:
    return pow(x % mod, -1, mod)


def add_points(
    p1: tuple[int, int] | None, p2: tuple[int, int] | None
) -> tuple[int, int] | None:
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return INF
    if p1 == p2:
        lam = ((3 * x1 * x1 + A) * inv(2 * y1, P)) % P
    else:
        lam = ((y2 - y1) * inv(x2 - x1, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def mul_point(k: int, p: tuple[int, int] = (GX, GY)) -> tuple[int, int]:
    result = INF
    addend: tuple[int, int] | None = p
    while k:
        if k & 1:
            result = add_points(result, addend)
        addend = add_points(addend, addend)
        k >>= 1
    if result is INF:
        raise ValueError("invalid scalar produced point at infinity")
    return result


def ecdsa_raw_sign(priv: int, msg: bytes, nonce: int) -> bytes:
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    rx, _ = mul_point(nonce)
    r = rx % N
    if r == 0:
        raise ValueError("bad deterministic ECDSA nonce: r=0")
    s = (inv(nonce, N) * (z + r * priv)) % N
    if s == 0:
        raise ValueError("bad deterministic ECDSA nonce: s=0")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def cbor_head(major: int, value: int) -> bytes:
    base = major << 5
    if value < 24:
        return bytes([base | value])
    if value < 256:
        return bytes([base | 24, value])
    if value < 65536:
        return bytes([base | 25, (value >> 8) & 0xFF, value & 0xFF])
    raise ValueError(f"CBOR value too large for this generator: {value}")


def uint(value: int) -> bytes:
    return cbor_head(0, value)


def neg(value: int) -> bytes:
    if value >= 0:
        raise ValueError("CBOR negative helper requires a negative integer")
    return cbor_head(1, -1 - value)


def bstr(value: bytes, *, force_u16_len: bool = False) -> bytes:
    if force_u16_len:
        if len(value) >= 65536:
            raise ValueError("byte string too large")
        return b"\x59" + len(value).to_bytes(2, "big") + value
    return cbor_head(2, len(value)) + value


def text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return cbor_head(3, len(raw)) + raw


def arr(items: Sequence[bytes]) -> bytes:
    return cbor_head(4, len(items)) + b"".join(items)


def mp(pairs: Sequence[tuple[bytes, bytes]]) -> bytes:
    out = bytearray(cbor_head(5, len(pairs)))
    for key, value in pairs:
        out.extend(key)
        out.extend(value)
    return bytes(out)


def tag(tag_number: int, child: bytes) -> bytes:
    return cbor_head(6, tag_number) + child


def tag24_bstr(child: bytes, *, force_child_u16_len: bool = False) -> bytes:
    return tag(24, bstr(child, force_u16_len=force_child_u16_len))


def tdate(value: str) -> bytes:
    if len(value) != 20:
        raise ValueError("tdate values must be 20-byte RFC3339 timestamps")
    return tag(0, text(value))


def fulldate(value: str) -> bytes:
    if len(value) != 10:
        raise ValueError("full-date values must be YYYY-MM-DD")
    return tag(1004, text(value))


def cose_sig_structure(payload: bytes) -> bytes:
    # Matches kCose1Prefix plus a two-byte payload length in mdoc_witness.h.
    return (
        arr(
            [
                text("Signature1"),
                bstr(PROTECTED_ES256),
                bstr(b""),
                bstr(payload, force_u16_len=True),
            ]
        )
    )


def device_authentication_bytes() -> bytes:
    out = bytearray()
    out.extend(arr_prefix := cbor_head(4, 4))
    del arr_prefix
    out.extend(text("DeviceAuthentication"))
    out.extend(TRANSCRIPT)
    out.extend(text(DOC_TYPE))
    out.extend(tag24_bstr(mp([])))
    return bytes(out)


def device_sig_structure() -> bytes:
    da = device_authentication_bytes()
    payload = tag24_bstr(da)
    return arr([text("Signature1"), bstr(PROTECTED_ES256), bstr(b""), bstr(payload)])


def issuer_signed_item(digest_id: int, element_id: str, element_value: bytes) -> bytes:
    body = mp(
        [
            (text("digestID"), uint(digest_id)),
            (text("random"), bstr(bytes([0xC0 + digest_id]) * 16)),
            (text("elementIdentifier"), text(element_id)),
            (text("elementValue"), element_value),
        ]
    )
    return tag24_bstr(body)


def hex_static(value: int) -> str:
    return f"0x{value:064x}"


def format_byte_array(data: bytes, indent: str = "     ") -> str:
    pieces = [f"0x{b:02x}" for b in data]
    lines: list[str] = []
    for i in range(0, len(pieces), 12):
        suffix = "," if i + 12 < len(pieces) else ""
        lines.append(indent + ", ".join(pieces[i : i + 12]) + suffix)
    return "\n".join(lines)


def build_fixture() -> tuple[str, str]:
    issuer_priv = 5
    issuer2_priv = 11
    device_priv = 7
    issuer_x, issuer_y = mul_point(issuer_priv)
    issuer2_x, issuer2_y = mul_point(issuer2_priv)
    device_x, device_y = mul_point(device_priv)

    attrs: list[tuple[int, str, bytes]] = [
        (0, "age_over_18", b"\xf5"),
        (1, "family_name", text("Mustermann")),
        (2, "birth_date", fulldate("1971-09-01")),
        (3, "height", uint(175)),
        (4, "issue_date", fulldate("2024-03-15")),
    ]
    tagged_attrs = [issuer_signed_item(*attr) for attr in attrs]
    digest_map = mp(
        [
            (uint(digest_id), bstr(hashlib.sha256(tagged_attr).digest()))
            for (digest_id, _, _), tagged_attr in zip(attrs, tagged_attrs)
        ]
    )

    device_key = mp(
        [
            (uint(1), uint(2)),
            (neg(-1), uint(1)),
            (neg(-2), bstr(device_x.to_bytes(32, "big"))),
            (neg(-3), bstr(device_y.to_bytes(32, "big"))),
        ]
    )
    mso = mp(
        [
            (text("version"), text("1.0")),
            (text("digestAlgorithm"), text("SHA-256")),
            (text("valueDigests"), mp([(text(MDL_NS), digest_map)])),
            (text("deviceKeyInfo"), mp([(text("deviceKey"), device_key)])),
            (text("docType"), text(DOC_TYPE)),
            (
                text("validityInfo"),
                mp(
                    [
                        (text("signed"), tdate("2024-01-01T00:00:00Z")),
                        (text("validFrom"), tdate("2024-01-01T00:00:00Z")),
                        (text("validUntil"), tdate("2030-01-01T00:00:00Z")),
                        (text("expectedUpdate"), tdate("2029-01-01T00:00:00Z")),
                    ]
                ),
            ),
        ]
    )
    tagged_mso = tag24_bstr(mso, force_child_u16_len=True)
    issuer_sig = ecdsa_raw_sign(issuer_priv, cose_sig_structure(tagged_mso), nonce=17)
    device_sig = ecdsa_raw_sign(device_priv, device_sig_structure(), nonce=19)

    issuer_auth = arr(
        [
            bstr(PROTECTED_ES256),
            mp([]),
            bstr(tagged_mso),
            bstr(issuer_sig),
        ]
    )
    device_signature = arr(
        [
            bstr(PROTECTED_ES256),
            mp([]),
            b"\xf6",
            bstr(device_sig),
        ]
    )
    device_signed = mp(
        [
            (text("nameSpaces"), tag24_bstr(mp([]))),
            (
                text("deviceAuth"),
                mp([(text("deviceSignature"), device_signature)]),
            ),
        ]
    )
    issuer_signed = mp(
        [
            (text("nameSpaces"), mp([(text(MDL_NS), arr(tagged_attrs))])),
            (text("issuerAuth"), issuer_auth),
        ]
    )
    document = mp(
        [
            (text("docType"), text(DOC_TYPE)),
            (text("issuerSigned"), issuer_signed),
            (text("deviceSigned"), device_signed),
        ]
    )
    device_response = mp(
        [
            (text("version"), text("1.0")),
            (text("documents"), arr([document])),
            (text("status"), uint(0)),
        ]
    )
    if len(device_response) > 5000:
        raise ValueError(f"synthetic mdoc is too large: {len(device_response)}")

    issuer_keys = [(issuer_x, issuer_y), (issuer2_x, issuer2_y)]
    header = render_header(device_response, issuer_keys)
    return header, render_doc(header)


def render_header(mdoc: bytes, issuer_keys: Sequence[tuple[int, int]]) -> str:
    issuer_xs = ",\n".join(
        f"    StaticString(\n        \"{hex_static(x)}\")" for x, _ in issuer_keys
    )
    issuer_ys = ",\n".join(
        f"    StaticString(\n        \"{hex_static(y)}\")" for _, y in issuer_keys
    )
    transcript = format_byte_array(TRANSCRIPT, indent="     ")
    mdoc_bytes = format_byte_array(mdoc, indent="     ")
    issuer_x, issuer_y = issuer_keys[0]
    return f"""// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_EXAMPLES_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_EXAMPLES_H_

#include <cstddef>
#include <cstdint>

#include \"algebra/static_string.h\"
#include \"circuits/mdoc/mdoc_attribute_ids.h\"

namespace proofs {{

// Deterministic, synthetic fixture generated by
// lib/circuits/mdoc/generate_synthetic_mdoc_examples.py.  It is not copied
// from an issuer, wallet, conformance suite, DMV, or other production source.
static constexpr bool kMdocExamplesSanitized = false;

static const StaticString kIssuerPKX[] = {{
{issuer_xs},
}};

static const StaticString kIssuerPKY[] = {{
{issuer_ys},
}};

struct MdocTests {{
  StaticString pkx, pky; /* public key of the issuer */
  uint8_t transcript[1024];
  size_t transcript_size;
  uint8_t* now;
  const char* doc_type;
  size_t mdoc_size;
  uint8_t mdoc[5000];
}};

static const struct MdocTests mdoc_tests[] = {{
    {{StaticString(\"{hex_static(issuer_x)}\"),
     StaticString(\"{hex_static(issuer_y)}\"),
     {{
{transcript}
     }},
     {len(TRANSCRIPT)},
     (uint8_t*)\"{NOW}\",
     kMDLDocType,
     {len(mdoc)},
     {{
{mdoc_bytes}
     }}}},
}};

}}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_EXAMPLES_H_
"""


def render_doc(header: str) -> str:
    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\" />
<title>mdoc_examples.h Source File</title>
</head>
<body>
<h1>mdoc_examples.h</h1>
<p>
  This generated source page mirrors the deterministic synthetic mdoc fixture
  used by the public test suite.  The fixture is artificial and contains no
  third-party or production issuer material.
</p>
<pre>
{html.escape(header)}
</pre>
</body>
</html>
"""


def main() -> None:
    header, doc = build_fixture()
    HEADER_PATH.write_text(header, encoding="utf-8", newline="\n")
    DOC_PATH.write_text(doc, encoding="utf-8", newline="\n")
    print(f"wrote {HEADER_PATH.relative_to(REPO_ROOT)}")
    print(f"wrote {DOC_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()