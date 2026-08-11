# marty-status

`marty-status` is Marty's canonical implementation of credential status-list
encoding, mutation, and bounded decoding.

It implements:

- IETF Token Status Lists: 1, 2, 4, or 8 bits per entry, packed least
  significant bit first and compressed with DEFLATE in the ZLIB data format.
- W3C Bitstring Status List v1.0: one-bit entries packed most significant bit
  first, compressed with GZIP, and encoded as multibase base64url without
  padding.

The crate rejects unsupported bit widths, out-of-range access, oversized
lists, malformed encodings, decompression beyond the declared list size, and
W3C credential subjects below the 131,072-entry privacy floor.

Python, service, and credential-package integrations must adapt this crate;
they must not maintain another status-list algorithm.
