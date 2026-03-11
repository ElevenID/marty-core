#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Mock implementation of the Longfellow mdoc ZK C-API (mdoc_zk.h ABI).
// Provides stub implementations of run_mdoc_prover, run_mdoc_verifier,
// generate_circuit, kZkSpecs and find_zk_spec so the Rust crate can be
// compiled and tested without building the full Longfellow C++ library.

extern "C" {

typedef struct {
  uint8_t namespace_id[64];
  uint8_t id[32];
  uint8_t cbor_value[64];
  size_t namespace_len, id_len, cbor_value_len;
} RequestedAttribute;

typedef enum {
  MDOC_PROVER_SUCCESS = 0,
  MDOC_PROVER_NULL_INPUT = 1,
  MDOC_PROVER_INVALID_INPUT = 2,
} MdocProverErrorCode;

typedef enum {
  MDOC_VERIFIER_SUCCESS = 0,
  MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE = 1,
  MDOC_VERIFIER_PROOF_TOO_SMALL = 2,
  MDOC_VERIFIER_HASH_PARSING_FAILURE = 3,
  MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE = 4,
  MDOC_VERIFIER_GENERAL_FAILURE = 5,
  MDOC_VERIFIER_NULL_INPUT = 6,
  MDOC_VERIFIER_INVALID_INPUT = 7,
} MdocVerifierErrorCode;

typedef enum {
  CIRCUIT_GENERATION_SUCCESS = 0,
  CIRCUIT_GENERATION_NULL_INPUT = 1,
  CIRCUIT_GENERATION_GENERAL_FAILURE = 2,
} CircuitGenerationErrorCode;

typedef struct {
  const char* system;
  char circuit_hash[65];
  size_t num_attributes;
  size_t version;
  size_t block_enc_hash;
  size_t block_enc_sig;
} ZkSpecStruct;

static const char kMockSystem[] = "longfellow-libzk-mock";

extern const ZkSpecStruct kZkSpecs[12] = {
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000001", 1, 1, 0, 0},
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000002", 1, 2, 0, 0},
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000003", 2, 3, 0, 0},
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000004", 2, 4, 0, 0},
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000005", 3, 5, 0, 0},
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000006", 3, 6, 0, 0},
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000007", 4, 7, 0, 0},
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000008", 4, 8, 0, 0},
  {kMockSystem, "0000000000000000000000000000000000000000000000000000000000000009", 5, 9, 0, 0},
  {kMockSystem, "000000000000000000000000000000000000000000000000000000000000000a", 5, 10, 0, 0},
  {kMockSystem, "000000000000000000000000000000000000000000000000000000000000000b", 6, 11, 0, 0},
  {kMockSystem, "000000000000000000000000000000000000000000000000000000000000000c", 6, 12, 0, 0},
};

const ZkSpecStruct* find_zk_spec(const char* system_name, const char* circuit_hash) {
  if (!system_name || !circuit_hash) return NULL;
  for (int i = 0; i < 12; ++i) {
    if (strcmp(kZkSpecs[i].system, system_name) == 0 &&
        strcmp(kZkSpecs[i].circuit_hash, circuit_hash) == 0) {
      return &kZkSpecs[i];
    }
  }
  return NULL;
}

CircuitGenerationErrorCode generate_circuit(const ZkSpecStruct* zk_spec,
                                             uint8_t** cb, size_t* clen) {
  if (!zk_spec || !cb || !clen) return CIRCUIT_GENERATION_NULL_INPUT;
  *clen = 32;
  *cb = (uint8_t*)malloc(*clen);
  if (!*cb) return CIRCUIT_GENERATION_GENERAL_FAILURE;
  for (size_t i = 0; i < *clen; ++i) (*cb)[i] = (uint8_t)i;
  return CIRCUIT_GENERATION_SUCCESS;
}

MdocProverErrorCode run_mdoc_prover(
    const uint8_t* bcp, size_t bcsz,
    const uint8_t* mdoc, size_t mdoc_len,
    const char* pkx, const char* pky,
    const uint8_t* transcript, size_t tr_len,
    const RequestedAttribute* attrs, size_t attrs_len,
    const char* now,
    uint8_t** prf, size_t* proof_len,
    const ZkSpecStruct* zk_spec) {
  (void)zk_spec;
  if (!bcp || !mdoc || !pkx || !pky || !transcript || !attrs || !now || !prf || !proof_len)
    return MDOC_PROVER_NULL_INPUT;
  if (bcsz == 0 || mdoc_len == 0 || tr_len == 0 || attrs_len == 0)
    return MDOC_PROVER_INVALID_INPUT;

  // Mock proof: transcript bytes + fixed tag (tag enables tamper detection).
  static const uint8_t tag[16] = {
    0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
    0xfa,0xce,0xb0,0x0c,0xab,0xcd,0xef,0x01
  };
  *proof_len = tr_len + sizeof(tag);
  *prf = (uint8_t*)malloc(*proof_len);
  if (!*prf) return MDOC_PROVER_NULL_INPUT;
  memcpy(*prf, transcript, tr_len);
  memcpy(*prf + tr_len, tag, sizeof(tag));
  return MDOC_PROVER_SUCCESS;
}

MdocVerifierErrorCode run_mdoc_verifier(
    const uint8_t* bcp, size_t bcsz,
    const char* pkx, const char* pky,
    const uint8_t* transcript, size_t tr_len,
    const RequestedAttribute* attrs, size_t attrs_len,
    const char* now,
    const uint8_t* zkproof, size_t proof_len,
    const char* docType,
    const ZkSpecStruct* zk_spec) {
  (void)bcp; (void)bcsz; (void)pkx; (void)pky;
  (void)attrs; (void)attrs_len; (void)now; (void)docType; (void)zk_spec;
  if (!transcript || !zkproof)
    return MDOC_VERIFIER_NULL_INPUT;
  if (tr_len == 0 || proof_len == 0)
    return MDOC_VERIFIER_INVALID_INPUT;
  // Accept proof if it starts with the transcript bytes.
  if (proof_len < tr_len) return MDOC_VERIFIER_PROOF_TOO_SMALL;
  if (memcmp(zkproof, transcript, tr_len) != 0) return MDOC_VERIFIER_GENERAL_FAILURE;
  return MDOC_VERIFIER_SUCCESS;
}

} // extern "C"
