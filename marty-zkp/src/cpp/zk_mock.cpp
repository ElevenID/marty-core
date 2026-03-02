#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

// Mock implementation of LibZK C-API (generic predicate interface)

extern "C" {

    typedef enum {
        ZkSuccess = 0,
        ZkErrorGeneric = 1,
        ZkErrorInvalidInput = 2,
        ZkErrorVerificationFailed = 3
    } ZkStatus;

    void* zk_create_transcript(const uint8_t* nonce, size_t nonce_len) {
        // Allocate a tiny opaque context so the pointer is non-null and unique.
        int* p = (int*)malloc(sizeof(int));
        *p = 1;
        return (void*)p;
    }

    void zk_free_transcript(void* transcript) {
        if (transcript) free(transcript);
    }

    // ── Generic predicate API ─────────────────────────────────────────

    ZkStatus zk_prove_predicate(
        void* transcript,
        const char* predicate_id,
        const uint8_t* mso_bytes,
        size_t mso_len,
        const uint8_t* signature,
        size_t sig_len,
        const char* claim_value,
        uint8_t** proof_out,
        size_t* proof_len_out
    ) {
        if (!transcript || !predicate_id || !mso_bytes || !signature || !claim_value)
            return ZkErrorInvalidInput;
        if (mso_len == 0 || sig_len == 0)
            return ZkErrorInvalidInput;

        // Mock: encode predicate_id + a fixed suffix as the "proof"
        // Real LibZK would run the Ligero circuit here.
        const char* suffix = ":mock_zk_proof";
        size_t pid_len = strlen(predicate_id);
        size_t suf_len = strlen(suffix);
        size_t total = pid_len + suf_len;

        *proof_out = (uint8_t*)malloc(total);
        if (!*proof_out) return ZkErrorGeneric;

        memcpy(*proof_out, predicate_id, pid_len);
        memcpy(*proof_out + pid_len, suffix, suf_len);
        *proof_len_out = total;

        return ZkSuccess;
    }

    ZkStatus zk_verify_predicate(
        void* transcript,
        const char* predicate_id,
        const uint8_t* mso_bytes,
        size_t mso_len,
        const uint8_t* proof,
        size_t proof_len
    ) {
        if (!transcript || !predicate_id || !proof || proof_len == 0)
            return ZkErrorVerificationFailed;
        // Mock: accept any non-empty proof
        return ZkSuccess;
    }

    // ── Buffer management ─────────────────────────────────────────────

    void zk_free_buffer(uint8_t* buffer) {
        if (buffer) free(buffer);
    }

} // extern "C"
