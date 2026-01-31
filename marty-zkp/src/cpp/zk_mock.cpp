#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

// Mock implementation of LibZK C-API

extern "C" {

    typedef enum {
        ZkSuccess = 0,
        ZkErrorGeneric = 1,
        ZkErrorInvalidInput = 2,
        ZkErrorVerificationFailed = 3
    } ZkStatus;

    void* zk_create_transcript(const uint8_t* nonce, size_t nonce_len) {
        // Just return a dummy pointer
        int* p = (int*)malloc(sizeof(int));
        *p = 1; 
        return (void*)p;
    }

    void zk_free_transcript(void* transcript) {
        if (transcript) free(transcript);
    }

    ZkStatus zk_prove_age_over_18(
        void* transcript,
        const uint8_t* mso_bytes,
        size_t mso_len,
        const uint8_t* signature,
        size_t sig_len,
        const char* birth_date_str,
        uint8_t** proof_out,
        size_t* proof_len_out
    ) {
        if (!mso_bytes || !signature || !birth_date_str) return ZkErrorInvalidInput;
        
        // Mock proof generation
        const char* mock_proof = "mock_zk_proof_data";
        size_t len = strlen(mock_proof);
        
        *proof_out = (uint8_t*)malloc(len);
        memcpy(*proof_out, mock_proof, len);
        *proof_len_out = len;
        
        return ZkSuccess;
    }

    ZkStatus zk_verify_age_over_18(
        void* transcript,
        const uint8_t* mso_bytes,
        size_t mso_len,
        const uint8_t* proof,
        size_t proof_len
    ) {
        if (!proof || proof_len == 0) return ZkErrorVerificationFailed;
        return ZkSuccess;
    }

    void zk_free_buffer(uint8_t* buffer) {
        if (buffer) free(buffer);
    }
}
