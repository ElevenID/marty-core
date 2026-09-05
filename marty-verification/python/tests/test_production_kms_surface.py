import marty_verification
import marty_verification_py


def test_production_module_excludes_local_secret_key_operations():
    forbidden = {
        "ed448_generate",
        "ed448_sign",
        "Pkcs12Data",
        "pkcs12_parse",
        "iso9796_scheme1_sign",
        "eac_sign_terminal_challenge",
        "eac_calculate_mac",
        "load_private_key_pem",
        "load_private_key_der",
        "save_private_key_pem",
        "extract_public_key",
        "detect_private_key_type",
        "raw_private_key_to_pkcs8",
        "pkcs8_to_raw_private_key",
        "ed25519_generate",
        "ed25519_sign",
        "x25519_generate",
        "x25519_agree",
        "p256_generate",
        "p256_agree",
        "ecdsa_p256_generate",
        "ecdsa_p384_generate",
        "ecdsa_p521_generate",
        "ecdsa_p256_sign",
        "ecdsa_p384_sign",
        "ecdsa_p521_sign",
        "rsa_generate",
        "rsa_pkcs1_sha256_sign",
        "rsa_pkcs1_sha384_sign",
        "rsa_pkcs1_sha512_sign",
        "rsa_pss_sha256_sign",
        "rsa_pss_sha384_sign",
        "rsa_pss_sha512_sign",
        "generate_key",
        "Jwk",
        "jwk_generate",
        "jws_sign",
        "jws_verify",
        "jwe_encrypt",
        "jwe_decrypt",
        "open_badge_ob2_issue",
        "open_badge_ob3_issue",
        "dtc_sign",
        "CertProfile",
        "CertificateBuilderConfig",
        "build_self_signed_certificate",
        "build_self_signed_certificate_with_key",
    }

    assert forbidden.isdisjoint(dir(marty_verification))
    assert forbidden.isdisjoint(dir(marty_verification_py))
    for safe_name in (
        "verify_signature",
        "generate_random_bytes",
        "aes_gcm_encrypt",
        "aes_gcm_decrypt",
        "dtc_prepare_signing",
        "dtc_assemble_signature",
        "dtc_verify",
        "open_badge_ob2_verify",
        "open_badge_ob3_verify",
    ):
        assert hasattr(marty_verification, safe_name), safe_name

    session_surfaces = {
        "NativeBacSession": {
            "derive_bac_keys",
            "start_bac_with_keys",
            "start_bac_with_random",
            "derive_session_keys",
            "set_session_keys",
            "session_keys",
        },
        "NativePaceSession": {
            "derive_password_key",
            "start_pace_with_private_key",
        },
        "NativeEacChipAuthentication": {
            "generate_ephemeral_keypair",
            "perform_chip_authentication",
        },
        "NativeEacSecureMessaging": {"encrypt_apdu_with_iv", "state"},
    }
    for class_name, secret_methods in session_surfaces.items():
        session_class = getattr(marty_verification, class_name)
        assert secret_methods.isdisjoint(dir(session_class)), class_name

    assert hasattr(marty_verification.NativeBacSession, "protect_command")
    assert hasattr(marty_verification.NativePaceSession, "protect_command")
    assert hasattr(
        marty_verification.NativeEacChipAuthentication,
        "generate_ephemeral_public_key",
    )
    assert hasattr(marty_verification.NativeEacSecureMessaging, "status")

    try:
        marty_verification.NativeEacSecureMessaging(
            b"not accepted in production", "ecdh_p256_sha256"
        )
    except TypeError:
        pass
    else:
        raise AssertionError("production accepted injected EAC shared secret")
