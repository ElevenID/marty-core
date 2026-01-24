"""
marty-verification-py - Python bindings for marty-verification

Provides cryptographic verification, Open Badges, mDoc/mDL, eMRTD, 
and certificate operations through Rust FFI.
"""

from ._marty_verification import (
    # Open Badges
    open_badge_ob2_issue,
    open_badge_ob2_verify,
    open_badge_ob3_issue,
    open_badge_ob3_verify,
    OpenBadgesVersion,
    # MRZ Operations
    parse_mrz,
    compute_check_digit,
    validate_check_digit,
    MrzData,
    # mDoc/mDL Verification
    mdl_verify,
    mdl_verify_with_config,
    MdlVerificationResult,
    # eMRTD Verification
    emrtd_verify,
    emrtd_verify_with_config,
    EmrtdVerificationResult,
    # Certificate Operations
    CertificateInfo,
    build_certificate,
    build_self_signed_certificate_with_key,
    certificate_der_to_pem,
    verify_certificate_chain,
    # Cryptographic Operations
    hash_data,
    Ed25519KeyPair,
    P256KeyPair,
    # Trust Registries
    IacaRegistry,
    CscaRegistry,
    TrustRegistry,
    # Additional exports as needed
)

__version__ = "0.1.0"

__all__ = [
    # Open Badges
    "open_badge_ob2_issue",
    "open_badge_ob2_verify",
    "open_badge_ob3_issue",
    "open_badge_ob3_verify",
    "OpenBadgesVersion",
    # MRZ
    "parse_mrz",
    "compute_check_digit",
    "validate_check_digit",
    "MrzData",
    # mDoc/mDL
    "mdl_verify",
    "mdl_verify_with_config",
    "MdlVerificationResult",
    # eMRTD
    "emrtd_verify",
    "emrtd_verify_with_config",
    "EmrtdVerificationResult",
    # Certificates
    "CertificateInfo",
    "build_certificate",
    "build_self_signed_certificate_with_key",
    "certificate_der_to_pem",
    "verify_certificate_chain",
    # Crypto
    "hash_data",
    "Ed25519KeyPair",
    "P256KeyPair",
    # Trust
    "IacaRegistry",
    "CscaRegistry",
    "TrustRegistry",
]
