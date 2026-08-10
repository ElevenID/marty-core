"""Cross-language tests for the Python-facing ISO 18013 bindings."""

from __future__ import annotations

import asyncio

import marty_iso18013 as native


def test_request_response_cbor_round_trip() -> None:
    request = native.MdlRequest(
        "org.iso.18013.5.1.mDL",
        {"org.iso.18013.5.1": ["family_name"]},
    )
    assert len(bytes(request.nonce)) == 32
    decoded_request = native.MdlRequest.from_bytes(request.to_bytes())
    assert decoded_request.data_elements == request.data_elements

    response = native.MdlResponse(
        "org.iso.18013.5.1.mDL", b"device-response", native.ResponseStatus.Ok
    )
    decoded_response = native.MdlResponse.from_bytes(response.to_bytes())
    assert bytes(decoded_response.data) == b"device-response"


def test_two_native_sessions_exchange_directional_messages() -> None:
    async def exchange() -> None:
        engagement = native.DeviceEngagement.new()
        alice = native.Session.from_engagement_py(engagement, None)
        bob = native.Session.from_engagement_py(engagement, None)
        alice_key = alice.public_key_py()
        bob_key = bob.public_key_py()
        alice.establish_py(bob_key)
        bob.establish_py(alice_key)

        ciphertext = alice.send_encrypted_py(b"alice-to-bob")
        assert bytes(bob.receive_encrypted_py(ciphertext)) == b"alice-to-bob"
        reverse = bob.send_encrypted_py(b"bob-to-alice")
        assert bytes(alice.receive_encrypted_py(reverse)) == b"bob-to-alice"

    asyncio.run(exchange())


def test_transport_and_selective_disclosure_bindings_are_present() -> None:
    assert native.BleTransport is not None
    assert native.NfcTransport is not None
    assert native.HttpsTransport is not None

    disclosure = native.SelectiveDisclosure()
    disclosure.add_namespace("org.iso.18013.5.1", ["family_name", "birth_date"])
    disclosure.add_mandatory("family_name")
    assert disclosure.filter_request(
        {"org.iso.18013.5.1": ["birth_date"]}, {}
    ) == {"org.iso.18013.5.1": ["family_name"]}
