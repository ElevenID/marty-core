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
        device = native.Session.from_engagement_py(engagement, None)
        reader = native.Session.reader_from_engagement_py(engagement, None)
        device_key = device.public_key_py()
        reader_key = reader.public_key_py()
        device.establish_py(reader_key)
        reader.establish_py(device_key)

        ciphertext = device.send_encrypted_py(b"device-to-reader")
        assert bytes(reader.receive_encrypted_py(ciphertext)) == b"device-to-reader"
        reverse = reader.send_encrypted_py(b"reader-to-device")
        assert bytes(device.receive_encrypted_py(reverse)) == b"reader-to-device"

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
