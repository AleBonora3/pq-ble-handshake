"""Known-answer and invariant tests for the v0.7 hybrid primitives."""

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.common.phase7 import (
    PHASE7_HYBRID_IKM_SIZE,
    PHASE7_KDF_INFO,
    PHASE7_TRANSCRIPT_SIZE,
    build_hybrid_ikm,
    build_phase7_transcript,
    compute_phase7_finished_c,
    compute_phase7_finished_p,
    compute_phase7_sas,
    compute_phase7_transcript_hash,
    derive_p256_ecdh_shared_secret,
    derive_phase7_keys,
    derive_phase7_traffic_keys,
    format_phase7_sas,
    generate_p256_private_key,
    load_p256_public_key,
    p256_private_key_from_scalar,
    serialize_p256_public_key,
)


SESSION_ID = bytes(range(16))
SS_MLKEM = bytes(range(32))
MLKEM_PUBLIC_KEY = bytes(i % 256 for i in range(1184))
MLKEM_CIPHERTEXT = bytes((255 - i) % 256 for i in range(1088))

CENTRAL_PUBLIC_KEY = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440"
    "f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162"
    "bce33576b315ececbb6406837bf51f5"
)
PERIPHERAL_PUBLIC_KEY = bytes.fromhex(
    "047cf27b188d034f7e8a52380304b51ac3"
    "c08969e277f21b35a60b48fc476699780"
    "7775510db8ed040293d9ac69f7430dbba7"
    "dade63ce982299e04b79d227873d1"
)
SS_ECDH = bytes.fromhex(
    "7cf27b188d034f7e8a52380304b51ac3"
    "c08969e277f21b35a60b48fc47669978"
)

EXPECTED_TRANSCRIPT_HASH = bytes.fromhex(
    "41f888d2a4edc656b750c2a6a4fdced1"
    "88f28580c53c2023c409e5f4f797db22"
)
EXPECTED_K_APP = bytes.fromhex(
    "2ccee2ee74d05015fb3d0f4fbae67114"
    "155849544ccb997a7f4753cb0f9345e2"
)
EXPECTED_K_SAS = bytes.fromhex(
    "a32cdc88dd312643db1ebbefb3110344"
    "6a28064a167ef294c21522220dd3289e"
)
EXPECTED_K_FINISHED_C = bytes.fromhex(
    "cf694b9f1d4a992b28bc9f0d07f85a6e"
    "d723785a25a7abd2f170ca4834c2d049"
)
EXPECTED_K_FINISHED_P = bytes.fromhex(
    "4875346b987aadf48943fb2d20841dc5"
    "8cdad447018b903c6f8cadc230ed09d5"
)
EXPECTED_FINISHED_C = bytes.fromhex(
    "13b2d59858f1a9174af11a3067c8608b"
    "fdf747fd7b85a9c9c7fc5eaf3184fa5c"
)
EXPECTED_FINISHED_P = bytes.fromhex(
    "abfc48a58dd7acaa6b4fb3431006eafe"
    "99c758df6a3082cc1cb5f7a21ed9daaa"
)
EXPECTED_K_C2P = bytes.fromhex(
    "07279ad8c5a44e75471d72af386cc19e"
    "ef94e0bb546fdd139b720d7cfc1dcf26"
)
EXPECTED_K_P2C = bytes.fromhex(
    "e9fe283d7b24bac9a3b66d9a8c31e79a"
    "9aa6f0f2eef165e5db316650889a9219"
)


def _transcript_hash(**changes: bytes) -> bytes:
    values = {
        "session_id": SESSION_ID,
        "mlkem_public_key": MLKEM_PUBLIC_KEY,
        "mlkem_ciphertext": MLKEM_CIPHERTEXT,
        "central_p256_public_key": CENTRAL_PUBLIC_KEY,
        "peripheral_p256_public_key": PERIPHERAL_PUBLIC_KEY,
    }
    values.update(changes)
    return compute_phase7_transcript_hash(**values)


def _flip_one_bit(value: bytes, index: int = -1) -> bytes:
    changed = bytearray(value)
    changed[index] ^= 0x01
    return bytes(changed)


def test_generated_p256_public_key_has_exact_sec1_encoding():
    public_key = serialize_p256_public_key(generate_p256_private_key())
    assert len(public_key) == 65
    assert public_key[0] == 0x04


def test_generated_p256_keypairs_derive_identical_32_byte_secrets():
    private_a = generate_p256_private_key()
    private_b = generate_p256_private_key()
    public_a = serialize_p256_public_key(private_a)
    public_b = serialize_p256_public_key(private_b)

    secret_a = derive_p256_ecdh_shared_secret(private_a, public_b)
    secret_b = derive_p256_ecdh_shared_secret(private_b, public_a)

    assert len(secret_a) == 32
    assert secret_a == secret_b


def test_deterministic_scalar_public_key_kats():
    assert serialize_p256_public_key(
        p256_private_key_from_scalar(1)
    ) == CENTRAL_PUBLIC_KEY
    assert serialize_p256_public_key(
        p256_private_key_from_scalar(2)
    ) == PERIPHERAL_PUBLIC_KEY


def test_scalar_one_two_ecdh_shared_secret_kat_both_directions():
    central = p256_private_key_from_scalar(1)
    peripheral = p256_private_key_from_scalar(2)

    central_secret = derive_p256_ecdh_shared_secret(
        central, PERIPHERAL_PUBLIC_KEY
    )
    peripheral_secret = derive_p256_ecdh_shared_secret(
        peripheral, CENTRAL_PUBLIC_KEY
    )

    assert central_secret == SS_ECDH
    assert peripheral_secret == SS_ECDH


@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        CENTRAL_PUBLIC_KEY[:-1],
        CENTRAL_PUBLIC_KEY + b"\x00",
        b"\x04" + b"\x00" * 64,
    ],
)
def test_malformed_p256_public_keys_are_rejected(encoded):
    with pytest.raises(ValueError):
        load_p256_public_key(encoded)


def test_wrong_sec1_prefix_is_rejected():
    with pytest.raises(ValueError, match="uncompressed"):
        load_p256_public_key(b"\x03" + CENTRAL_PUBLIC_KEY[1:])


def test_canonical_transcript_size_and_hash_kat():
    transcript = build_phase7_transcript(
        SESSION_ID,
        MLKEM_PUBLIC_KEY,
        MLKEM_CIPHERTEXT,
        CENTRAL_PUBLIC_KEY,
        PERIPHERAL_PUBLIC_KEY,
    )
    assert len(transcript) == PHASE7_TRANSCRIPT_SIZE == 2457
    assert _transcript_hash() == EXPECTED_TRANSCRIPT_HASH


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_id", SESSION_ID[:-1]),
        ("mlkem_public_key", MLKEM_PUBLIC_KEY[:-1]),
        ("mlkem_ciphertext", MLKEM_CIPHERTEXT[:-1]),
        ("central_p256_public_key", CENTRAL_PUBLIC_KEY[:-1]),
        ("peripheral_p256_public_key", PERIPHERAL_PUBLIC_KEY[:-1]),
    ],
)
def test_canonical_transcript_rejects_wrong_input_sizes(field, value):
    with pytest.raises(ValueError):
        _transcript_hash(**{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        (
            "central_p256_public_key",
            _flip_one_bit(CENTRAL_PUBLIC_KEY),
        ),
        (
            "peripheral_p256_public_key",
            _flip_one_bit(PERIPHERAL_PUBLIC_KEY),
        ),
        ("mlkem_public_key", _flip_one_bit(MLKEM_PUBLIC_KEY)),
        ("mlkem_ciphertext", _flip_one_bit(MLKEM_CIPHERTEXT)),
    ],
)
def test_one_bit_transcript_input_change_changes_hash(field, value):
    assert _transcript_hash(**{field: value}) != EXPECTED_TRANSCRIPT_HASH


def test_transcript_rejects_wrong_public_key_prefixes():
    with pytest.raises(ValueError, match="Central"):
        _transcript_hash(
            central_p256_public_key=b"\x03" + CENTRAL_PUBLIC_KEY[1:]
        )
    with pytest.raises(ValueError, match="Peripheral"):
        _transcript_hash(
            peripheral_p256_public_key=(
                b"\x03" + PERIPHERAL_PUBLIC_KEY[1:]
            )
        )


def test_hybrid_ikm_exact_layout_and_length():
    ikm = build_hybrid_ikm(SS_MLKEM, SS_ECDH)
    assert len(ikm) == PHASE7_HYBRID_IKM_SIZE == 68
    assert ikm == b"\x00\x20" + SS_MLKEM + b"\x00\x20" + SS_ECDH


def test_hybrid_key_schedule_kat_for_all_four_keys():
    keys = derive_phase7_keys(SS_MLKEM, SS_ECDH, EXPECTED_TRANSCRIPT_HASH)
    assert keys.application == EXPECTED_K_APP
    assert keys.sas == EXPECTED_K_SAS
    assert keys.finished_c == EXPECTED_K_FINISHED_C
    assert keys.finished_p == EXPECTED_K_FINISHED_P
    assert all(
        len(key) == 32
        for key in (
            keys.application,
            keys.sas,
            keys.finished_c,
            keys.finished_p,
        )
    )


def test_changing_either_component_changes_all_derived_keys():
    expected = derive_phase7_keys(
        SS_MLKEM, SS_ECDH, EXPECTED_TRANSCRIPT_HASH
    )
    changed_mlkem = derive_phase7_keys(
        _flip_one_bit(SS_MLKEM), SS_ECDH, EXPECTED_TRANSCRIPT_HASH
    )
    changed_ecdh = derive_phase7_keys(
        SS_MLKEM, _flip_one_bit(SS_ECDH), EXPECTED_TRANSCRIPT_HASH
    )

    for changed in (changed_mlkem, changed_ecdh):
        assert changed.application != expected.application
        assert changed.sas != expected.sas
        assert changed.finished_c != expected.finished_c
        assert changed.finished_p != expected.finished_p


def test_swapped_secret_order_does_not_match_key_schedule():
    swapped_ikm = build_hybrid_ikm(SS_ECDH, SS_MLKEM)
    swapped_key_block = HKDF(
        algorithm=hashes.SHA256(),
        length=128,
        salt=EXPECTED_TRANSCRIPT_HASH,
        info=PHASE7_KDF_INFO,
    ).derive(swapped_ikm)
    assert swapped_key_block[:32] != EXPECTED_K_APP


def test_sas_kat_and_six_digit_format():
    assert compute_phase7_sas(
        EXPECTED_K_SAS, EXPECTED_TRANSCRIPT_HASH
    ) == 559099
    assert format_phase7_sas(559099) == "559099"
    assert format_phase7_sas(42) == "000042"


def test_finished_kats():
    assert compute_phase7_finished_c(
        EXPECTED_K_FINISHED_C, EXPECTED_TRANSCRIPT_HASH
    ) == EXPECTED_FINISHED_C
    assert compute_phase7_finished_p(
        EXPECTED_K_FINISHED_P, EXPECTED_TRANSCRIPT_HASH
    ) == EXPECTED_FINISHED_P


def test_directional_traffic_key_kats_and_separation():
    keys = derive_phase7_traffic_keys(EXPECTED_K_APP)
    assert keys.central_to_peripheral == EXPECTED_K_C2P
    assert keys.peripheral_to_central == EXPECTED_K_P2C
    assert keys.central_to_peripheral != keys.peripheral_to_central


def test_test_only_scalar_rejects_invalid_values():
    with pytest.raises(ValueError):
        p256_private_key_from_scalar(0)
    with pytest.raises(TypeError):
        p256_private_key_from_scalar(True)


def test_non_p256_keys_are_rejected():
    wrong_curve_private = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError, match="P-256"):
        serialize_p256_public_key(wrong_curve_private)
    with pytest.raises(ValueError, match="P-256"):
        derive_p256_ecdh_shared_secret(
            wrong_curve_private, wrong_curve_private.public_key()
        )
