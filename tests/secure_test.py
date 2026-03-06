import base64

from uiauth import secure


def test_calculate_hash_length():
    result = secure.calculate_hash("hello")
    assert len(result) == 128  # SHA-512 produces 128 hex chars


def test_calculate_hash_deterministic():
    assert secure.calculate_hash("hello") == secure.calculate_hash("hello")


def test_calculate_hash_different_inputs():
    assert secure.calculate_hash("hello") != secure.calculate_hash("world")


def test_base64_encode_decode_roundtrip():
    for value in ["hello", "password123", "user@example.com", "with spaces"]:
        assert secure.base64_decode(secure.base64_encode(value)) == value


def test_base64_encode_output_is_valid():
    encoded = secure.base64_encode("test")
    assert base64.b64decode(encoded.encode()) == b"test"


def test_hex_encode_decode_roundtrip():
    for value in ["admin", "password123", "hello world", "test@email.com", "pass!@#"]:
        assert secure.hex_decode(secure.hex_encode(value)) == value


def test_hex_encode_contains_unicode_prefix():
    result = secure.hex_encode("a")
    assert "\\u00" in result


def test_hex_encode_different_inputs_differ():
    assert secure.hex_encode("admin") != secure.hex_encode("user")
