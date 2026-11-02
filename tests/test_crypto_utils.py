from __future__ import annotations

import pytest

from common import crypto_utils as cu
from common.encoding import b64d, b64e, canonical_json, cat, split, to_int


def test_h_is_sha256() -> None:
    assert cu.h(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hmac_rfc4231_case2() -> None:
    tag = cu.HMAC(b"Jefe", b"what do ya want for nothing?")
    assert tag.hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


def test_kdf_length_and_domain_separation() -> None:
    k = b"\x01" * 32
    assert len(cu.KDF(k, b"M1")) == 32
    assert cu.KDF(k, b"M1") != cu.KDF(k, b"M3")
    assert cu.KDF(k, b"M1") == cu.KDF(k, b"M1")


def test_aes_gcm_roundtrip_and_random_nonce() -> None:
    k = cu.rand(32)
    c1 = cu.Enc(k, b"secret", b"aad")
    c2 = cu.Enc(k, b"secret", b"aad")
    assert c1 != c2  # fresh nonce each time
    assert cu.Dec(k, c1, b"aad") == b"secret"


@pytest.mark.parametrize("where", ["nonce", "body", "tag"])
def test_aes_gcm_detects_tampering(where: str) -> None:
    k = cu.rand(32)
    c = bytearray(cu.Enc(k, b"secret message", b"aad"))
    idx = {"nonce": 0, "body": 14, "tag": len(c) - 1}[where]
    c[idx] ^= 0x01
    with pytest.raises(cu.IntegrityError):
        cu.Dec(k, bytes(c), b"aad")


def test_aes_gcm_detects_wrong_aad_and_key() -> None:
    k = cu.rand(32)
    c = cu.Enc(k, b"m", b"aad")
    with pytest.raises(cu.IntegrityError):
        cu.Dec(k, c, b"other")
    with pytest.raises(cu.IntegrityError):
        cu.Dec(cu.rand(32), c, b"aad")
    with pytest.raises(cu.IntegrityError):
        cu.Dec(k, b"short", b"aad")


def test_ecdsa_sign_verify() -> None:
    sk = cu.ecdsa_keygen()
    sig = cu.ecdsa_sign(sk, b"log entry")
    assert cu.ecdsa_verify(sk.public_key(), sig, b"log entry")
    assert not cu.ecdsa_verify(sk.public_key(), sig, b"log entry!")
    assert not cu.ecdsa_verify(cu.ecdsa_keygen().public_key(), sig, b"log entry")


def test_key_pem_roundtrip() -> None:
    sk = cu.ecdsa_keygen()
    sk2 = cu.load_private_key_pem(cu.private_key_to_pem(sk))
    pk2 = cu.load_public_key_pem(cu.public_key_to_pem(sk.public_key()))
    assert cu.ecdsa_verify(pk2, cu.ecdsa_sign(sk2, b"m"), b"m")


def test_ecdh_agreement() -> None:
    d_AS, Q_AS = cu.ecdh_keygen()
    e, E = cu.ecdh_keygen()
    assert len(Q_AS) == 33 and len(E) == 33
    assert cu.ecdh(e, Q_AS) == cu.ecdh(d_AS, E)
    with pytest.raises(cu.IntegrityError):
        cu.ecdh(e, b"\x02" + b"\xff" * 32)  # x >= p: not a curve point


def test_xor_rand_ct_eq() -> None:
    a, b = cu.rand(32), cu.rand(32)
    assert cu.xor(cu.xor(a, b), b) == a
    with pytest.raises(ValueError):
        cu.xor(a, b"x")
    assert len(cu.rand(16)) == 16 and cu.rand(16) != cu.rand(16)
    assert cu.ct_eq(a, a) and not cu.ct_eq(a, b)


def test_cat_is_unambiguous_and_invertible() -> None:
    assert cat("ab", "c") != cat("a", "bc")
    assert cat(b"", b"x") != cat(b"x", b"")
    packed = cat("ID", b"\x00\x01", 1234567890123)
    fields = split(packed, expected=3)
    assert fields[0] == b"ID" and fields[1] == b"\x00\x01" and to_int(fields[2]) == 1234567890123
    with pytest.raises(ValueError):
        split(packed[:-1])
    with pytest.raises(ValueError):
        split(packed, expected=2)


def test_base64_and_canonical_json() -> None:
    assert b64d(b64e(b"\x00\xff")) == b"\x00\xff"
    with pytest.raises(ValueError):
        b64d("not base64!!")
    assert canonical_json({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'
