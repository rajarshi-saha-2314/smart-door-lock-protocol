"""The ONLY module that calls cryptographic primitives.

Everything is delegated to the ``cryptography`` library; randomness comes from
``secrets``. Function names follow the protocol notation:

    h(m)          SHA-256
    HMAC(k, m)    HMAC-SHA256
    KDF(k, info)  HKDF-SHA256, 32-byte output
    Enc(k, m, aad) / Dec(k, c, aad)   AES-256-GCM, random 12-byte nonce
"""

from __future__ import annotations

import hmac as _hmac
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac as _chmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32
GCM_NONCE_LEN = 12
CURVE = ec.SECP256R1()

PrivateKey = ec.EllipticCurvePrivateKey
PublicKey = ec.EllipticCurvePublicKey


class IntegrityError(Exception):
    """AEAD tag or signature verification failed."""


# ---------------------------------------------------------------- symmetric


def h(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def HMAC(key: bytes, data: bytes) -> bytes:
    mac = _chmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def KDF(key: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key)


def Enc(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM. Output = nonce(12) ‖ ciphertext ‖ tag(16)."""
    nonce = rand(GCM_NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def Dec(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < GCM_NONCE_LEN + 16:
        raise IntegrityError("ciphertext too short")
    try:
        return AESGCM(key).decrypt(blob[:GCM_NONCE_LEN], blob[GCM_NONCE_LEN:], aad)
    except InvalidTag as exc:
        raise IntegrityError("AES-GCM authentication failed") from exc


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor operands must have equal length")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def rand(n: int = 16) -> bytes:
    return secrets.token_bytes(n)


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality for tags and verifiers."""
    return _hmac.compare_digest(a, b)


# ---------------------------------------------------------------- ECDSA (audit log)


def ecdsa_keygen() -> PrivateKey:
    return ec.generate_private_key(CURVE)


def ecdsa_sign(sk: PrivateKey, data: bytes) -> bytes:
    return sk.sign(data, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(pk: PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        pk.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------- ECDH (M1 key agreement)


def ecdh_keygen() -> tuple[PrivateKey, bytes]:
    """Return (private key, compressed public point — 33 bytes)."""
    priv = ec.generate_private_key(CURVE)
    return priv, point_bytes(priv.public_key())


def ecdh(priv: PrivateKey, peer_point: bytes) -> bytes:
    """Shared secret Z = priv · peer_point (x-coordinate, 32 bytes)."""
    try:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, peer_point)
    except ValueError as exc:
        raise IntegrityError("invalid EC point") from exc
    return priv.exchange(ec.ECDH(), peer)


def point_bytes(pk: PublicKey) -> bytes:
    return pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


# ---------------------------------------------------------------- key serialization


def private_key_to_pem(sk: PrivateKey) -> bytes:
    return sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_to_pem(pk: PublicKey) -> bytes:
    return pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key_pem(data: bytes) -> PrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("not an EC private key")
    return key


def load_public_key_pem(data: bytes) -> PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("not an EC public key")
    return key
