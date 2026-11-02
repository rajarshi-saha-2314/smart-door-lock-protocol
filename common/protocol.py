"""Protocol formulas (Section 3), written once and shared by SD, DL, AS and the attacks.

Approved deviations from the original spec (see README "Design changes"):
  * D1  k1 also mixes an ephemeral-static ECDH secret Z = e·Q_AS, and M1 carries E = e·G.
  * D2  A = h(ID_U ‖ x ‖ v) with a per-card issue counter v.
  * D3  Auth_U = HMAC(SK, "U-CONFIRM" ‖ TID ‖ T5) — uses TID (DL never sees TID_new).
"""

from __future__ import annotations

from common.crypto_utils import HMAC, KDF, h, xor
from common.encoding import cat

ALLOW = "ALLOW"
DENY = "DENY"


# ---------------------------------------------------------------- registration


def compute_K_DL(ID_DL: str, x: bytes) -> bytes:
    """K_DL = h(ID_DL ‖ x)"""
    return h(cat(ID_DL, x))


def compute_A(ID_U: str, x: bytes, v: int) -> bytes:
    """A = h(ID_U ‖ x ‖ v)   (D2: v = card issue counter)"""
    return h(cat(ID_U, x, v))


def compute_RPW(PW_U: str, r: bytes) -> bytes:
    """RPW = h(PW_U ‖ r)"""
    return h(cat(PW_U, r))


def mask(ID_U: str, RPW: bytes) -> bytes:
    """h(ID_U ‖ RPW) — masks A inside B."""
    return h(cat(ID_U, RPW))


def compute_B(A: bytes, ID_U: str, RPW: bytes) -> bytes:
    """B = A ⊕ h(ID_U ‖ RPW)"""
    return xor(A, mask(ID_U, RPW))


def recover_A(B: bytes, ID_U: str, RPW: bytes) -> bytes:
    """A = B ⊕ h(ID_U ‖ RPW)"""
    return xor(B, mask(ID_U, RPW))


def fuzzy_verifier(ID_U: str, RPW: bytes, n0: int) -> int:
    """V = int(h(h(ID_U ‖ RPW))) mod n0"""
    return int.from_bytes(h(mask(ID_U, RPW)), "big") % n0


# ---------------------------------------------------------------- login


def aad_C1(TID: bytes, T1: int, ID_DL: str, E: bytes) -> bytes:
    return cat(TID, T1, ID_DL, E)


def derive_k1(A: bytes, Z: bytes, TID: bytes, T1: int, E: bytes) -> bytes:
    """k1 = KDF(A ‖ Z, "M1" ‖ TID ‖ T1 ‖ E)   (D1)"""
    return KDF(cat(A, Z), cat("M1", TID, T1, E))


def compute_Tag2(K_DL: bytes, M1_bytes: bytes, N2: bytes, T2: int, ID_DL: str) -> bytes:
    """Tag2 = HMAC(K_DL, M1 ‖ N2 ‖ T2 ‖ ID_DL)"""
    return HMAC(K_DL, cat(M1_bytes, N2, T2, ID_DL))


def derive_SK(N1: bytes, N2: bytes, N3: bytes, ID_DL: str, TID: bytes, T3: int) -> bytes:
    """SK = h(N1 ‖ N2 ‖ N3 ‖ ID_DL ‖ TID ‖ T3)"""
    return h(cat(N1, N2, N3, ID_DL, TID, T3))


def aad_C_DL(ID_DL: str, TID: bytes, N2: bytes) -> bytes:
    return cat(ID_DL, TID, N2)


def derive_k_u(A: bytes, N1: bytes, T3: int) -> bytes:
    """k_u = KDF(A, "M3" ‖ N1 ‖ T3)"""
    return KDF(A, cat("M3", N1, T3))


def aad_C_U(TID: bytes, ID_DL: str) -> bytes:
    return cat(TID, ID_DL)


def compute_Auth_DL(SK: bytes, ID_DL: str, TID: bytes, T4: int) -> bytes:
    """Auth_DL = HMAC(SK, "DL-CONFIRM" ‖ ID_DL ‖ TID ‖ T4)"""
    return HMAC(SK, cat("DL-CONFIRM", ID_DL, TID, T4))


def compute_Auth_U(SK: bytes, TID: bytes, T5: int) -> bytes:
    """Auth_U = HMAC(SK, "U-CONFIRM" ‖ TID ‖ T5)   (D3)"""
    return HMAC(SK, cat("U-CONFIRM", TID, T5))


def aad_session(ID_DL: str, TID: bytes, seq: int, sender: str) -> bytes:
    """AAD for post-handshake traffic protected with Enc_SK."""
    return cat("SESSION", ID_DL, TID, seq, sender)
