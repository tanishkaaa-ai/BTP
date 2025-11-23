# ============================================================
# utils/symmetric.py
# Simple symmetric encryption based on a GT key
# Used for Enc_KEY(M) and Dec_KEY(M) in the paper
# ============================================================

from charm.toolbox.pairinggroup import GT
import hashlib

def kdf_from_key(group, KEY_gt: GT, length: int) -> bytes:
    """
    Derive a pseudorandom keystream from a GT element KEY_gt.
    1) Serialize KEY_gt
    2) Hash with SHA-256
    3) Repeat / truncate to desired length
    """
    raw = group.serialize(KEY_gt)                 # group element -> bytes
    digest = hashlib.sha256(raw).digest()         # 32-byte hash
    # Repeat the hash until we cover 'length' bytes
    keystream = (digest * ((length // len(digest)) + 1))[:length]
    return keystream


def sym_enc(group, KEY_gt: GT, plaintext: bytes) -> bytes:
    """
    Symmetric 'encryption' using XOR with keystream derived from KEY_gt.
    This corresponds to CS = Enc_KEY(M) in the paper (Eq. 22).
    """
    ks = kdf_from_key(group, KEY_gt, len(plaintext))
    return bytes([p ^ k for p, k in zip(plaintext, ks)])


def sym_dec(group, KEY_gt: GT, ciphertext: bytes) -> bytes:
    """
    Symmetric decryption – XOR again with the same keystream.
    This corresponds to M = Dec_KEY(CS).
    """
    return sym_enc(group, KEY_gt, ciphertext)     # XOR is its own inverse
