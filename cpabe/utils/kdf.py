# ============================================================
# Helper: KDF from GT -> bytes
# ============================================================
import hashlib
def kdf(self, K_gt):
    """
    Derive a symmetric key from a GT element using SHA-256 over its
    serialized byte representation.
    """
    K_bytes = self.group.serialize(K_gt)
    return hashlib.sha256(K_bytes).digest()
