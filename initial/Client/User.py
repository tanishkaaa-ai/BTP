# ============================================================
# client/User.py
# User-side client:
# - Holds SK and ID_i
# - Creates token (PSK_IDi + attributes)
# - Performs final decryption and verification
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, ZR
from utils.symmetric import sym_dec
import hashlib

class UserClient:
    def __init__(self, user_id: str, ID_i, SK: dict, aa, group_name='MNT224'):
        """
        user_id : string identifier (for AC & AA)
        ID_i    : anonymous identity dict from TA
        SK      : secret key from AA (has S, PSK_IDi, D0, D_i1, QID_i)
        aa      : AttributeAuthority instance (to get PK, etc.)
        """
        self.group = PairingGroup(group_name)
        self.user_id = user_id
        self.ID_i = ID_i
        self.SK = SK
        self.aa = aa

    # ---------- Token creation (Eq. 24) ----------
    def create_token(self):
        """
        Token(TK) = PSK_IDi || AU*
        Used for AC server access / verification.
        """
        return {
            "PSK_IDi": self.SK["PSK_IDi"],
            "AU_star": list(self.SK["S"]),
            "ID_i": self.ID_i
        }

    # ---------- Final decryption (Eq. 27–29) ----------
    def final_decrypt(self, C, CT0):
        """
        Final decrypt(PK, SK, C, CT0) -> M

        Steps:
        1) Compute KEY' from C_tilde, C_hat, D0, C  (Eq. 27)
        2) Use KEY' to decrypt CS -> M'
        3) Compute VK' from KEY' and M' (Eq. 29)
        4) Compare VK' with VK from CT0; if equal, accept.
        """
        CT = CT0["CT"]
        CS = CT0["CS"]
        VK = CT0["VK"]

        # Extract ciphertext components
        C_tilde = CT["C_tilde"]    # KEY * Y^s
        C_hat = CT["C_hat"]        # g^s

        # Extract secret key components
        D0 = self.SK["D0"]         # g^(α - r)

        # ---------- Eq. (27): KEY' ----------
        # denom1 = e(C_hat, D0) = e(g^s, g^(α - r)) = e(g,g)^{s(α - r)}
        denom1 = self.group.pair(C_hat, D0)

        # KEY_num = C_tilde = KEY * e(g,g)^{α s}
        KEY_num = C_tilde

        # KEY_denom = denom1 * C = e(g,g)^{s(α - r)} * e(g,g)^{r s}
        KEY_denom = denom1 * C

        # KEY' = KEY_num / KEY_denom = KEY
        KEY_prime = KEY_num / KEY_denom

        # ---------- Decrypt CS with KEY' ----------
        plaintext_bytes = sym_dec(self.group, KEY_prime, CS)
        M_prime = plaintext_bytes

        # ---------- Eq. (29): VK' ----------
        # Compute hashes h(KEY'), h(M')
        h_KEY_bytes = hashlib.sha256(self.group.serialize(KEY_prime)).digest()
        h_M_bytes = hashlib.sha256(M_prime).digest()

        # Map to exponents in ZR
        exp_KEY = self.group.init(ZR, int.from_bytes(h_KEY_bytes, 'big'))
        exp_M = self.group.init(ZR, int.from_bytes(h_M_bytes, 'big'))

        # g^{h(KEY')}, g^{h(M')} with g from AA's PK
        g = self.aa.PK["g"]
        VK_prime = (g ** exp_KEY, g ** exp_M)

        # Compare VK' with ciphertext VK
        if VK_prime != VK:
            raise ValueError("Verification failed: VK' != VK (message may be tampered)")

        return M_prime
