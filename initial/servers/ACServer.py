# ============================================================
# servers/ACServer.py  (FINAL VERSION)
# Implements:
# - Cloud ciphertext storage
# - Token verification (Eq. 25)
# - Outsourced partial decryption (Eq. 26)
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, G1, pair
from servers.CloudStorage import CloudStorage


class AccessControlServer:
    def __init__(self, aa, group_name='MNT224'):
        """
        aa         : AttributeAuthority instance (provides PK, Tpub_AA, hash_h2)
        """
        self.group = PairingGroup(group_name)
        self.aa = aa
        self.cloud = CloudStorage()        # <- Use cloud layer for storage
        self.user_table = {}               # user_id -> (ID_i, QID_i)

    # ------------------- Storage -------------------
    def store_ciphertext(self, file_id: str, CT0: dict):
        self.cloud.upload(file_id, CT0)

    def fetch_ciphertext(self, file_id: str):
        return self.cloud.download(file_id)

    # ------------------- Registration -------------------
    def register_user_from_aa(self, user_id: str, ID_i, QID_i):
        """
        AC stores user identity tuple for token verification.
        """
        self.user_table[user_id] = (ID_i, QID_i)

    # ------------------- Token Verification (Eq. 25) -------------------
    def verify_token(self, user_id: str, PSK_IDi, ID_i):
        """
        Verifies:
            PSK_IDi * P == QID_i + h2(ID_i, QID_i) * Tpub_AA
        """

        # Retrieve from table
        ID_i_ref, QID_i = self.user_table[user_id]

        if ID_i != ID_i_ref:
            return False

        P = self.aa.P
        Tpub_AA = self.aa.Tpub_AA

        left = PSK_IDi * P
        h2_val = self.aa.hash_h2(ID_i, QID_i)
        right = QID_i + (h2_val * Tpub_AA)

        return left == right

    # ------------------- Partial Decryption (Eq. 26) -------------------
    def partial_decrypt(self, file_id: str, SK: dict):
        """
        Computes:
            C = e(g^r, C') / e(C_hat, ∏ g^t_i)
        """

        CT0 = self.fetch_ciphertext(file_id)
        CT = CT0["CT"]

        AS = CT["AS"]
        C_hat = CT["C_hat"]        # g^s
        C_prime = CT["C_prime"]    # (h * Π C_i)^s

        D_i1 = SK["D_i1"]          # each = g^{r_i}
        AU_star = SK["S"]

        # ----- Compute g^r = Π g^{r_i} -----
        g_r = self.group.init(G1, 1)
        for att in AU_star:
            if att in D_i1:
                g_r *= D_i1[att]

        numerator = pair(g_r, C_prime)

        # ----- Compute Π g^{t_i} for all attributes in policy -----
        prod_T = self.group.init(G1, 1)
        for att in AS:
            Ti = self.aa.PK["T_i"][att]
            prod_T *= Ti

        denominator = pair(C_hat, prod_T)

        C = numerator / denominator  # e(g,g)^{r·s}

        return C, CT0
