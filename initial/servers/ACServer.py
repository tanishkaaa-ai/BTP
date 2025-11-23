# ============================================================
# servers/ACServer.py
# Access Control server:
# - Stores ciphertext in "cloud"
# - Verifies token
# - Performs partial decrypt(CT, AU*, SK) -> C
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, G1, pair

class AccessControlServer:
    def __init__(self, aa, group_name='MNT224'):
        """
        aa         : instance of AttributeAuthority (for shared info / Tpub_AA)
        group_name : pairing curve name
        """
        self.group = PairingGroup(group_name)
        self.aa = aa
        self.storage = {}         # file_id -> CT0
        self.user_table = {}      # user_id -> (ID_i, QID_i) (shared by AA)

    # ---------- Storage ----------
    def store_ciphertext(self, file_id: str, CT0: dict):
        """
        Save CT0 into cloud database.
        """
        self.storage[file_id] = CT0

    def fetch_ciphertext(self, file_id: str):
        """
        Retrieve CT0 from cloud.
        """
        return self.storage[file_id]

    # ---------- Registration from AA ----------
    def register_user_from_aa(self, user_id: str, ID_i, QID_i):
        """
        AA calls this (or main code calls with values from AA)
        to let AC know (ID_i, QID_i) for trace / token verification.
        """
        self.user_table[user_id] = (ID_i, QID_i)

    # ---------- Token verification (tracking-related) ----------
    def verify_token(self, user_id: str, PSK_IDi, ID_i):
        """
        Implements Eq. (25) style check:
            PSK_IDi * P  ==  QID_i + h2(ID_i, QID_i) * Tpub_AA

        This confirms that the token was made by the legitimate user
        without revealing their real identity to the AC server.
        """
        # Get mapping (ID_i_ref, QID_i) that AA has registered
        ID_i_ref, QID_i = self.user_table[user_id]

        # If ID values don't match, reject early
        if ID_i_ref != ID_i:
            return False

        # Left hand side: PSK_IDi * P
        P = self.aa.P                   # P from AA (elliptic curve generator)
        left = PSK_IDi * P

        # Right side: QID_i + h2(ID_i, QID_i) * Tpub_AA
        h2_val = self.aa.hash_h2(ID_i, QID_i)
        right = QID_i + (h2_val * self.aa.Tpub_AA)

        return left == right

    # ---------- Partial decrypt ----------
    def partial_decrypt(self, file_id: str, SK: dict):
        """
        partial_decrypt(CT, AU*, x) = C

        From paper Eq. (26), conceptually:
            C = e(g^r, C') / e(C_hat, (∏ g^t_i)^s) = e(g,g)^{r·s}

        Here:
        - We reconstruct g^r from SK["D_i1"] (each D_i1 = g^{r_i})
        - Use CT["C_prime"], CT["C_hat"], and AA's T_i
        """

        CT0 = self.fetch_ciphertext(file_id)
        CT = CT0["CT"]

        # Extract ciphertext pieces
        AS = CT["AS"]
        C_hat = CT["C_hat"]       # g^s
        C_prime = CT["C_prime"]   # (h * ∏C_i)^s (approx.)

        # Extract user key pieces
        D_i1 = SK["D_i1"]         # dict: attribute -> g^{r_i}
        AU_star = SK["S"]         # user attributes set

        # --------- Build g^r = ∏ g^{r_i} = ∏ D_i1[att] ----------
        g_r = self.group.init(G1, 1)  # identity in G1
        for att in AU_star:
            if att in D_i1:
                g_r *= D_i1[att]      # multiply them: g^r1 * g^r2 ...

        # Numerator = e(g^r, C_prime)
        numerator = pair(g_r, C_prime)

        # Denominator approximates e(C_hat, ∏ g^{t_i})
        prod_T = self.group.init(G1, 1)
        for att in AS:
            Ti = self.aa.PK["T_i"][att]   # g^{t_i}
            prod_T *= Ti

        denominator = pair(C_hat, prod_T)

        # C = numerator / denominator ≈ e(g,g)^{r·s}
        C = numerator / denominator

        return C, CT0
