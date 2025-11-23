# ============================================================
# crypto/Encrypt.py
# Encryption phase of the CP-ABE scheme
# Generates CT (public CP-ABE ciphertext), CS (symmetric),
# and VK (verification tag)
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
from utils.symmetric import sym_enc
import hashlib

class Encryptor:
    def __init__(self, PK, group_name='MNT224'):
        """
        PK      : public key from AttributeAuthority (AA)
        group_name : pairing curve name
        """
        self.group = PairingGroup(group_name)
        self.PK = PK

    def encrypt(self, message: bytes, AS):
        """
        Encrypt(PK, M, AS) = CT0 = (CT, CS, VK)

        Inputs:
        - message : bytes of the medical data, e.g. b"ECG..."
        - AS      : access structure (list of attributes) e.g. ["Doctor", "Cardiology"]

        Steps follow Section 4.2.4, Eq. (15)–(23).
        """

        g = self.PK["g"]          # generator g ∈ G1
        h = self.PK["h"]          # h = g^β
        Y = self.PK["Y"]          # Y = e(g,g)^α
        T_i = self.PK["T_i"]      # attribute elements T_i = g^t_i

        # ---------- Eq. (15): choose random s in Z_p ----------
        s = self.group.random(ZR)

        # ---------- Choose random symmetric key KEY ∈ GT ----------
        # (paper treats KEY as a random GT element used as symmetric key)
        KEY = pair(g, g) ** self.group.random(ZR)

        # ---------- Eq. (16): C̃, Cˇ, C̅ ----------
        # C_tilde = KEY * Y^s
        C_tilde = (Y ** s) * KEY

        # C_hat = g^s
        C_hat = g ** s

        # C_bar = h^s = (g^β)^s
        C_bar = h ** s

        # ---------- Eq. (17)–(18): C_i for each attribute ----------
        # In full scheme, C_i depends on whether v_{i,1} ∈ W_i or not.
        # Here we simplify: C_i = T_i^s for each attribute in AS.
        C_i = {}
        for att in AS:
            Ti = T_i[att]               # T_i = g^t_i for this attribute
            C_i[att] = Ti ** s          # C_i = (g^t_i)^s = g^(t_i s)

        # ---------- Eq. (19)–(20): C' ----------
        # C' = (h * ∏ C_i)^s
        prod = h                        # start with h
        for att in AS:
            prod *= C_i[att]            # accumulate h * C_i1 * C_i2 * ...

        C_prime = prod ** s             # raise to s

        # ---------- Eq. (21): CT ----------
        CT = {
            "AS": list(AS),             # access structure / policy
            "C_tilde": C_tilde,         # KEY * Y^s
            "C_hat": C_hat,             # g^s
            "C_bar": C_bar,             # h^s
            "C_prime": C_prime          # (h * ∏C_i)^s
        }

        # ---------- Eq. (22): CS = Enc_KEY(M) ----------
        CS = sym_enc(self.group, KEY, message)

        # ---------- Eq. (22): VK = (g^{h(KEY)}, g^{h(M)}) ----------
        # First hash KEY and M
        h_KEY_bytes = hashlib.sha256(self.group.serialize(KEY)).digest()
        h_M_bytes = hashlib.sha256(message).digest()

        # Map these hashes into exponents in ZR
        exp_KEY = self.group.init(ZR, int.from_bytes(h_KEY_bytes, 'big'))
        exp_M = self.group.init(ZR, int.from_bytes(h_M_bytes, 'big'))

        # g^{h(KEY)}, g^{h(M)} (use same generator g)
        VK = (g ** exp_KEY, g ** exp_M)

        # ---------- Eq. (23): CT0 = < CT , CS, VK > ----------
        CT0 = {
            "CT": CT,
            "CS": CS,
            "VK": VK
        }
        return CT0
