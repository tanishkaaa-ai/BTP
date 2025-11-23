# ============================================================
# Attribute Authority (AA)
# Setup(k) -> (PK, AMK)
# KeyGen(ID_i, AU*) -> SK
# Based on Sensors 2020 CP-ABE IoMT scheme
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
import hashlib

class AttributeAuthority:

    def __init__(self, universe_attributes):
        """
        universe_attributes = U = [att1, att2, ... att_n]
        Represents all attributes possible in the system.
        """

        # Initialize pairing group G1, GT based on elliptic curve MNT224
        self.group = PairingGroup('MNT224')

        # Generator element g ∈ G1
        self.g = self.group.random(G1)

        # ---------------- SETUP STEP ----------------
        # α, β, t_i ∈ Zp (random exponents defined in Section 4.2.2)
        self.alpha = self.group.random(ZR)    # α
        self.beta = self.group.random(ZR)     # β

        # Public parameter h = g^β  (Eq. 8)
        self.h = self.g ** self.beta

        # Y = e(g,g)^α used in ciphertext (Eq. 8)
        self.Y = pair(self.g, self.g) ** self.alpha

        # Attribute exponent table t_i and T_i = g^t_i for each attribute (Eq. 8)
        self.t_i = {}
        self.T_i = {}

        for att in universe_attributes:
            t = self.group.random(ZR)       # random exponent for attribute
            self.t_i[att] = t
            self.T_i[att] = self.g ** t     # T_i = g^t_i

        # Build public and master keys (Eq. 8 and 9)
        self.PK = {
            "g": self.g,
            "h": self.h,
            "Y": self.Y,
            "T_i": self.T_i
        }

        # Master key needed only by AA
        self.AMK = {"alpha": self.alpha, "beta": self.beta, "t_i": self.t_i}


    # ---------------- KEYGEN PHASE ----------------
    def keygen(self, ID_i, AU_star):
        """
        KeyGen(PK, ID_i, AMK, AU*) -> SK   (Section 4.2.3)
        AU_star = set of attributes belonging to user
        """

        # d_i random Zq* used for user private component (paper step "random d_i")
        d_i = self.group.random(ZR)

        # QID_i = d_i * g (EC-style encoded identity representation)
        QID_i = d_i * self.g

        # h2 hash used for linking ID and QID without revealing identity (Eq. 11)
        concat = (str(ID_i) + str(QID_i)).encode('utf-8')
        h2_val = self.group.init(ZR, int.from_bytes(hashlib.sha256(concat).digest(), 'big'))

        # PSK_IDi = d_i + h2(ID_i,QID_i)*α   (Eq. 11)
        PSK_IDi = d_i + h2_val * self.alpha

        # For each attribute in user set: r_j ∈ Zp  (Eq. 13)
        r_j = {att: self.group.random(ZR) for att in AU_star}

        # r = Σ r_j  (Eq. 13)
        r = sum(r_j.values(), self.group.init(ZR, 0))

        # D0 = g^(α - r)  (Eq. 14)
        D0 = self.g ** (self.alpha - r)

        # D_i1 = g^r_j for each attribute (Eq. 14)
        D_i1 = {att: self.g ** r_val for att, r_val in r_j.items()}

        # Construct final secret key SK (Eq. 14)
        SK = {
            "S": set(AU_star),
            "PSK_IDi": PSK_IDi,
            "QID_i": QID_i,
            "D0": D0,
            "D_i1": D_i1
        }

        return SK
