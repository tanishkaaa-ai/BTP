# ============================================================
# crypto/CPABE_basic.py
# Basic CP-ABE Implementation (Setup & KeyGen)
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair

class CPABE_Basic:
    def __init__(self, group_name='MNT224'):
        self.group = PairingGroup(group_name)

    # ------------------ SETUP ------------------
    def setup(self):
        g = self.group.random(G1)
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)

        h = g ** beta
        Y = pair(g, g) ** alpha

        PK = {"g": g, "h": h, "Y": Y}
        MK = {"alpha": alpha, "beta": beta}
        return PK, MK

    # ------------------ KEY GENERATION ------------------
    def keygen(self, PK, MK, S):
        r = self.group.random(ZR)
        D0 = PK["g"] ** (MK["alpha"] - r)
        D_i = {attr: PK["g"] ** self.group.random(ZR) for attr in S}

        SK = {"S": S, "D0": D0, "D_i": D_i}
        return SK
