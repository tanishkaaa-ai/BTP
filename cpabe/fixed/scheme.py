# sensors_cpabe_fixed_idbound.py
# ============================================================
# Fixed CP-ABE Scheme with:
#   1) Identity-Bound Decryption Exponents (h_i = H(ID_i))
#   2) Traceability via (QID_i, PSK_i) and public (P, Tpub_AA)
#
# This file combines:
#   - Your original collusion fix (identity-bound D' and D_j)
#   - The traceability mechanism from the paper:
#
#       QID_i  = d_i * P
#       PSK_i  = d_i + h2(ID_i, QID_i) * alpha
#
#   - A token verification equation:
#
#       PSK_i * P  ==  QID_i + h2(ID_i, QID_i) * Tpub_AA
#
# Ciphertext structure and encryption remain unchanged.
# Only the secret key and auxiliary traceability info are extended.
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, G1, ZR
from cpabe.fixed.keygen import keygen as keygen_mod
from cpabe.fixed.encrypt import encrypt as encrypt_mod
from cpabe.fixed.decrypt_partial import partial_decrypt as partial_mod
from cpabe.fixed.decrypt_final import final_decrypt as final_mod
from cpabe.utils.verification import verify_token as verify_token_mod

from charm.toolbox.pairinggroup import pair


class SensorsCPABEFixedIDBound:
    """
    Fixed CP-ABE with Identity-Bound Decryption + Traceability.

    ---------------------- Identity Binding ----------------------

    Let ID_i be the user's (anonymous) identity as bytes.
    We derive an identity exponent:

        h_i = H(ID_i) ∈ Z_p

    Original (flawed-style) exponents for the decryption key were:

        D'   = g^(α - r)
        D_j  = g^(r_j)

    where r = Σ r_j over attributes.

    Our FIX modifies them to:

        D'*  = g^(α - r + h_i)
        D*_j = g^(r_j + h_i)

    So there is an extra identity term h_i sprinkled into all
    decryption exponents. Combined with the ciphertext exponent s,
    this yields additional terms in the decryption pairing output
    that depend on h_i.

    Only the legitimate user who *knows* h_i can remove those
    extra factors. If two different users with different h_i
    try to collude, their exponents cannot be combined into one
    clean factor, and decryption fails.

    ------------------------- Traceability ------------------------

    In addition to identity binding, we add traceability components
    for each user:

        d_i   ← random in Z_p
        QID_i = d_i * P        (G1 element)
        h2    = H2(ID_i, QID_i) ∈ Z_p
        PSK_i = d_i + h2 * α   (scalar in Z_p)

    Here P is a public G1 base (from setup), and:

        Tpub_AA = α * P        (public traceability key in G1)

    During token verification, we check:

        PSK_i * P  ==  QID_i + h2 * Tpub_AA

    This binds PSK_i, QID_i, ID_i, and the AA master secret α
    into a single equation, preventing impersonation and
    unauthorized key/token sharing.

    ------------------ Ciphertext & Decryption -------------------

    Ciphertext and encryption remain unchanged coarsely:
        - CT carries (Ce, C_hat, CS, VK1, VK2, policy_attrs)
        - Ce  = KEY * e(g,g)^(α s)
        - C_hat = g^s
        - CS = SymEnc_KEY(M)
        - VK = (g^{h(KEY)}, g^{h(M)})

    Partial decrypt constructs a "C*" term via pairings with D*_j,
    and final decrypt uses D'* and the identity exponent h_i
    to reconstruct the original KEY, then decrypts and checks VK.
    """

    # ============================================================
    # Constructor
    # ============================================================
    def __init__(self, group_name='SS512'):
        # Underlying bilinear pairing group
        self.group = PairingGroup(group_name)

        # Traceability base (public) in G1. Each user's QID_i = d_i * P.
        self.P = self.group.random(G1)

        # Tpub_AA = alpha * P (will be set in setup)
        self.Tpub_AA = None

    # ============================================================
    # Setup: generate system public key and master key
    # ============================================================
    def setup(self):
        """
        Setup() -> (pk, mk)

        Steps:
          1) Choose random g ∈ G1
          2) α ∈ Z_p randomly
          3) Y = e(g,g)^α ∈ GT
          4) Tpub_AA = α * P ∈ G1 for traceability

        Public key:
            pk = { g, Y, P, Tpub_AA }

        Master key:
            mk = { alpha }
        """
        g = self.group.random(G1)
        alpha = self.group.random(ZR)

        # Y = e(g,g)^α
        Y = pair(g, g) ** alpha

        # Traceability public key: Tpub_AA = α P
        self.Tpub_AA = alpha * self.P

        pk = {
            'g': g,
            'Y': Y,
            'P': self.P,
            'Tpub_AA': self.Tpub_AA
        }
        mk = {
            'alpha': alpha
        }
        self.mk = mk 
        return pk, mk
    
# ------------------------------------------------------------
    # Key Generation (delegated)
    # ------------------------------------------------------------
    def keygen(self, pk, mk, user_id_bytes, user_attrs):
        return keygen_mod(self.group, pk, mk, user_id_bytes, user_attrs)

    # ------------------------------------------------------------
    # Token Verify (delegated to utils)
    # ------------------------------------------------------------
    def verify_token(self, pk, sk):
        return verify_token_mod(self.group, pk, sk)

    # ------------------------------------------------------------
    # Encrypt (delegated)
    # ------------------------------------------------------------
    def encrypt(self, pk, message_bytes, policy_attrs):
        return encrypt_mod(self.group, pk, message_bytes, policy_attrs)

    # ------------------------------------------------------------
    # Partial Decrypt (delegated)
    # ------------------------------------------------------------
    def partial_decrypt(self, pk, ct, sk):
        return partial_mod(self.group, pk, ct, sk)

    # ------------------------------------------------------------
    # Final Decrypt (delegated)
    # ------------------------------------------------------------
    def final_decrypt(self, pk, sk, C_star, ct):
        return final_mod(self.group, pk, sk, C_star, ct)