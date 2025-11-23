# ============================================================
# crypto/Decrypt.py
# Final Decryption after outsourcing stage
# ============================================================

from charm.toolbox.pairinggroup import PairingGroup, ZR
from utils.symmetric import sym_dec
import hashlib

class FinalDecryptor:
    def __init__(self, PK, group_name='MNT224'):
        self.group = PairingGroup(group_name)
        self.PK = PK

    def final_decrypt(self, C, CT0, SK):
        CT = CT0["CT"]
        CS = CT0["CS"]
        VK = CT0["VK"]

        C_tilde = CT["C_tilde"]
        C_hat = CT["C_hat"]
        D0 = SK["D0"]

        denom1 = self.group.pair(C_hat, D0)
        KEY_prime = C_tilde / (denom1 * C)

        plaintext = sym_dec(self.group, KEY_prime, CS)

        h_KEY = hashlib.sha256(self.group.serialize(KEY_prime)).digest()
        h_M = hashlib.sha256(plaintext).digest()

        exp_KEY = self.group.init(ZR, int.from_bytes(h_KEY, 'big'))
        exp_M = self.group.init(ZR, int.from_bytes(h_M, 'big'))

        g = self.PK["g"]
        VK_prime = (g ** exp_KEY, g ** exp_M)

        if VK_prime != VK:
            raise ValueError("Verification Failed — Data modified or wrong key")

        return plaintext
