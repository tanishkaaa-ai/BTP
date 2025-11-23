# ============================================================
# crypto/Decrypt.py  (Pure Python version, no charm)
# ------------------------------------------------------------
# This simulates the "Final Decrypt" stage from the CP-ABE paper.
# It follows the paper structure:
#   - Use C + CT0 to reconstruct KEY'
#   - Decrypt CS using KEY'
#   - Verify integrity with VK = (h(KEY'), h(M'))
#
# In our pure-python simulation, KEY' == KEY is stored in CT0["_KEY"]
# because we don't have real bilinear math, but logic is identical.
# ============================================================

import hashlib
from utils.symmetric import sym_dec


class FinalDecryptor:
    def __init__(self):
        pass

    def final_decrypt(self, C, CT0):
        """
        Inputs:
            C    : Output of partial decrypt (simulated as b"OK")
            CT0  : { CT, CS, VK, _KEY }
        
        Output:
            plaintext bytes

        Steps simulated as:
            1. Recover KEY' (paper: KEY' = C̃ / (C * e(...)))
            2. M' = Dec_KEY'(CS)
            3. Compute VK'
            4. Ensure VK' == VK
        """

        # Extract parts
        CT = CT0["CT"]
        CS = CT0["CS"]
        VK = CT0["VK"]
        KEY_prime = CT0["_KEY"]      # In real CP-ABE, this is derived via math

        # --------- Step 1: KEY' ready ---------
        # (Paper equation 27 simulated)

        # --------- Step 2: Decrypt CS ---------
        plaintext = sym_dec(KEY_prime, CS)

        # --------- Step 3: Compute VK' ---------
        # VK' = (hash(KEY'), hash(M'))
        h_KEY = hashlib.sha256(KEY_prime).hexdigest()
        h_M = hashlib.sha256(plaintext).hexdigest()
        VK_prime = (h_KEY, h_M)

        # --------- Step 4: Check VK ---------
        if VK_prime != VK:
            raise ValueError("Verification failed — data tampered or wrong key.")

        return plaintext
