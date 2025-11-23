# demo/run_demo.py
# ============================================================
# End-to-end flow (pure Python CP-ABE-like demo)
# ============================================================

from authorities.TA import TraceAuthority
from authorities.AA import AttributeAuthority
from servers.ACServer import AccessControlServer
from client.User import UserClient
from crypto.Encrypt import Encryptor


def main():
    print("\n=== CP-ABE IoMT Demo (Pure Python) ===\n")

    # ---------- 1. Setup authorities ----------
    U = ["Doctor", "Nurse", "Cardiology"]
    aa = AttributeAuthority(U)
    ta = TraceAuthority()
    ac = AccessControlServer(aa)

    # ---------- 2. User registration at TA ----------
    RID = "RealID123"
    ID_i = ta.register(RID, "Tanisha", "2025")
    print("[TA] Anonymous ID_i =", ID_i)

    # ---------- 3. AA issues SK to user ----------
    user_attrs = ["Doctor", "Cardiology"]
    SK = aa.keygen_with_trace(ID_i, user_attrs)
    print("[AA] Secret key SK with attributes:", user_attrs)

    user_id = "user1"
    ac.register_user_from_aa(user_id, ID_i, SK["QID_i"])

    # ---------- 4. Create user client ----------
    user = UserClient(user_id, ID_i, SK, aa)

    # ---------- 5. Data owner encrypts medical record ----------
    encryptor = Encryptor(aa.PK)
    message = b"Patient ECG: Normal sinus rhythm."
    AS = ["Doctor", "Cardiology"]

    CT0 = encryptor.encrypt(message, AS)
    ac.store_ciphertext("record001", CT0)
    print("[Encryptor] Stored ciphertext for 'record001' with policy:", AS)

    # ---------- 6. User creates token; AC verifies ----------
    token = user.create_token()
    ok = ac.verify_token(user_id, token["PSK_IDi"], token["ID_i"])
    print("[AC] Token verified:", ok)

    if not ok:
        print("Access denied.")
        return

    # ---------- 7. AC performs partial decrypt ----------
    C, CTX = ac.partial_decrypt("record001", SK)
    print("[AC] Partial decrypt completed, C =", C)

    # ---------- 8. User final decrypts and verifies ----------
    recovered = user.final_decrypt(C, CTX)
    print("[User] Final decrypted message:", recovered.decode("utf-8"))

    print("\n=== DEMO COMPLETE ===\n")


if __name__ == "__main__":
    main()
