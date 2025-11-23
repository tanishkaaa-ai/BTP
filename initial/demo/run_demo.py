from authorities.AA import AttributeAuthority
from authorities.TA import TraceAuthority
from servers.ACServer import ACServer
from Client.User import UserClient
from crypto.Encrypt import Encryptor


def main():
    print("\n=== CP-ABE IoMT Full Demo Running ===")

    # -------------------- Authorities --------------------
    U = ["Doctor", "Nurse", "Cardiology"]
    aa = AttributeAuthority(U)
    aa.setup_trace_public()

    ta = TraceAuthority()
    ac = ACServer(aa)

    # -------------------- User Registration --------------------
    RID = "RealUserID123"
    ID_i = ta.register(RID, "Tanisha", "2025")
    print("[TA] Anonymous ID_i =", ID_i)

    user_attrs = ["Doctor", "Cardiology"]
    SK = aa.keygen_with_trace(ID_i, user_attrs)

    # AC server also stores KEY traceability (ID_i, QID_i)
    ac.register_user_from_aa("user1", ID_i, SK["QID_i"])
    print("[AA] Secret key issued with attributes", user_attrs)

    # -------------------- User Client --------------------
    user = UserClient("user1", ID_i, SK, aa)

    # -------------------- Encrypt medical data --------------------
    encryptor = Encryptor(aa.PK)
    message = b"Patient ECG: Normal Sinus Rhythm."
    AS = ["Doctor", "Cardiology"]

    CT0 = encryptor.encrypt(message, AS)
    ac.store_ciphertext("record001", CT0)
    print("[Encryptor] Ciphertext stored in cloud as record001")

    # -------------------- User token --------------------
    token = user.create_token()
    ok = ac.verify_token("user1", token["PSK_IDi"], token["ID_i"])
    print("[AC] Token verified:", ok)

    if not ok:
        print("Access denied.")
        return

    # -------------------- AC Partial Decrypt --------------------
    C, CTX = ac.partial_decrypt("record001", SK)
    print("[AC] Partial decrypt C computed")

    # -------------------- Final Decrypt --------------------
    M = user.final_decrypt(C, CTX)
    print("[User] Final decrypted message:", M.decode())
    print("\n=== DEMO COMPLETE ===")


if __name__ == "__main__":
    main()
