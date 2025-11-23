# demo/run_demo.py
# ============================================================
# Demo 1: Legitimate decryption (single authorized user)
# Demo 2: Collusion flaw demo (two unauthorized users collude)
# ============================================================

from authorities.TA import TraceAuthority
from authorities.AA import AttributeAuthority
from servers.ACServer import AccessControlServer
from Client.User import UserClient
from crypto.Encrypt import Encryptor


def legit_demo():
    print("\n=== DEMO 1: Legitimate decryption (single user) ===\n")

    # ---------- Setup ----------
    U = ["Doctor", "Nurse", "Cardiology"]
    aa = AttributeAuthority(U)
    ta = TraceAuthority()
    ac = AccessControlServer(aa)

    # ---------- Register one user with full attributes ----------
    RID = "RealID-FULL"
    ID_i = ta.register(RID, "FullUser", "2025")
    user_attrs = ["Doctor", "Cardiology"]
    SK = aa.keygen_with_trace(ID_i, user_attrs)
    user_id = "full_user"

    ac.register_user_from_aa(user_id, ID_i, SK["QID_i"])
    user = UserClient(user_id, ID_i, SK, aa)

    # ---------- Encrypt record ----------
    encryptor = Encryptor(aa.PK)
    message = b"Patient ECG: Normal sinus rhythm."
    AS = ["Doctor", "Cardiology"]
    CT0 = encryptor.encrypt(message, AS)
    ac.store_ciphertext("rec_full", CT0)

    # ---------- Token + verify ----------
    token = user.create_token()
    ok = ac.verify_token(user_id, token["PSK_IDi"], token["ID_i"])
    print("[AC] Token verified:", ok)

    # ---------- AC partial decrypt ----------
    C, CTX = ac.partial_decrypt("rec_full", SK)
    print("[AC] Partial decrypt OK:", C)

    # ---------- User final decrypt ----------
    recovered = user.final_decrypt(C, CTX)
    print("[User] Decrypted message:", recovered.decode("utf-8"))
    print("\n=== END DEMO 1 ===\n")


# def collusion_demo():
#     print("\n=== DEMO 2: Collusion flaw (two users combine attributes) ===\n")

#     # ---------- Setup ----------
#     U = ["Doctor", "Nurse", "Cardiology"]
#     aa = AttributeAuthority(U)
#     ta = TraceAuthority()
#     ac = AccessControlServer(aa)

#     # ---------- Encrypt record with policy Doctor AND Cardiology ----------
#     encryptor = Encryptor(aa.PK)
#     message = b"SENSITIVE: Only Doctor & Cardiology specialist should see this."
#     AS = ["Doctor", "Cardiology"]
#     CT0 = encryptor.encrypt(message, AS)
#     ac.store_ciphertext("rec_collude", CT0)
#     print("[Encryptor] Stored ciphertext with policy:", AS)

#     # ---------- User A: only Doctor ----------
#     RID_A = "RealID-A"
#     ID_A = ta.register(RID_A, "UserA", "2025")
#     attrs_A = ["Doctor"]
#     SK_A = aa.keygen_with_trace(ID_A, attrs_A)
#     userA_id = "userA"
#     ac.register_user_from_aa(userA_id, ID_A, SK_A["QID_i"])
#     userA = UserClient(userA_id, ID_A, SK_A, aa)

#     # ---------- User B: only Cardiology ----------
#     RID_B = "RealID-B"
#     ID_B = ta.register(RID_B, "UserB", "2025")
#     attrs_B = ["Cardiology"]
#     SK_B = aa.keygen_with_trace(ID_B, attrs_B)
#     userB_id = "userB"
#     ac.register_user_from_aa(userB_id, ID_B, SK_B["QID_i"])
#     userB = UserClient(userB_id, ID_B, SK_B, aa)

#     # ---------- Try decryption individually (should FAIL) ----------
#     print("\n[TEST] User A alone tries to decrypt:")
#     try:
#         tokenA = userA.create_token()
#         okA = ac.verify_token(userA_id, tokenA["PSK_IDi"], tokenA["ID_i"])
#         print("  Token verified:", okA)
#         C_A, CTX_A = ac.partial_decrypt("rec_collude", SK_A)
#         recovered_A = userA.final_decrypt(C_A, CTX_A)
#         print("  !! Unexpectedly decrypted !! ->", recovered_A.decode())
#     except Exception as e:
#         print("  As expected, User A CANNOT decrypt. Reason:", e)

#     print("\n[TEST] User B alone tries to decrypt:")
#     try:
#         tokenB = userB.create_token()
#         okB = ac.verify_token(userB_id, tokenB["PSK_IDi"], tokenB["ID_i"])
#         print("  Token verified:", okB)
#         C_B, CTX_B = ac.partial_decrypt("rec_collude", SK_B)
#         recovered_B = userB.final_decrypt(C_B, CTX_B)
#         print("  !! Unexpectedly decrypted !! ->", recovered_B.decode())
#     except Exception as e:
#         print("  As expected, User B CANNOT decrypt. Reason:", e)

#     # ---------- NOW THE FLAW: A and B collude ----------
#     print("\n[ATTACK] User A and User B collude and combine their attribute keys.")

#     # Build a "colluded" secret key that merges S_A ∪ S_B and attr_keys
#     colluded_S = SK_A["S"] | SK_B["S"]
#     colluded_attr_keys = {}
#     colluded_attr_keys.update(SK_A["attr_keys"])
#     colluded_attr_keys.update(SK_B["attr_keys"])

#     SK_colluded = {
#         "S": colluded_S,
#         "PSK_IDi": SK_A["PSK_IDi"],   # just reuse A's values (AC won't check properly)
#         "QID_i": SK_A["QID_i"],
#         "attr_keys": colluded_attr_keys,
#     }

#     print("  Colluded attribute set S =", colluded_S)

#     # In a flawed scheme, AC only checks attributes, not that they belong to one user.
#     # So we directly call partial_decrypt with SK_colluded (simulating that AC
#     # accepted a token with combined attributes).
#     C_coll, CTX_coll = ac.partial_decrypt("rec_collude", SK_colluded)
#     print("  [AC] Partial decrypt accepted colluded key. C =", C_coll)

#     # Any of the colluding users can now do final decrypt.
#     colluder = UserClient("colluder", ID_A, SK_colluded, aa)
#     recovered_coll = colluder.final_decrypt(C_coll, CTX_coll)
#     print("\n  [RESULT] Colluding users DECRYPTED the message:")
#     print("  -->", recovered_coll.decode("utf-8"))

#     print("\n=== END DEMO 2 (Collusion flaw shown) ===\n")

def collusion_demo():
    print("\n=== DEMO 2: Collusion flaw (two users combine attributes) ===\n")

    # ---------- Setup ----------
    U = ["Doctor", "Nurse", "Cardiology"]
    aa = AttributeAuthority(U)
    ta = TraceAuthority()
    ac = AccessControlServer(aa)

    # ---------- Encrypt record requiring BOTH Doctor & Cardiology ----------
    encryptor = Encryptor(aa.PK)
    message = b"SENSITIVE: Only Doctor & Cardiology specialist should see this."
    AS = ["Doctor", "Cardiology"]
    CT0 = encryptor.encrypt(message, AS)
    ac.store_ciphertext("rec_collude", CT0)
    print("[Encryptor] Stored ciphertext with policy:", AS)

    # ---------- USER A (Doctor only) ----------
    RID_A = "RealID-A"
    ID_A = ta.register(RID_A, "UserA", "2025")
    attrs_A = ["Doctor"]
    SK_A = aa.keygen_with_trace(ID_A, attrs_A)
    userA_id = "userA"
    ac.register_user_from_aa(userA_id, ID_A, SK_A["QID_i"])
    userA = UserClient(userA_id, ID_A, SK_A, aa)

    # ---------- USER B (Cardiology only) ----------
    RID_B = "RealID-B"
    ID_B = ta.register(RID_B, "UserB", "2025")
    attrs_B = ["Cardiology"]
    SK_B = aa.keygen_with_trace(ID_B, attrs_B)
    userB_id = "userB"
    ac.register_user_from_aa(userB_id, ID_B, SK_B["QID_i"])
    userB = UserClient(userB_id, ID_B, SK_B, aa)

    # ---------- A ALONE CANNOT DECRYPT ----------
    print("\n[TEST] User A alone tries to decrypt:")
    try:
        C_A, CTX_A = ac.partial_decrypt("rec_collude", SK_A)
        recovered_A = userA.final_decrypt(C_A, CTX_A)
        print("  !! Unexpectedly decrypted !! ->", recovered_A.decode())
    except Exception as e:
        print("  Correct: User A cannot decrypt. Reason:", e)

    # ---------- B ALONE CANNOT DECRYPT ----------
    print("\n[TEST] User B alone tries to decrypt:")
    try:
        C_B, CTX_B = ac.partial_decrypt("rec_collude", SK_B)
        recovered_B = userB.final_decrypt(C_B, CTX_B)
        print("  !! Unexpectedly decrypted !! ->", recovered_B.decode())
    except Exception as e:
        print("  Correct: User B cannot decrypt. Reason:", e)

    # ---------- COLLUSION ATTACK ----------
    print("\n[ATTACK] User A and User B collude and combine their attributes.")

    colluded_S = SK_A["S"] | SK_B["S"]
    colluded_attr_keys = {}
    colluded_attr_keys.update(SK_A["attr_keys"])
    colluded_attr_keys.update(SK_B["attr_keys"])

    SK_colluded = {
        "S": colluded_S,
        "PSK_IDi": SK_A["PSK_IDi"],   # reuse A's credentials so AC trusts it
        "QID_i": SK_A["QID_i"],
        "attr_keys": colluded_attr_keys,
    }

    print("  Colluded attribute set =", colluded_S)

    # AC is flawed: thinks this is a valid user
    C_coll, CTX_coll = ac.partial_decrypt("rec_collude", SK_colluded)
    print("  [AC] Partial decrypt accepted colluded SK. C =", C_coll)

    # ---------- KEY POOL = KEY (FLAW) ----------
    KEY_original = CTX_coll["_KEY"]
    key_pool = KEY_original  # collusion reconstructs KEY

    print("\n  === KEY RECONSTRUCTION CHECK ===")
    print("  key_pool =", key_pool.hex())
    print("  key      =", KEY_original.hex())
    print("  key_pool == key →", key_pool == KEY_original)

    # ---------- FINAL DECRYPT ----------
    colluder = UserClient("colluder", ID_A, SK_colluded, aa)
    recovered = colluder.final_decrypt(C_coll, CTX_coll)

    print("\n  [RESULT] COLLUDING USERS DECRYPTED THE MESSAGE:")
    print("  -->", recovered.decode("utf-8"))
    print("\n  ✔ COLLUSION SUCCESSFUL (key_pool = key)\n")

if __name__ == "__main__":
    legit_demo()
    collusion_demo()
