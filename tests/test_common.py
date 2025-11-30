

from cpabe.flawed.scheme import CollusionFlawedCPABE

def run_flawed():
    scheme = CollusionFlawedCPABE()
    pk, mk = scheme.setup()

    policy = ["Physician", "CardiologyDept", "CriticalCareAccess"]

    with open("input.csv", "rb") as f:
        message = f.read()

    # User A (missing 1 policy attribute)
    userA = {
        "Physician",
        "ICU",
        "Level1Access"
    }

    # User B (missing a different policy attribute)
    userB = {
        "CardiologyDept",
        "CriticalCareAccess",
        "Nurse"
    }

    skA = scheme.keygen(pk, mk, b"userA", list(userA))
    skB = scheme.keygen(pk, mk, b"userB", list(userB))
    print("-----------Flawed Scheme------------")
    print("Policy:", policy)
    print("\nUser A attrs:", sorted(userA))
    print("User B attrs:", sorted(userB))
    print("User A ID:", skA["ID"])
    print("User B ID:", skB["ID"])

    print("\nToken A:", scheme.verify_token(pk, skA), "(valid key issued by AA)")
    print("Token B:", scheme.verify_token(pk, skB), "(valid key issued by AA)")

    ct = scheme.encrypt(pk, message, policy)

    # -----------------------------------------------------
    # A ALONE
    # -----------------------------------------------------
    print("\n--- A alone decryption attempt ---")
    print("Reason: A is missing 'CardiologyDept' → policy incomplete.")
    print("FLAWED scheme checks only attribute presence. A does NOT have all.")
    try:
        C_A, ct2 = scheme.partial_decrypt(pk, ct, skA)
        out = scheme.final_decrypt(pk, skA, C_A, ct2)
        print("UNEXPECTED SUCCESS:", out[:50])
    except Exception as e:
        print("FAIL:", e)

    # -----------------------------------------------------
    # B ALONE
    # -----------------------------------------------------
    print("\n--- B alone decryption attempt ---")
    print("Reason: B is missing 'Physician' → policy still incomplete.")
    try:
        C_B, ct2 = scheme.partial_decrypt(pk, ct, skB)
        out = scheme.final_decrypt(pk, skB, C_B, ct2)
        print("UNEXPECTED SUCCESS:", out[:50])
    except Exception as e:
        
        print("FAIL:", e)

    # -----------------------------------------------------
    # COLLUSION
    # -----------------------------------------------------
    print("\n--- A + B collusion attempt ---")
    print("Reason: In FLAWED scheme, QID[attr] = g^(w[attr]) is SAME for all users.")
    print("        No identity binding. A and B can POOL attributes:")
    print("        A∪B covers all required policy attributes,")
    print("        so they reconstruct correct G = Π QID[attr].")
    print("        This lets them compute correct KEY → decryption SUCCESS.")

    colluders = {
        "QID": {**skA["QID"], **skB["QID"]},     # pooled attributes
        "attrs": skA["attrs"] | skB["attrs"],   # combined set
        "ID": skA["ID"],                        # identity irrelevant in flawed scheme
        "QID_i": skA["QID_i"],
        "PSK_i": skA["PSK_i"],
    }

    try:
        C_C, ct2 = scheme.partial_decrypt(pk, ct, colluders)
        out = scheme.final_decrypt(pk, colluders, C_C, ct2)
        print_table_format(out)
    except Exception as e:
        print("COLLUSION FAIL:", e)




from cpabe.fixed.scheme import SensorsCPABEFixedIDBound

def run_fixed():
    scheme = SensorsCPABEFixedIDBound()
    pk, mk = scheme.setup()

    policy = ["Physician", "CardiologyDept", "CriticalCareAccess"]

    with open("input.csv", "rb") as f:
        message = f.read()

    # User A (missing 1 policy attribute)
    userA = {
        "Physician",
        "ICU",
        "Level1Access"
    }

    # User B (missing a different policy attribute)
    userB = {
        "CardiologyDept",
        "CriticalCareAccess",
        "Nurse"
    }

    skA = scheme.keygen(pk, mk, b"userA", list(userA))
    skB = scheme.keygen(pk, mk, b"userB", list(userB))
    print("---------FIXED SCHEME----------")
    print("Policy:", policy)
    print("User A attrs:", sorted(userA))
    print("User B attrs:", sorted(userB))
    print("User A ID:", skA["ID"])
    print("User B ID:", skB["ID"])
    print("h(A):", skA["h_i"])
    print("h(B):", skB["h_i"])

    print("\nToken check A:", scheme.verify_token(pk, skA), "(valid key issued by AA)")
    print("Token check B:", scheme.verify_token(pk, skB), "(valid key issued by AA)")

    ct = scheme.encrypt(pk, message, policy)

    # A alone
    print("\n--- A alone decryption attempt ---")
    print("Reason: A is missing 'CardiologyDept' AND h(A) must match all Dj* exponents")
    try:
        C_A, ct2 = scheme.partial_decrypt(pk, ct, skA)
        out = scheme.final_decrypt(pk, skA, C_A, ct2)
        print("UNEXPECTED SUCCESS:", out[:50])
    except Exception as e:
        print("FAIL:", e)

    # B alone
    print("\n--- B alone decryption attempt ---")
    print("Reason: B is missing 'Physician' AND h(B) is different from required identity exponent")
    try:
        C_B, ct2 = scheme.partial_decrypt(pk, ct, skB)
        out = scheme.final_decrypt(pk, skB, C_B, ct2)
        print("UNEXPECTED SUCCESS:", out[:50])
    except Exception as e:
        print("FAIL:", e)

    # Collusion attempt
    print("\n--- A + B collusion attempt ---")
    print("Reason: Even though A∪B covers all attributes,")
    print("        h(A) ≠ h(B), so Dj* exponents cannot combine into a valid single identity.")
    print("        Therefore they cannot rebuild correct KEY → VK check fails.")
    
    colluders = {
        "ID": skA["ID"],           # Attempt to impersonate A
        "h_i": skA["h_i"],         # But combining Dj* from A and B breaks identity math
        "D_prime_star": skA["D_prime_star"],
        "Dj_star": {**skA["Dj_star"], **skB["Dj_star"]},
        "attrs": skA["attrs"] | skB["attrs"],
        "QID_i": skA["QID_i"],
        "PSK_i": skA["PSK_i"],
    }

    try:
        C_C, ct2 = scheme.partial_decrypt(pk, ct, colluders)
        out = scheme.final_decrypt(pk, colluders, C_C, ct2)
        print("UNEXPECTED SUCCESS:", out[:80])
    except Exception as e:
        print("COLLUSION FAIL:", e)

def print_table_format(out):
    decoded = out.decode("utf-8", errors="ignore")
    lines = decoded.strip().split("\n")

    # print header
    header = [p.strip() for p in lines[0].split(",")]
    print(" | ".join(header))
    print("-" * 88)

    # print first 3 rows (we only have 3 anyway)
    for line in lines[1:4]:
        row = [p.strip() for p in line.split(",")]
        print(" | ".join(row))

if __name__ == "__main__":
    run_flawed()
    run_fixed()
