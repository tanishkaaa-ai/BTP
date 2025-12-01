from cpabe.flawed.scheme import CollusionFlawedCPABE
from cpabe.fixed.scheme import SensorsCPABEFixedIDBound


# ===============================
# Helper: print decrypted data in table form
# ===============================
def print_table_format(out):
    decoded = out.decode("utf-8", errors="ignore")
    lines = decoded.strip().split("\n")

    header = [p.strip() for p in lines[0].split(",")]
    print(" | ".join(header))
    print("-" * 88)

    for line in lines[1:4]:
        row = [p.strip() for p in line.split(",")]
        print(" | ".join(row))


# ===============================
# Read input for N users
# ===============================
def get_users():
    users = {}
    n = int(input("\nEnter number of users: "))

    for i in range(n):
        print(f"\n--- User {i+1} ---")
        uid = input("Enter user ID (string): ").encode()

        attrs_raw = input("Enter attributes (comma-separated): ")
        attrs = [a.strip() for a in attrs_raw.split(",") if a.strip()]

        users[uid] = set(attrs)

    return users


# ===============================
# Main Runner
# ===============================
def run_test():
    print("\nChoose scheme:")
    print("1. Flawed Scheme")
    print("2. Fixed Scheme")
    choice = int(input("Enter choice (1/2): "))

    if choice == 1:
        scheme = CollusionFlawedCPABE()
        print("\nRunning Flawed CP-ABE Scheme...")
    else:
        scheme = SensorsCPABEFixedIDBound()
        print("\nRunning Fixed CP-ABE Scheme...")

    pk, mk = scheme.setup()

    # Read policy
    policy_raw = input("\nEnter access policy (comma-separated attributes): ")
    policy = [p.strip() for p in policy_raw.split(",") if p.strip()]
    print("Policy =", policy)

    # Read users dynamically
    users = get_users()

    # Read input file
    file_name = input("\nEnter input CSV filename (default: input.csv): ").strip()
    if file_name == "":
        file_name = "input.csv"

    with open(file_name, "rb") as f:
        message = f.read()

    # generate keys
    sks = {}
    for uid, attrs in users.items():
        sks[uid] = scheme.keygen(pk, mk, uid, list(attrs))

    ct = scheme.encrypt(pk, message, policy)

    print("\n=========== Testing Decryption for Each User ===========")
    for uid, SK in sks.items():
        print(f"\n--- User {uid.decode()} ---")
        print("Attributes:", SK["attrs"])

        try:
            C, ct2 = scheme.partial_decrypt(pk, ct, SK)
            out = scheme.final_decrypt(pk, SK, C, ct2)
            print("DECRYPT SUCCESS → Showing table output:")
            print_table_format(out)
        except Exception as e:
            print("DECRYPT FAIL:", e)

    # Collusion test
    print("\n========== COLLUSION TEST ==========")
    all_attrs = set()
    colluder_SK = {}

    for uid, SK in sks.items():
        all_attrs |= SK["attrs"]

    # NOTE: we only merge components common to both schemes
    any_uid = list(sks.keys())[0]
    base = sks[any_uid]

    colluders = {
        "attrs": all_attrs,
        "ID": base.get("ID"),
        "QID_i": base.get("QID_i"),
        "PSK_i": base.get("PSK_i"),
    }

    # scheme-specific merging
    if choice == 1:
        # flawed scheme merging
        merged_QID = {}
        for SK in sks.values():
            merged_QID.update(SK["QID"])
        colluders["QID"] = merged_QID

    else:
        # fixed scheme merging
        merged_D = {}
        for SK in sks.values():
            merged_D.update(SK["Dj_star"])
        colluders["Dj_star"] = merged_D
        colluders["D_prime_star"] = base["D_prime_star"]
        colluders["h_i"] = base["h_i"]

    try:
        C, ct2 = scheme.partial_decrypt(pk, ct, colluders)
        out = scheme.final_decrypt(pk, colluders, C, ct2)
        print("\nCOLLUSION SUCCESS → showing decrypted output:")
        print_table_format(out)
    except Exception as e:
        print("\nCOLLUSION FAIL:", e)


# ===============================
# MAIN
# ===============================
if __name__ == "__main__":
    run_test()
