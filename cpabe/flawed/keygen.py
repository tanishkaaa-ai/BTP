# cpabe/flawed/keygen.py

from charm.toolbox.pairinggroup import ZR

def keygen(group, pk, mk, user_attrs, user_id_bytes=None):
    """
    Flawed KeyGen WITH traceability:
      - Per-attribute QID[a] = g^{w[a]}
      - Traceability: QID_i = d_i * P,  PSK_i = d_i + h2*alpha
    """

    if mk is None:
        raise Exception("Run setup() first so mk exists.")

    g = pk["g"]
    P = pk["P"]
    alpha = mk["alpha"]          # ONLY used for traceability
    w_map = mk["w"]

    # -------- per-attribute part (flawed) --------
    QID = {}
    for attr in user_attrs:
        if attr not in w_map:
            w_map[attr] = group.random(ZR)
        QID[attr] = g ** w_map[attr]

    # -------- derive ID --------
    if user_id_bytes is None:
        sorted_attrs = sorted(list(user_attrs))
        user_id_bytes = b"user|" + "|".join(sorted_attrs).encode()

    # -------- traceability --------
    d_i = group.random(ZR)
    QID_i = d_i * P

    h2_input = user_id_bytes + group.serialize(QID_i)
    h2_val = group.hash(h2_input, ZR)

    PSK_i = d_i + h2_val * alpha

    return {
        "QID": QID,
        "attrs": set(user_attrs),
        "ID": user_id_bytes,
        "QID_i": QID_i,
        "PSK_i": PSK_i
    }