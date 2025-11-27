# ============================================================
# KeyGen  (Flawed per-attribute scheme + traceability)
# ============================================================

from charm.toolbox.pairinggroup import ZR 
def keygen(self, pk, user_attrs, user_id_bytes=None):
    """
    KeyGen(pk, user_attrs, user_id_bytes=None) -> sk

    FLAWED attribute side:
      For each attribute a ∈ user_attrs:
        if w[a] not set:
           w[a] randomly in Z_p
        QID[a] = g^{w[a]}

      No per-user randomness here, only per-attribute weight.
      QID[a] is the same for any user who has attribute a.

    This is the essence of the collusion flaw: attribute powers
    can be pooled between users.

    Traceability side:
      We also create an identity ID_i (user_id_bytes), if not provided
      we derive one from the attribute list:

          ID_i = b"user|" + sorted(attribute names)...

      Then:
          d_i   ← random in Z_p
          QID_i = d_i · P
          h2    = H2(ID_i, QID_i) ∈ Z_p
          PSK_i = d_i + h2 · α

    Output:
      sk = {
        'QID':   {attr: g^{w[attr]}},
        'attrs': set(user_attrs),
        'ID':    ID_i,
        'QID_i': QID_i,
        'PSK_i': PSK_i
      }
    """
    if self.mk is None:
        raise Exception("Run setup() first so self.mk is initialized.")

    g = pk["g"]
    w_map = self.mk["w"]
    alpha = self.mk["alpha"]
    P = pk["P"]

    # 1) Per-attribute flawed part: QID[a] = g^{w[a]}
    QID = {}
    for attr in user_attrs:
        if attr not in w_map:
            w_map[attr] = self.group.random(ZR)
        QID[attr] = g ** w_map[attr]

    # 2) Identity for this user: either provided or derived
    if user_id_bytes is None:
        # Derive a pseudo-identity from sorted attributes
        sorted_attrs = sorted(list(user_attrs))
        user_id_bytes = b"user|" + "|".join(sorted_attrs).encode("utf-8")

    # 3) Traceability: QID_i, PSK_i
    # Choose per-user randomness d_i
    d_i = self.group.random(ZR)

    # QID_i = d_i * P
    QID_i = d_i * P

    # h2 = H2(ID_i, QID_i)
    h2_input = user_id_bytes + self.group.serialize(QID_i)
    h2_val = self.group.hash(h2_input, ZR)

    # PSK_i = d_i + h2 * alpha
    PSK_i = d_i + h2_val * alpha

    # Combine into SK
    sk = {
        "QID": QID,  # per-attribute components
        "attrs": set(user_attrs),  # attribute set
        "ID": user_id_bytes,  # identity bytes
        "QID_i": QID_i,  # traceability tag
        "PSK_i": PSK_i,  # pseudo secret key
    }
    return sk
