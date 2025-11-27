

from charm.toolbox.pairinggroup import ZR

def _hash_to_ZR(self, data):
    """
    Safely hash arbitrary data (bytes or group element) into ZR.
    """
    if isinstance(data, bytes):
        raw = data
    else:
        raw = self.group.serialize(data)
    return self.group.hash(raw, ZR)
