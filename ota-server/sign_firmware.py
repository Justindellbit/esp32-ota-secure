#!/usr/bin/env python3
"""
sign_firmware.py
Usage: python3 sign_firmware.py firmware.bin
Produit: firmware.bin.sig (signature ECDSA P-256 / SHA-256)
"""

import sys
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SIGNING_KEY = os.path.join(os.path.dirname(__file__), "pki/signing.key")

def sign(fw_path):
    if not os.path.exists(fw_path):
        print(f"[ERR] fichier introuvable: {fw_path}")
        sys.exit(1)

    # charger clé privée
    with open(SIGNING_KEY, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # lire firmware
    with open(fw_path, "rb") as f:
        fw_data = f.read()

    # signer SHA-256 + ECDSA
    signature = private_key.sign(fw_data, ec.ECDSA(hashes.SHA256()))

    # écrire .sig
    sig_path = fw_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"[OK] firmware : {fw_path} ({len(fw_data)} bytes)")
    print(f"[OK] signature: {sig_path} ({len(signature)} bytes)")
    print(f"[OK] algo     : ECDSA P-256 / SHA-256")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 sign_firmware.py <firmware.bin>")
        sys.exit(1)
    sign(sys.argv[1])
