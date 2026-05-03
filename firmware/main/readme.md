 
 # ESP32 OTA Secure

Système de mise à jour firmware sécurisé pour ESP32 avec :
- Vérification de signature ECDSA P-256 avant flash
- Transport HTTPS TLS
- Dashboard de monitoring fleet en temps réel
- Partitions ota_0/ota_1 avec rollback automatique

## Stack technique

| Composant | Technologie |
|---|---|
| Firmware | ESP-IDF v6.1, C |
| Crypto | mbedTLS 4.x, ECDSA P-256 |
| Serveur | Python 3, Flask |
| Dashboard | HTML/JS vanilla |
| Transport | HTTPS auto-signé |

 ## Configuration

 ## *Setup rapide

### Raspberry Pi

```bash
# Dépendances
sudo apt install python3-venv openssl
python3 -m venv venv && source venv/bin/activate
pip install flask cryptography

# Générer les clés
mkdir pki certs
openssl ecparam -name prime256v1 -genkey -noout -out pki/signing.key
openssl ec -in pki/signing.key -pubout -out pki/signing.pub
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key \
  -out certs/server.crt

# Lancer le serveur
python3 server.py
```

### ESP32

```bash
# Prérequis: ESP-IDF v5.0+
# Copier server.crt et signing.pub dans main/certs/

# exporter les variable d'environnement de esp-idf dans power shell
 
cd D:\espressif\esp-idf> 
.\install.ps1
Puis retour dans le dossier de projet
idf.py set-target esp32
idf.py build
idf.py -p PORT flash monitor
```

### Déployer une mise à jour

```bash
# Compiler nouveau firmware (PC)
idf.py build
scp build/OTA.bin USER@PI_IP:~/ota-server/firmware/fw_X.X.X.bin

# Signer (coté Pi)
python3 sign_firmware.py firmware/fw_X.X.X.bin

# Mettre à jour CURRENT_VERSION dans server.py
# Redémarrer server.py
```

## Sécurité

- La clé privée `pki/signing.key` ne doit jamais être commitée
- Le `.gitignore` l'exclut automatiquement
- Sans la clé privée, aucun firmware falsifié ne peut être accepté par l'ESP32
- Le certificat TLS est auto-signé et embarqué dans le firmware

## Ce projet ne couvre pas

- Secure Boot V2 hardware (eFuses ESP32) (Elle a ete simulé pour eviter d'endommager la carte)
- Anti-rollback par numéro de version en flash
- HSM pour stockage clé privée en production
- OTA sur réseau non fiable sans VPN

## Supplement

 

# Vérifie ce que le script a signé exactement directemment en ligne de commande
python3 -c "
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# relit clé privée
with open('pki/signing.key', 'rb') as f:
    key = serialization.load_pem_private_key(f.read(), password=None)

# relit firmware
with open('firmware/fw_1.1.0.bin', 'rb') as f:
    fw = f.read()

print(f'firmware size: {len(fw)} bytes')

# signe
sig = key.sign(fw, ec.ECDSA(hashes.SHA256()))
print(f'signature size: {len(sig)} bytes')

# vérifie immédiatement avec clé publique
pub = key.public_key()
try:
    pub.verify(sig, fw, ec.ECDSA(hashes.SHA256()))
    print('verification: OK')
except Exception as e:
    print(f'verification: FAIL — {e}')

# écrase le .sig
with open('firmware/fw_1.1.0.bin.sig', 'wb') as f:
    f.write(sig)
print('signature écrite')
"

# Check
openssl dgst -sha256 \
  -verify pki/signing.pub \
  -signature firmware/fw_1.1.0.bin.sig \
