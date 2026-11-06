#!/bin/sh
# Generate test fixtures: a throwaway CA + leaf cert, and a minimal PE
# carrying a REAL PKCS#7 signature (openssl cms) whose eContent embeds the
# PE's own Authenticode hash - so efi_sig_verify() can be tested end to end.
set -e
D=tests/fixtures
mkdir -p "$D"

# 1. throwaway CA + leaf
openssl req -x509 -newkey rsa:2048 -keyout "$D/ca.key" -out "$D/ca.crt" \
    -days 3650 -nodes -subj "/CN=GenPE Test UEFI CA 2023/" 2>/dev/null
openssl req -newkey rsa:2048 -keyout "$D/leaf.key" -out "$D/leaf.csr" \
    -nodes -subj "/CN=GenPE Test Boot Loader/" 2>/dev/null
openssl x509 -req -in "$D/leaf.csr" -CA "$D/ca.crt" -CAkey "$D/ca.key" \
    -CAcreateserial -out "$D/leaf.crt" -days 3650 -sha256 2>/dev/null
openssl x509 -in "$D/ca.crt"   -outform DER -out "$D/ca.der"
openssl x509 -in "$D/leaf.crt" -outform DER -out "$D/leaf.der"

python3 - <<'PYEOF'
import hashlib, struct, subprocess, os

D = "tests/fixtures"

# 2. minimal PE32+ image (MZ + PE + optional header, no sections)
pe = bytearray(0x200)
pe[0:2] = b"MZ"
struct.pack_into("<I", pe, 0x3c, 0x80)
pe[0x80:0x84] = b"PE\0\0"
# COFF: machine x64, 0 sections, opt hdr 240 bytes
struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 0, 0, 0, 0, 240, 0x22)
opt = 0x98
struct.pack_into("<H", pe, opt, 0x20b)                 # PE32+ magic
# data dirs start at opt+112; security dir = idx4 -> opt+144
secdir = opt + 144
struct.pack_into("<I", pe, secdir, len(pe))            # va = EOF (patched later anyway)

# 3. Authenticode hash over the image excluding checksum, secdir entry, cert tbl
def authcode(img, secva, secsz):
    eoff = 0x80; dd = eoff + 24 + 112; cksum = eoff + 24 + 64
    h = hashlib.sha256()
    hend = len(img) - secsz
    h.update(img[:cksum])
    h.update(img[cksum+4:dd+32])
    h.update(img[dd+40:hend])
    return h.digest()

# secdir fields are excluded from the hash; secsz is filled after signing
digest = authcode(bytes(pe), len(pe), 0)

# 4. eContent = DigestInfo { SEQ{oid sha256}, OCTET STRING hash }
oid_sha256 = bytes.fromhex("06096086480165030402010500")
content = bytes([0x30, len(oid_sha256)+2+34]) + oid_sha256 + \
          bytes([0x04, 0x20]) + digest
open(D + "/content.bin", "wb").write(content)

# 5. real CMS signature over it
subprocess.run(["openssl", "cms", "-sign", "-binary",
    "-in", D + "/content.bin",
    "-signer", D + "/leaf.crt", "-inkey", D + "/leaf.key",
    "-certfile", D + "/ca.crt",
    "-outform", "DER", "-out", D + "/sig.p7",
    "-nodetach", "-nosmimecap", "-md", "sha256"], check=True)
p7 = open(D + "/sig.p7", "rb").read()

# 6. WIN_CERTIFICATE table appended to the PE
tbl = struct.pack("<IHH", 8 + len(p7), 0x0200, 0x0002) + p7
pad = (-len(tbl)) % 8
tbl += b"\0" * pad
struct.pack_into("<II", pe, secdir, len(pe), len(tbl))
signed = bytes(pe) + tbl
open(D + "/signed_pe.bin", "wb").write(signed)

# tampered variants
t = bytearray(signed); t[0x60] ^= 0xff            # corrupt image body
open(D + "/tampered_pe.bin", "wb").write(bytes(t))
t = bytearray(signed); t[-40] ^= 0xff            # corrupt RSA signature bytes
open(D + "/badsig_pe.bin", "wb").write(bytes(t))
print("fixtures: signed_pe.bin=%d bytes, p7=%d" % (len(signed), len(p7)))
PYEOF
