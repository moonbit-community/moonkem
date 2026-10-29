"""Independent SHA-3/SHAKE reference vectors used by src/hash_kat_test.mbt."""
import hashlib

for label, message in [("empty", b""), ("abc", b"abc"), ("multiblock", bytes(range(200)))]:
    for name in ["sha3_256", "sha3_512", "shake_128", "shake_256"]:
        digest = getattr(hashlib, name)(message)
        output = digest.digest(200) if name.startswith("shake") else digest.digest()
        print(label, name, list(output))
