import os
import base64
import struct
import string
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# =========================================================
# صيغة ملف مشفر خاصة بالبرنامج:
# MAGIC + VERSION + ALG + SALT + IV + MAC + ORIGINAL_NAME + PAYLOAD
# الهدف: لما أفك تشفير ملف يرجع بنفس الاسم والامتداد ويشتغل طبيعي
# =========================================================
MAGIC = b"CSYS"
VERSION = 1

ALG_3DES = 1
ALG_VIGENERE = 2


class CryptoUtils:
    # ------------------ Padding for 3DES CBC ------------------
    @staticmethod
    def pkcs7_pad(data: bytes, block_size: int) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len]) * pad_len

    @staticmethod
    def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
        if not data or len(data) % block_size != 0:
            raise ValueError("Padding غير صحيح")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("Padding غير صحيح")
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Padding غير صحيح")
        return data[:-pad_len]

    # ------------------ Generate Keys ------------------
    @staticmethod
    def generate_3des_key() -> bytes:
        return os.urandom(24)

    @staticmethod
    def generate_vigenere_key(length: int = 16) -> str:
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(length))

    # ------------------ Detect / Parse Key ------------------
    @staticmethod
    def looks_like_base64(s: str) -> bool:
        s = (s or "").strip()
        if len(s) < 8:
            return False
        allowed = set(string.ascii_letters + string.digits + "+/=\n\r")
        return all(c in allowed for c in s)

    @staticmethod
    def parse_key_input(key_text: str):
        """
        إذا المستخدم لصق مفتاح Base64 طوله 24 bytes -> raw
        غير كذا -> اعتبره كلمة مرور
        """
        key_text = (key_text or "").strip()
        if not key_text:
            raise ValueError("المفتاح فارغ")

        if CryptoUtils.looks_like_base64(key_text):
            try:
                raw = base64.b64decode(key_text, validate=True)
                if len(raw) == 24:
                    return "raw", raw
            except Exception:
                pass

        return "password", key_text.encode("utf-8")

    # ------------------ KDF (PBKDF2) ------------------
    @staticmethod
    def kdf_password(password_bytes: bytes, salt: bytes, length: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=200_000,
            backend=default_backend(),
        )
        return kdf.derive(password_bytes)

    # ------------------ Header Build / Parse ------------------
    @staticmethod
    def build_header(alg_id: int, salt: bytes, iv: bytes, mac: bytes, original_name: str, payload_len: int) -> bytes:
        name_bytes = original_name.encode("utf-8", errors="replace")
        if len(name_bytes) > 65535:
            name_bytes = name_bytes[:65535]

        header = b""
        header += MAGIC
        header += struct.pack("!B", VERSION)
        header += struct.pack("!B", alg_id)
        header += struct.pack("!B", len(salt))
        header += struct.pack("!B", len(iv))
        header += struct.pack("!H", len(mac))
        header += salt
        header += iv
        header += mac
        header += struct.pack("!H", len(name_bytes))
        header += name_bytes
        header += struct.pack("!I", payload_len)
        return header

    @staticmethod
    def parse_header(blob: bytes) -> dict:
        idx = 0
        if len(blob) < 4 + 1 + 1 + 1 + 1 + 2:
            raise ValueError("ملف غير صالح")

        if blob[idx:idx+4] != MAGIC:
            raise ValueError("هذا الملف ليس من صيغة البرنامج")
        idx += 4

        ver = blob[idx]
        idx += 1
        if ver != VERSION:
            raise ValueError("إصدار غير مدعوم")

        alg_id = blob[idx]
        idx += 1

        salt_len = blob[idx]
        idx += 1
        iv_len = blob[idx]
        idx += 1

        mac_len = struct.unpack("!H", blob[idx:idx+2])[0]
        idx += 2

        if len(blob) < idx + salt_len + iv_len + mac_len + 2 + 4:
            raise ValueError("ملف ناقص أو تالف")

        salt = blob[idx:idx+salt_len]
        idx += salt_len
        iv = blob[idx:idx+iv_len]
        idx += iv_len
        mac = blob[idx:idx+mac_len]
        idx += mac_len

        name_len = struct.unpack("!H", blob[idx:idx+2])[0]
        idx += 2

        if len(blob) < idx + name_len + 4:
            raise ValueError("ملف ناقص أو تالف")

        name = blob[idx:idx+name_len].decode("utf-8", errors="replace")
        idx += name_len

        payload_len = struct.unpack("!I", blob[idx:idx+4])[0]
        idx += 4

        if len(blob) < idx + payload_len:
            raise ValueError("ملف ناقص أو تالف")

        payload = blob[idx:idx+payload_len]

        return {
            "alg_id": alg_id,
            "salt": salt,
            "iv": iv,
            "mac": mac,
            "name": name,
            "payload": payload,
        }

    @staticmethod
    def read_metadata(enc_path: str):
        with open(enc_path, "rb") as f:
            blob = f.read()
        info = CryptoUtils.parse_header(blob)
        return info["alg_id"], info["name"]

    # ------------------ Base64 Clean ------------------
    @staticmethod
    def clean_base64_text(s: str) -> str:
        """
        أنا سويت هذه الدالة لأن كثير مرات المستخدم يلصق Base64 وفيه:
        - أسطر جديدة
        - مسافات
        - Tabs
        وهذا يخرب فك التشفير
        فهنا أشيل أي whitespace بالكامل.
        """
        return "".join((s or "").split())
