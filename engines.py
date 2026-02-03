import os
import base64
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

from crypto_utils import CryptoUtils, MAGIC, VERSION, ALG_3DES, ALG_VIGENERE


class CryptoEngine:
    ALG_ID = 0
    NAME = "Base"

    def encrypt(self, data: bytes, key_text: str, original_name: str) -> bytes:
        raise NotImplementedError

    def decrypt(self, blob: bytes, key_text: str):
        raise NotImplementedError


class TripleDESEngine(CryptoEngine):
    """
    3DES-CBC + PKCS7 + HMAC-SHA256
    - HMAC يضمن لي إن المفتاح صحيح وإن الملف ما تم العبث فيه
    """
    ALG_ID = ALG_3DES
    NAME = "DES"
    BLOCK_SIZE = 8

    def _derive_keys(self, key_mode: str, key_material: bytes, salt: bytes):
        if key_mode == "raw":
            enc_key = key_material
            h = hashes.Hash(hashes.SHA256(), backend=default_backend())
            h.update(b"mac|" + enc_key)
            mac_key = h.finalize()
            return enc_key, mac_key

        dk = CryptoUtils.kdf_password(key_material, salt, length=24 + 32)
        return dk[:24], dk[24:]

    def encrypt(self, data: bytes, key_text: str, original_name: str) -> bytes:
        key_mode, key_material = CryptoUtils.parse_key_input(key_text)
        salt = os.urandom(16) if key_mode == "password" else b""
        enc_key, mac_key = self._derive_keys(key_mode, key_material, salt)

        iv = os.urandom(self.BLOCK_SIZE)
        padded = CryptoUtils.pkcs7_pad(data, self.BLOCK_SIZE)

        cipher = Cipher(algorithms.TripleDES(enc_key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()

        # header بدون mac
        name_bytes = original_name.encode("utf-8", errors="replace")
        if len(name_bytes) > 65535:
            name_bytes = name_bytes[:65535]

        header_wo_mac = b""
        header_wo_mac += MAGIC
        header_wo_mac += struct.pack("!B", VERSION)
        header_wo_mac += struct.pack("!B", self.ALG_ID)
        header_wo_mac += struct.pack("!B", len(salt))
        header_wo_mac += struct.pack("!B", len(iv))
        header_wo_mac += struct.pack("!H", 0)
        header_wo_mac += salt
        header_wo_mac += iv
        header_wo_mac += struct.pack("!H", len(name_bytes))
        header_wo_mac += name_bytes
        header_wo_mac += struct.pack("!I", len(ciphertext))

        hm = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        hm.update(header_wo_mac)
        hm.update(ciphertext)
        mac = hm.finalize()

        header = CryptoUtils.build_header(self.ALG_ID, salt, iv, mac, original_name, len(ciphertext))
        return header + ciphertext

    def decrypt(self, blob: bytes, key_text: str):
        info = CryptoUtils.parse_header(blob)
        if info["alg_id"] != self.ALG_ID:
            raise ValueError("الملف ليس مشفرًا بـ DES/3DES")

        salt = info["salt"]
        iv = info["iv"]
        mac = info["mac"]
        original_name = info["name"]
        ciphertext = info["payload"]

        key_mode, key_material = CryptoUtils.parse_key_input(key_text)
        enc_key, mac_key = self._derive_keys(key_mode, key_material, salt)

        # تحقق HMAC
        name_bytes = original_name.encode("utf-8", errors="replace")
        if len(name_bytes) > 65535:
            name_bytes = name_bytes[:65535]

        header_wo_mac = b""
        header_wo_mac += MAGIC
        header_wo_mac += struct.pack("!B", VERSION)
        header_wo_mac += struct.pack("!B", self.ALG_ID)
        header_wo_mac += struct.pack("!B", len(salt))
        header_wo_mac += struct.pack("!B", len(iv))
        header_wo_mac += struct.pack("!H", 0)
        header_wo_mac += salt
        header_wo_mac += iv
        header_wo_mac += struct.pack("!H", len(name_bytes))
        header_wo_mac += name_bytes
        header_wo_mac += struct.pack("!I", len(ciphertext))

        hm = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        hm.update(header_wo_mac)
        hm.update(ciphertext)
        try:
            hm.verify(mac)
        except Exception:
            raise ValueError("المفتاح غير صحيح أو الملف تالف")

        cipher = Cipher(algorithms.TripleDES(enc_key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        data = CryptoUtils.pkcs7_unpad(padded, self.BLOCK_SIZE)

        return data, original_name


class VigenereEngine(CryptoEngine):
    """
    Vigenere للنصوص/الملفات:
    - للملفات: أشفر Base64 للناتج
    """
    ALG_ID = ALG_VIGENERE
    NAME = "Vigenere"

    def _vig_encrypt(self, text: str, key: str) -> str:
        key = key.upper()
        out = []
        i = 0
        for ch in text:
            if ch.isalpha():
                shift = ord(key[i % len(key)]) - ord("A")
                if ch.isupper():
                    out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
                else:
                    out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
                i += 1
            else:
                out.append(ch)
        return "".join(out)

    def _vig_decrypt(self, text: str, key: str) -> str:
        key = key.upper()
        out = []
        i = 0
        for ch in text:
            if ch.isalpha():
                shift = ord(key[i % len(key)]) - ord("A")
                if ch.isupper():
                    out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
                else:
                    out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
                i += 1
            else:
                out.append(ch)
        return "".join(out)

    def encrypt(self, data: bytes, key_text: str, original_name: str) -> bytes:
        key = (key_text or "").strip()
        if not key:
            raise ValueError("مفتاح Vigenere فارغ")

        b64_text = base64.b64encode(data).decode("ascii")
        enc_text = self._vig_encrypt(b64_text, key).encode("utf-8")

        header = CryptoUtils.build_header(self.ALG_ID, b"", b"", b"", original_name, len(enc_text))
        return header + enc_text

    def decrypt(self, blob: bytes, key_text: str):
        info = CryptoUtils.parse_header(blob)
        if info["alg_id"] != self.ALG_ID:
            raise ValueError("الملف ليس مشفرًا بـ Vigenere")

        key = (key_text or "").strip()
        if not key:
            raise ValueError("مفتاح Vigenere فارغ")

        original_name = info["name"]
        enc_text = info["payload"].decode("utf-8", errors="strict")
        dec_text = self._vig_decrypt(enc_text, key)

        try:
            data = base64.b64decode(dec_text.encode("ascii"), validate=True)
        except Exception:
            raise ValueError("فشل فك التشفير: المفتاح خطأ أو البيانات تالفة")

        return data, original_name
