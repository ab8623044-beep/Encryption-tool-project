import os
import base64
from crypto_utils import CryptoUtils, ALG_3DES, ALG_VIGENERE
from engines import TripleDESEngine, VigenereEngine


class CryptoSystem:
    def __init__(self):
        self.engines_by_name = {
            "DES": TripleDESEngine(),
            "Vigenere": VigenereEngine(),
        }
        self.engines_by_id = {
            ALG_3DES: self.engines_by_name["DES"],
            ALG_VIGENERE: self.engines_by_name["Vigenere"],
        }

    # ---------------- Text ----------------
    def encrypt_text_to_b64(self, algorithm_name: str, plain_text: str, key_text: str) -> str:
        if algorithm_name not in self.engines_by_name:
            raise ValueError("خوارزمية غير مدعومة")
        blob = self.engines_by_name[algorithm_name].encrypt(plain_text.encode("utf-8"), key_text, "text.txt")
        return base64.b64encode(blob).decode("utf-8")

    def decrypt_text_from_b64(self, algorithm_name: str, b64_cipher: str, key_text: str) -> str:
        if algorithm_name not in self.engines_by_name:
            raise ValueError("خوارزمية غير مدعومة")

        clean = CryptoUtils.clean_base64_text(b64_cipher)
        try:
            blob = base64.b64decode(clean, validate=True)
        except Exception:
            raise ValueError("النص المشفر ليس Base64 صحيح")

        data, _ = self.engines_by_name[algorithm_name].decrypt(blob, key_text)
        return data.decode("utf-8", errors="replace")

    # ---------------- Files ----------------
    def encrypt_file(self, algorithm_name: str, input_path: str, key_text: str, output_path: str) -> str:
        if algorithm_name not in self.engines_by_name:
            raise ValueError("خوارزمية غير مدعومة")

        with open(input_path, "rb") as f:
            data = f.read()

        original_name = os.path.basename(input_path)
        blob = self.engines_by_name[algorithm_name].encrypt(data, key_text, original_name)

        with open(output_path, "wb") as f:
            f.write(blob)

        return output_path

    def decrypt_file_auto(self, input_path: str, key_text: str, output_path: str) -> str:
        with open(input_path, "rb") as f:
            blob = f.read()

        header = CryptoUtils.parse_header(blob)
        alg_id = header["alg_id"]

        if alg_id not in self.engines_by_id:
            raise ValueError("خوارزمية غير معروفة داخل الملف")

        engine = self.engines_by_id[alg_id]
        data, original_name = engine.decrypt(blob, key_text)

        # إذا المستخدم حفظ بدون امتداد -> أضيف الامتداد الأصلي
        chosen_base = os.path.basename(output_path)
        if "." not in chosen_base:
            _, orig_ext = os.path.splitext(original_name)
            if orig_ext:
                output_path += orig_ext

        with open(output_path, "wb") as f:
            f.write(data)

        return output_path

    # ---------------- Keys ----------------
    def generate_des_key_b64(self) -> str:
        raw = CryptoUtils.generate_3des_key()
        return base64.b64encode(raw).decode("utf-8")

    def generate_vigenere_key(self, length: int = 16) -> str:
        return CryptoUtils.generate_vigenere_key(length)

    # ---------------- Metadata ----------------
    def read_metadata(self, enc_path: str):
        return CryptoUtils.read_metadata(enc_path)
