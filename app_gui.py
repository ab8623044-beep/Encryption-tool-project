import os
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

from crypto_system import CryptoSystem
from ui_helpers import enable_clipboard_shortcuts_for_text


class CryptoApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("نظام التشفير - 3DES و Vigenere")
        self.root.geometry("1150x800")

        self.system = CryptoSystem()

        self.algorithm = tk.StringVar(value="DES")
        self.key_var = tk.StringVar()
        self.show_key = tk.BooleanVar(value=False)

        self.selected_file = ""
        self.original_name = ""

        self._build_ui()

    def _build_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_text = ttk.Frame(nb)
        self.tab_files = ttk.Frame(nb)
        self.tab_keys = ttk.Frame(nb)
        self.tab_info = ttk.Frame(nb)

        nb.add(self.tab_text, text="تشفير النصوص")
        nb.add(self.tab_files, text="تشفير الملفات")
        nb.add(self.tab_keys, text="توليد المفاتيح")
        nb.add(self.tab_info, text="ملاحظات النظام")

        self._build_text_tab()
        self._build_files_tab()
        self._build_keys_tab()
        self._build_info_tab()

    # =========================================================
    # تبويب النصوص (قسمين منفصلين: تشفير / فك تشفير)
    # =========================================================
    def _build_text_tab(self):
        settings = ttk.LabelFrame(self.tab_text, text="الإعدادات", padding=10)
        settings.pack(fill="x", padx=5, pady=5)

        ttk.Label(settings, text="الخوارزمية:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        algo = ttk.Combobox(settings, textvariable=self.algorithm, values=["DES", "Vigenere"], state="readonly", width=15)
        algo.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(settings, text="المفتاح:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.key_entry_text = ttk.Entry(settings, textvariable=self.key_var, width=40, show="*")
        self.key_entry_text.grid(row=0, column=3, padx=5, pady=5)

        ttk.Checkbutton(settings, text="إظهار", variable=self.show_key, command=self._toggle_key).grid(row=0, column=4, padx=5)
        ttk.Button(settings, text="توليد مفتاح", command=self._generate_key_by_algo).grid(row=0, column=5, padx=5)

        main = ttk.Frame(self.tab_text)
        main.pack(fill="both", expand=True, padx=5, pady=5)

        enc_frame = ttk.LabelFrame(main, text="1) تشفير نص", padding=10)
        dec_frame = ttk.LabelFrame(main, text="2) فك تشفير نص (الصق Base64 هنا)", padding=10)

        enc_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        dec_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        # ---- تشفير ----
        ttk.Label(enc_frame, text="النص العادي:").pack(anchor="w")
        self.plain_text_box = ScrolledText(enc_frame, height=12)
        self.plain_text_box.pack(fill="both", expand=True, pady=5)

        ttk.Button(enc_frame, text="تشفير →", command=self._encrypt_text).pack(fill="x", pady=5)

        ttk.Label(enc_frame, text="النص المشفر (Base64):").pack(anchor="w")
        self.encrypted_b64_box = ScrolledText(enc_frame, height=10)
        self.encrypted_b64_box.pack(fill="both", expand=True, pady=5)

        ttk.Button(enc_frame, text="نسخ Base64", command=self._copy_encrypted_b64).pack(fill="x", pady=5)

        # ---- فك تشفير ----
        ttk.Label(dec_frame, text="ضع/الصق Base64 المشفر:").pack(anchor="w")
        self.decrypt_input_b64_box = ScrolledText(dec_frame, height=12)
        self.decrypt_input_b64_box.pack(fill="both", expand=True, pady=5)

        ttk.Button(dec_frame, text="← فك التشفير", command=self._decrypt_text).pack(fill="x", pady=5)

        ttk.Label(dec_frame, text="الناتج بعد فك التشفير:").pack(anchor="w")
        self.decrypted_text_box = ScrolledText(dec_frame, height=10)
        self.decrypted_text_box.pack(fill="both", expand=True, pady=5)

        ttk.Button(dec_frame, text="نسخ النص الناتج", command=self._copy_decrypted_text).pack(fill="x", pady=5)

        # ✅ أهم سطرين: تفعيل اللصق والنسخ في كل الخانات
        for w in [self.plain_text_box, self.encrypted_b64_box, self.decrypt_input_b64_box, self.decrypted_text_box]:
            enable_clipboard_shortcuts_for_text(w)

    def _encrypt_text(self):
        alg = self.algorithm.get()
        key = self.key_var.get().strip()
        plain = self.plain_text_box.get("1.0", tk.END).rstrip("\n")

        if not plain:
            messagebox.showwarning("تنبيه", "اكتب نص قبل التشفير")
            return
        if not key:
            messagebox.showwarning("تنبيه", "اكتب المفتاح")
            return

        try:
            b64 = self.system.encrypt_text_to_b64(alg, plain, key)
            self.encrypted_b64_box.delete("1.0", tk.END)
            self.encrypted_b64_box.insert("1.0", b64)
        except Exception as e:
            messagebox.showerror("خطأ", str(e))

    def _decrypt_text(self):
        alg = self.algorithm.get()
        key = self.key_var.get().strip()
        b64_cipher = self.decrypt_input_b64_box.get("1.0", tk.END)

        if not b64_cipher.strip():
            messagebox.showwarning("تنبيه", "الصق Base64 المشفر في خانة فك التشفير")
            return
        if not key:
            messagebox.showwarning("تنبيه", "اكتب المفتاح")
            return

        try:
            plain = self.system.decrypt_text_from_b64(alg, b64_cipher, key)
            self.decrypted_text_box.delete("1.0", tk.END)
            self.decrypted_text_box.insert("1.0", plain)
        except Exception as e:
            messagebox.showerror("خطأ", str(e))

    def _copy_encrypted_b64(self):
        txt = self.encrypted_b64_box.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showwarning("تنبيه", "مافي Base64 للنسخ")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        messagebox.showinfo("تم", "تم نسخ Base64")

    def _copy_decrypted_text(self):
        txt = self.decrypted_text_box.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showwarning("تنبيه", "مافي نص للنسخ")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        messagebox.showinfo("تم", "تم نسخ النص الناتج")

    # =========================================================
    # تبويب الملفات
    # =========================================================
    def _build_files_tab(self):
        settings = ttk.LabelFrame(self.tab_files, text="الإعدادات", padding=10)
        settings.pack(fill="x", padx=5, pady=5)

        ttk.Label(settings, text="الخوارزمية عند التشفير:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        algo = ttk.Combobox(settings, textvariable=self.algorithm, values=["DES", "Vigenere"], state="readonly", width=15)
        algo.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(settings, text="المفتاح:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.key_entry_file = ttk.Entry(settings, textvariable=self.key_var, width=40, show="*")
        self.key_entry_file.grid(row=0, column=3, padx=5, pady=5)

        ttk.Checkbutton(settings, text="إظهار", variable=self.show_key, command=self._toggle_key).grid(row=0, column=4, padx=5)
        ttk.Button(settings, text="توليد مفتاح", command=self._generate_key_by_algo).grid(row=0, column=5, padx=5)

        info = ttk.LabelFrame(self.tab_files, text="الملف المحدد", padding=10)
        info.pack(fill="x", padx=5, pady=5)

        self.file_label = ttk.Label(info, text="لم يتم اختيار ملف")
        self.file_label.pack(anchor="w")

        self.meta_label = ttk.Label(info, text="الاسم الأصلي داخل الملف المشفر: غير معروف")
        self.meta_label.pack(anchor="w")

        btns = ttk.Frame(self.tab_files)
        btns.pack(fill="x", padx=5, pady=5)

        ttk.Button(btns, text="اختيار ملف", command=self._select_file).pack(side="left", padx=5)
        ttk.Button(btns, text="تشفير الملف", command=self._encrypt_file).pack(side="left", padx=5)
        ttk.Button(btns, text="فك تشفير الملف", command=self._decrypt_file).pack(side="left", padx=5)

        logf = ttk.LabelFrame(self.tab_files, text="سجل العمليات", padding=10)
        logf.pack(fill="both", expand=True, padx=5, pady=5)

        self.log = ScrolledText(logf, height=15)
        self.log.pack(fill="both", expand=True)

        enable_clipboard_shortcuts_for_text(self.log)

    def _select_file(self):
        path = filedialog.askopenfilename(title="اختر ملف", filetypes=[("All files", "*.*")])
        if not path:
            return

        self.selected_file = path
        size = os.path.getsize(path)
        self.file_label.config(text=f"الملف: {os.path.basename(path)} | الحجم: {self._size_str(size)}")

        self.original_name = ""
        try:
            _alg_id, name = self.system.read_metadata(path)
            self.original_name = name
            self.meta_label.config(text=f"الاسم الأصلي داخل الملف المشفر: {name}")
        except Exception:
            self.meta_label.config(text="الاسم الأصلي داخل الملف المشفر: غير معروف (قد يكون ملف عادي)")

        self._log(f"تم اختيار ملف: {os.path.basename(path)}")

    def _encrypt_file(self):
        if not self.selected_file:
            messagebox.showwarning("تنبيه", "اختاري ملف أولاً")
            return

        alg = self.algorithm.get()
        key = self.key_var.get().strip()
        if not key:
            messagebox.showwarning("تنبيه", "اكتبي المفتاح")
            return

        default_name = os.path.basename(self.selected_file) + ".enc"
        out_path = filedialog.asksaveasfilename(
            title="حفظ الملف المشفر",
            initialfile=default_name,
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
        )
        if not out_path:
            return

        try:
            final = self.system.encrypt_file(alg, self.selected_file, key, out_path)
            self._log(f"تم تشفير الملف: {os.path.basename(final)}")
            messagebox.showinfo("تم", f"تم تشفير الملف بنجاح:\n{final}")
        except Exception as e:
            messagebox.showerror("خطأ", str(e))

    def _decrypt_file(self):
        if not self.selected_file:
            messagebox.showwarning("تنبيه", "اختاري ملف أولاً")
            return

        key = self.key_var.get().strip()
        if not key:
            messagebox.showwarning("تنبيه", "اكتبي المفتاح")
            return

        suggested = self.original_name if self.original_name else "output"
        out_path = filedialog.asksaveasfilename(
            title="حفظ الملف بعد فك التشفير",
            initialfile=suggested,
            filetypes=[("All files", "*.*")],
        )
        if not out_path:
            return

        try:
            final = self.system.decrypt_file_auto(self.selected_file, key, out_path)
            self._log(f"تم فك التشفير إلى: {os.path.basename(final)}")
            messagebox.showinfo("تم", f"تم فك التشفير بنجاح:\n{final}")
        except Exception as e:
            messagebox.showerror("خطأ", str(e))

    # =========================================================
    # تبويب المفاتيح
    # =========================================================
    def _build_keys_tab(self):
        frame = ttk.LabelFrame(self.tab_keys, text="توليد مفاتيح", padding=10)
        frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(frame, text="توليد مفتاح DES (Base64)", command=self._gen_des).pack(fill="x", pady=5)
        ttk.Button(frame, text="توليد مفتاح Vigenere (طول 16)", command=self._gen_vig).pack(fill="x", pady=5)

        self.key_box = ScrolledText(self.tab_keys, height=8)
        self.key_box.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Button(self.tab_keys, text="نسخ المفتاح", command=self._copy_key_box).pack(pady=5)

        enable_clipboard_shortcuts_for_text(self.key_box)

    def _gen_des(self):
        k = self.system.generate_des_key_b64()
        self.key_var.set(k)
        self.key_box.delete("1.0", tk.END)
        self.key_box.insert("1.0", k)
        messagebox.showinfo("تم", "تم توليد مفتاح DES ووضعه في خانة المفتاح")

    def _gen_vig(self):
        k = self.system.generate_vigenere_key(16)
        self.key_var.set(k)
        self.key_box.delete("1.0", tk.END)
        self.key_box.insert("1.0", k)
        messagebox.showinfo("تم", "تم توليد مفتاح Vigenere ووضعه في خانة المفتاح")

    def _copy_key_box(self):
        txt = self.key_box.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showwarning("تنبيه", "المربع فاضي")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        messagebox.showinfo("تم", "تم نسخ المفتاح")

    # =========================================================
    # الملاحظات (شرح كامل)
    # =========================================================
    def _build_info_tab(self):
        info = """
آلية التشفير في البرنامج:

أولاً: DES (مطبق كـ 3DES)
- الخوارزمية المستخدمة: TripleDES
- وضع التشغيل: CBC
- Padding: PKCS7
- لو المستخدم كتب كلمة مرور -> أشتق مفاتيح باستخدام PBKDF2-SHA256 + Salt
- أضيف HMAC-SHA256 عشان أتأكد إن:
  1) المفتاح صحيح
  2) البيانات ما تم التلاعب فيها

ثانياً: Vigenere
- خوارزمية كلاسيكية تعليمية.
- للنصوص: تشفير مباشر للحروف الإنجليزية.
- للملفات: أحول الملف إلى Base64 ثم أشفر النص الناتج.

النصوص:
- عند التشفير: الناتج Base64 عشان أقدر أنسخه وألصقه.
- عند فك التشفير: ألصق Base64 في خانة فك التشفير والبرنامج ينظفه تلقائياً.

الملفات:
- عند التشفير: يُحفظ داخل ملف .enc اسم الملف الأصلي وامتداده.
- عند فك التشفير: البرنامج يقرأ الخوارزمية من داخل الملف تلقائياً ويرجع الملف الأصلي.

ملاحظة مهمة:
- إذا فكيت ملف وحفظتيه بدون امتداد، البرنامج يضيف الامتداد الأصلي تلقائياً.
"""
        box = ScrolledText(self.tab_info, height=30, wrap=tk.WORD)
        box.pack(fill="both", expand=True, padx=10, pady=10)
        box.insert("1.0", info.strip())
        box.configure(state="disabled")
        enable_clipboard_shortcuts_for_text(box)

    # =========================================================
    # Helpers
    # =========================================================
    def _toggle_key(self):
        show = "" if self.show_key.get() else "*"
        self.key_entry_text.config(show=show)
        self.key_entry_file.config(show=show)

    def _generate_key_by_algo(self):
        if self.algorithm.get() == "DES":
            self._gen_des()
        else:
            self._gen_vig()

    def _log(self, msg: str):
        t = datetime.datetime.now().strftime("%H:%M:%S")
        self.log.insert(tk.END, f"[{t}] {msg}\n")
        self.log.see(tk.END)

    def _size_str(self, size: int) -> str:
        s = float(size)
        for unit in ["B", "KB", "MB", "GB"]:
            if s < 1024:
                return f"{s:.2f} {unit}"
            s /= 1024
        return f"{s:.2f} TB"
