
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class AESEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption App")
        self.root.geometry("400x300")

        self.key_label = tk.Label(root, text="Key:")
        self.key_label.pack(pady=5)
        self.key_entry = tk.Entry(root, width=50, show='*')
        self.key_entry.pack(pady=5)

        self.plaintext_label = tk.Label(root, text="Plaintext:")
        self.plaintext_label.pack(pady=5)
        self.plaintext_entry = tk.Entry(root, width=50)
        self.plaintext_entry.pack(pady=5)

        self.ciphertext_label = tk.Label(root, text="Ciphertext:")
        self.ciphertext_label.pack(pady=5)
        self.ciphertext_entry = tk.Entry(root, width=50)
        self.ciphertext_entry.pack(pady=5)

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=5)

    def encrypt(self):
        key = self.key_entry.get().encode('utf-8')
        plaintext = self.plaintext_entry.get().encode('utf-8')
        try:
            cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            iv = cipher.iv
            encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
            self.ciphertext_entry.delete(0, tk.END)
            self.ciphertext_entry.insert(0, encrypted_data)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt(self):
        key = self.key_entry.get().encode('utf-8')
        ciphertext = self.ciphertext_entry.get().encode('utf-8')
        try:
            encrypted_data = base64.b64decode(ciphertext)
            iv = encrypted_data[:AES.block_size]
            ciphertext = encrypted_data[AES.block_size:]
            cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
            self.plaintext_entry.delete(0, tk.END)
            self.plaintext_entry.insert(0, plaintext)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = AESEncryptionApp(root)
    root.mainloop()