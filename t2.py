import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# Generate and save the key for encryption/decryption
def generate_key():
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)

def load_key():
    return open('secret.key', 'rb').read()

# Encrypt the selected file
def encrypt_file(file_path):
    key = load_key()
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original_file_data = file.read()
    encrypted_data = fernet.encrypt(original_file_data)
    with open(file_path + ".encrypted", 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    os.remove(file_path)
    messagebox.showinfo("Success", "File encrypted successfully!")

# Decrypt the selected file
def decrypt_file(file_path):
    key = load_key()
    fernet = Fernet(key)
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    original_file_path = file_path.replace(".encrypted", "")
    with open(original_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    os.remove(file_path)
    messagebox.showinfo("Success", "File decrypted successfully!")

# GUI for selecting and encrypting/decrypting files
def select_file_to_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        encrypt_file(file_path)

def select_file_to_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        decrypt_file(file_path)

# Initialize the main window
root = tk.Tk()
root.title("Image Encryption Tool")

# Generate key button
generate_key_btn = tk.Button(root, text="Generate Key", command=generate_key)
generate_key_btn.pack(pady=10)

# Encrypt file button
encrypt_btn = tk.Button(root, text="Encrypt File", command=select_file_to_encrypt)
encrypt_btn.pack(pady=10)

# Decrypt file button
decrypt_btn = tk.Button(root, text="Decrypt File", command=select_file_to_decrypt)
decrypt_btn.pack(pady=10)

root.mainloop()