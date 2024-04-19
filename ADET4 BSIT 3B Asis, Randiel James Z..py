import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from hashlib import sha256
import os

# Global variables to store key and selected file path
key = b''
selected_file = ''


def enter_key():
    global key
    try:
        key = key_entry.get().encode()
        if not key:
            raise ValueError("Key cannot be empty.")
        messagebox.showinfo("Success", "Key has been set successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to set key: {str(e)}")


def encrypt_data():
    global key, selected_file
    try:
        if not key:
            raise ValueError("Please enter the key first.")
        if not selected_file:
            raise ValueError("No file selected for encryption.")

        hashed_key = sha256(key).digest()

        with open(selected_file, 'rb') as file:
            data = file.read()

        cipher = AES.new(hashed_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))

        encrypted_file = selected_file + ".enc"
        with open(encrypted_file, 'wb') as file:
            file.write(cipher.iv)
            file.write(ct_bytes)

        messagebox.showinfo("Success", "File encrypted successfully.")
        os.remove(selected_file)
        selected_file = ''
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")


def decrypt_data():
    global key, selected_file
    try:
        if not key:
            raise ValueError("Please enter the key first.")
        if not selected_file:
            raise ValueError("No file selected for decryption.")

        hashed_key = sha256(key).digest()

        with open(selected_file, 'rb') as file:
            iv = file.read(16)
            ct = file.read()

        cipher = AES.new(hashed_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)

        decrypted_file = os.path.splitext(selected_file)[0]

        with open(decrypted_file, 'wb') as file:
            file.write(pt)

        messagebox.showinfo("Success", "File decrypted successfully.")
        os.remove(selected_file)
        selected_file = ''
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")


def select_file():
    global selected_file
    try:
        selected_file = filedialog.askopenfilename(title="Select file")
        if selected_file:
            messagebox.showinfo("Success", f"File selected: {selected_file}")
    except Exception as e:
        messagebox.showerror("Error", f"File selection failed: {str(e)}")


window = tk.Tk()
window.title("ADET4 File Encryption Tool by Randiel James Z. Asis")
window.geometry("455x240")

key_label = tk.Label(window, text="Enter Key:")
key_label.pack()
key_entry = tk.Entry(window, show="*")
key_entry.pack()

enter_key_button = tk.Button(window, text="Enter Key", command=enter_key)
enter_key_button.pack()

select_file_button = tk.Button(window, text="Select File", command=select_file)
select_file_button.pack()

encrypt_button = tk.Button(window, text="Encrypt File", command=encrypt_data)
encrypt_button.pack()

decrypt_button = tk.Button(window, text="Decrypt File", command=decrypt_data)
decrypt_button.pack()

window.mainloop()
