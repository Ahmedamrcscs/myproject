import os
import random
import hashlib
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

USERS_FILE = "users.txt"



def hash_password(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()




def encrypt_des(data: bytes, username: str) -> bytes:
    # 1. Generate a valid 8-byte key from the username
    key = hashlib.sha256(username.encode('utf-8')).digest()[:8]

    # 2. Create DES cipher in ECB mode (Deterministic for auth comparison)
    cipher = DES.new(key, DES.MODE_ECB)

    # 3. Pad data to be a multiple of DES block size (8 bytes)
    padded_data = pad(data, DES.block_size)

    # 4. Encrypt
    return cipher.encrypt(padded_data)



def encrypt_aes(data: bytes, username: str) -> bytes:
    # 1. Generate a valid 16-byte key (AES-128) from the username
    key = hashlib.sha256(username.encode('utf-8')).digest()[:16]

    # 2. Create AES cipher in ECB mode (Deterministic for auth comparison)
    cipher = AES.new(key, AES.MODE_ECB)

    # 3. Pad data to be a multiple of AES block size (16 bytes)
    padded_data = pad(data, AES.block_size)

    # 4. Encrypt
    return cipher.encrypt(padded_data)



def encrypt_rsa(data: bytes, public_key) -> str:
    # 1. Convert the bytes data to a large integer
    int_data = int.from_bytes(data, byteorder='big')

    # 2. Perform raw RSA encryption: c = m^e mod n
    # We use raw RSA because we need a deterministic result for the login comparison to work.
    # Standard PKCS1_OAEP padding is random and would cause login to fail.
    encrypted_int = pow(int_data, public_key.e, public_key.n)

    # 3. Return as hex string
    return hex(encrypted_int)[2:]


def generate_keys(username: str):
    random.seed(username)

    # Generate 1024-bit RSA key using the seeded random generator
    # random.randbytes ensures it uses the seed we just set
    key = RSA.generate(1024, randfunc=random.randbytes)

    return key.publickey()

# ==============================================================================


def full_encryption(username: str, password: str) -> str:



    hashed = hash_password(password)

  
    des_result = encrypt_des(hashed, username)


    aes_result = encrypt_aes(des_result, username)

    public_key = generate_keys(username)
    final_value = encrypt_rsa(aes_result, public_key)


    return final_value
# =======================================================



def load_users():
    users = {}

    if not os.path.exists(USERS_FILE):
        return users

    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if ":" not in line:
                continue
            username, encrypted_value = line.split(":", 1)
            users[username] = encrypted_value

    return users


def save_user(username: str, encrypted_value: str):
    with open(USERS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{username}:{encrypted_value}\n")



def validate_password(username: str, password: str) -> str:
   
    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if password.lower() == username.lower():
        return "Password cannot be the same as the username."

    if " " in password:
        return "Password cannot contain spaces."

    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."

    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."

    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit."

    if not any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for c in password):
        return "Password must contain at least one special character."

    return "OK"




def register_user(username: str, password: str) -> str:
    
    username = username.strip()
    password = password.strip()

    if not username or not password:
        return "Username and password cannot be empty."

    users = load_users()

    if username in users:
        return "Username already exists. Try another one."

    # Check password criteria
    validation_result = validate_password(username, password)
    if validation_result != "OK":
        return validation_result

    encrypted_value = full_encryption(username, password)
    save_user(username, encrypted_value)

    return f"User '{username}' registered successfully."


def login_user(username: str, password: str) -> str:
    
    username = username.strip()
    password = password.strip()

    if not username or not password:
        return "Username and password cannot be empty."

    users = load_users()

    if username not in users:
        return "User not found. Please register first."

    encrypted_value = full_encryption(username, password)

    if encrypted_value == users[username]:
        return "Authentication successful. Welcome!"
    else:
        return "Authentication failed. Wrong password."




def main_menu():
    while True:
        print("\n==== Password Authentication App ====")
        print("1- Register")
        print("2- Login")
        print("0- Exit")

        choice = input("Choose an option: ").strip()

        if choice == '1':
            username = input("Enter new username: ")
            password = input("Enter new password: ")
            msg = register_user(username, password)
            print(msg)

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            msg = login_user(username, password)
            print(msg)

        elif choice == '0':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Try again.")



# ===================== GUI =====================
def run_gui():
    root = tk.Tk()
    root.title("Password Authentication App")

    # Simple colors
    bg_color = "#f0f4ff"    # light blue-ish background
    btn_color = "#4a90e2"   # blue buttons
    btn_text_color = "#ffffff"
    label_color = "#333333" # dark text

    root.configure(bg=bg_color)
    root.geometry("420x260")
    root.resizable(False, False)

    # Title
    title_label = tk.Label(
        root,
        text="Password Authentication App",
        bg=bg_color,
        fg="#1a3c6e",
        font=("Arial", 14, "bold")
    )
    title_label.pack(pady=(15, 10))

    # Username label + entry
    lbl_username = tk.Label(root, text="Username:", bg=bg_color, fg=label_color)
    lbl_username.pack(pady=(5, 2))
    entry_username = tk.Entry(root, width=30)
    entry_username.pack()

    # Password label + entry
    lbl_password = tk.Label(root, text="Password:", bg=bg_color, fg=label_color)
    lbl_password.pack(pady=(10, 2))
    entry_password = tk.Entry(root, width=30, show="*")
    entry_password.pack()

    # Status label
    status_label = tk.Label(root, text="", bg=bg_color, fg="#00529B")
    status_label.pack(pady=10)

    def on_register():
        username = entry_username.get()
        password = entry_password.get()
        msg = register_user(username, password)
        status_label.config(text=msg)
        if "successfully" in msg:
            messagebox.showinfo("Register", msg)
        else:
            messagebox.showwarning("Register", msg)

    def on_login():
        username = entry_username.get()
        password = entry_password.get()
        msg = login_user(username, password)
        status_label.config(text=msg)
        if "successful" in msg:
            messagebox.showinfo("Login", msg)
        else:
            messagebox.showwarning("Login", msg)

    # Buttons frame
    btn_frame = tk.Frame(root, bg=bg_color)
    btn_frame.pack(pady=10)

    btn_register = tk.Button(
        btn_frame,
        text="Register",
        width=12,
        command=on_register,
        bg=btn_color,
        fg=btn_text_color,
        activebackground="#357ABD",
        activeforeground=btn_text_color
    )
    btn_register.grid(row=0, column=0, padx=5)

    btn_login = tk.Button(
        btn_frame,
        text="Login",
        width=12,
        command=on_login,
        bg=btn_color,
        fg=btn_text_color,
        activebackground="#357ABD",
        activeforeground=btn_text_color
    )
    btn_login.grid(row=0, column=1, padx=5)

    root.mainloop()



if __name__ == "__main__":
    # main_menu()
    run_gui()
