import os
import cv2
import hashlib
import tkinter as tk
import base64
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import zipfile
import numpy as np

# File to store passwords and salts
PASSWORD_STORAGE_FILE = "passwords.txt"

# Function to save the password and salt for each file
def save_password_record(filename, password, salt):
    """Save the password and salt associated with a specific file."""
    with open(PASSWORD_STORAGE_FILE, "a") as f:  # Append mode to keep multiple records
        f.write(f"{filename}: {base64.b64encode(salt).decode()} : {password}\n")

# Function to view stored passwords
def view_saved_passwords():
    """Display the stored passwords in a pop-up window."""
    if not os.path.exists(PASSWORD_STORAGE_FILE):
        messagebox.showinfo("Stored Passwords", "No saved passwords found.")
        return

    with open(PASSWORD_STORAGE_FILE, "r") as f:
        data = f.read()

    password_window = tk.Toplevel()
    password_window.title("Saved Passwords")
    password_window.geometry("500x300")
    text_box = tk.Text(password_window, wrap="word")
    text_box.insert("1.0", data)
    text_box.config(state="disabled")  # Make text read-only
    text_box.pack(expand=True, fill="both")

# Function to generate AES encryption key
def generate_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

# File Encryption Function
def encrypt_file():
    filepath = filedialog.askopenfilename(title="Select File to Encrypt")
    password = file_password_entry.get()

    if not filepath or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return

    salt = os.urandom(16)  # Generate unique salt
    key = generate_key(password, salt)

    with open(filepath, 'rb') as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    encrypted_filepath = filepath + ".enc"
    with open(encrypted_filepath, 'wb') as f:
        f.write(salt + cipher.iv + encrypted_data)

    save_password_record(encrypted_filepath, password, salt)
    os.remove(filepath)  # Delete original file
    messagebox.showinfo("Success", f"File encrypted and saved as: {encrypted_filepath}")

# File Decryption Function
def decrypt_file():
    filepath = filedialog.askopenfilename(title="Select Encrypted File")
    password = file_password_entry.get()

    if not filepath or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return

    with open(filepath, 'rb') as f:
        salt = f.read(16)  # Extract stored salt
        iv = f.read(16)    # Extract stored IV
        encrypted_data = f.read()

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    except (ValueError, KeyError):
        messagebox.showerror("Error", "Wrong password! Unable to decrypt.")
        return

    output_filepath = filepath.replace(".enc", "")
    with open(output_filepath, 'wb') as f:
        f.write(decrypted_data)

    os.remove(filepath)
    messagebox.showinfo("Success", f"File decrypted and saved as: {output_filepath}")

# Image Steganography: Hide and Reveal
def hide_image_in_image():
    """Hides a secret image inside a cover image using LSB steganography."""

    cover_image_path = filedialog.askopenfilename(title="Select Cover Image")
    secret_image_path = filedialog.askopenfilename(title="Select Secret Image")

    if not cover_image_path or not secret_image_path:
        messagebox.showwarning("Warning", "Please select both images.")
        return

    cover_img = Image.open(cover_image_path).convert('RGB')
    secret_img = Image.open(secret_image_path).convert('RGB')

    if cover_img.size[0] < secret_img.size[0] or cover_img.size[1] < secret_img.size[1]:
        messagebox.showerror("Error", "Secret image must be smaller than the cover image.")
        return

    cover_array = np.array(cover_img, dtype=np.uint8)
    secret_array = np.array(secret_img.resize(cover_img.size), dtype=np.uint8)

    # Encode width and height into the first pixel for accurate extraction
    width, height = secret_img.size
    cover_array[0, 0] = [width // 256, width % 256, height // 256]

    # Encode the secret image into the cover image using 4 LSBs
    encoded_array = (cover_array & 0b11110000) | (secret_array >> 4)
    encoded_img = Image.fromarray(encoded_array, 'RGB')

    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if save_path:
        encoded_img.save(save_path)
        messagebox.showinfo("Success", f"Image hidden successfully and saved at: {save_path}")


def reveal_image_from_image():
    """Extracts and restores a hidden image from an encoded steganographic image."""

    image_path = filedialog.askopenfilename(title="Select Encoded Image")

    if not image_path:
        messagebox.showwarning("Warning", "Please select an encoded image.")
        return

    encoded_img = Image.open(image_path)
    encoded_array = np.array(encoded_img, dtype=np.uint8)

    # Retrieve original width and height from the first pixel
    width = int(encoded_array[0, 0, 0]) * 256 + int(encoded_array[0, 0, 1])
    height = int(encoded_array[0, 0, 2]) * 256 + int(encoded_array[0, 1, 0])

    if width == 0 or height == 0:
        messagebox.showerror("Error", "Failed to retrieve original size. The image might not be encoded properly.")
        return

    # Extract the hidden image by reversing the encoding process
    revealed_array = (encoded_array & 0b00001111) << 4
    revealed_img = Image.fromarray(revealed_array, 'RGB')

    # Restore the hidden image to its original size
    revealed_img = revealed_img.resize((width, height), Image.LANCZOS)

    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if save_path:
        revealed_img.save(save_path, format='PNG', quality=100)  # Preserve maximum quality
        messagebox.showinfo("Success", f"Hidden image revealed and saved at: {save_path}")

# Video Encryption Function with Password Saving
def encrypt_video_file():
    filepath = filedialog.askopenfilename(title="Select Video File to Encrypt")
    password = video_password_entry.get()

    if not filepath or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return

    # Generate a unique salt for this file
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

    with open(filepath, 'rb') as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    encrypted_filepath = filepath + ".enc"
    with open(encrypted_filepath, 'wb') as f:
        f.write(salt + cipher.iv + encrypted_data)  # Store salt and IV in the encrypted file

    # Save password record
    save_password_record(encrypted_filepath, password, salt)

    os.remove(filepath)  # Delete original file after encryption
    messagebox.showinfo("Success", f"Video encrypted and saved as: {encrypted_filepath}")

# Video Decryption Function with Unique Key Retrieval
def decrypt_video_file():
    filepath = filedialog.askopenfilename(title="Select Encrypted Video File")
    password = video_password_entry.get()

    if not filepath or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return

    with open(filepath, 'rb') as f:
        salt = f.read(16)  # Extract stored salt
        iv = f.read(16)    # Extract IV
        encrypted_data = f.read()

    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    except (ValueError, KeyError):
        messagebox.showerror("Error", "Wrong password! Unable to decrypt video.")
        return

    output_filepath = filepath.replace(".enc", "")
    with open(output_filepath, 'wb') as f:
        f.write(decrypted_data)

    os.remove(filepath)  # Delete encrypted file after decryption
    messagebox.showinfo("Success", f"Video decrypted successfully and saved as: {output_filepath}")

# GUI Setup
root = tk.Tk()
root.title("Secure File & Media Manager")
root.geometry("700x500")
root.configure(bg="#f5f5f5")

# Style Configuration
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Arial", 12), padding=5)
style.configure("TLabel", font=("Arial", 12))
style.configure("TEntry", font=("Arial", 12), padding=5)

# Notebook for Tabs
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both", padx=10, pady=10)

# File Encryption Frame
file_frame = ttk.Frame(notebook)
notebook.add(file_frame, text="File Encryption & Decryption")

file_password_label = ttk.Label(file_frame, text="Enter Password:")
file_password_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
file_password_entry = ttk.Entry(file_frame, show="*")
file_password_entry.grid(row=0, column=1, padx=5, pady=5)
file_encrypt_button = ttk.Button(file_frame, text="Encrypt File", command=encrypt_file)
file_encrypt_button.grid(row=1, column=0, padx=5, pady=5)
file_decrypt_button = ttk.Button(file_frame, text="Decrypt File", command=decrypt_file)
file_decrypt_button.grid(row=1, column=1, padx=5, pady=5)
view_passwords_button = ttk.Button(root, text="View Saved Passwords", command=view_saved_passwords)
view_passwords_button.pack(pady=5)

# Image Steganography Frame
image_frame = ttk.Frame(notebook)
notebook.add(image_frame, text="Image Steganography")

hide_image_button = ttk.Button(image_frame, text="Hide Image in Image", command=hide_image_in_image)
hide_image_button.pack(pady=10)

reveal_image_button = ttk.Button(image_frame, text="Reveal Hidden Image", command=reveal_image_from_image)
reveal_image_button.pack(pady=10)

# Video Encryption Frame
video_frame = ttk.Frame(notebook)
notebook.add(video_frame, text="Video Encryption & Decryption")

video_password_label = ttk.Label(video_frame, text="Enter Password:")
video_password_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

video_password_entry = ttk.Entry(video_frame, show="*")
video_password_entry.grid(row=0, column=1, padx=5, pady=5)

video_encrypt_button = ttk.Button(video_frame, text="Encrypt Video", command=encrypt_video_file)
video_encrypt_button.grid(row=1, column=0, padx=5, pady=5)

video_decrypt_button = ttk.Button(video_frame, text="Decrypt Video", command=decrypt_video_file)
video_decrypt_button.grid(row=1, column=1, padx=5, pady=5)

status_label = ttk.Label(root, text="Welcome to Secure File & Media Manager", font=("Arial", 14))
status_label.pack(pady=10)

root.mainloop()
