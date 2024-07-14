import tkinter as tk
from tkinter import messagebox

def caesar_cipher_encrypt(text, shift):
    encrypted_text = ""
    shift = shift % 26  # Ensure the shift is within the range of the alphabet
    for char in text:
        if char.isalpha():  # check if the character is a letter
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char  # keep non-alphabet characters unchanged
    return encrypted_text

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)  # decryption is just encryption with negative shift

def encrypt_message():
    try:
        text = input_text.get("1.0", tk.END).strip()
        shift = int(shift_value.get().strip())
        if shift < 0:
            raise ValueError("Negative shift")
        encrypted = caesar_cipher_encrypt(text, shift)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted)
    except ValueError:
        messagebox.showerror("Error", "Shift value must be a positive integer.")

def decrypt_message():
    try:
        text = input_text.get("1.0", tk.END).strip()
        shift = int(shift_value.get().strip())
        if shift < 0:
            raise ValueError("Negative shift")
        decrypted = caesar_cipher_decrypt(text, shift)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted)
    except ValueError:
        messagebox.showerror("Error", "Shift value must be a positive integer.")

def clear_fields():
    input_text.delete("1.0", tk.END)
    shift_value.delete(0, tk.END)
    output_text.delete("1.0", tk.END)

# Create the main window
root = tk.Tk()
root.title("Caesar Cipher Tool")

# Set window size
root.geometry("500x400")

# Create and place the widgets with improved layout
frame = tk.Frame(root, padx=10, pady=10)
frame.pack(expand=True, fill=tk.BOTH)

title_label = tk.Label(frame, text="Caesar Cipher Encryption and Decryption", font=("Helvetica", 16, "bold"))
title_label.grid(row=0, column=0, columnspan=2, pady=10)

input_label = tk.Label(frame, text="Enter your message:")
input_label.grid(row=1, column=0, sticky=tk.W, pady=5)
input_text = tk.Text(frame, height=5, width=40)
input_text.grid(row=2, column=0, columnspan=2, pady=5)

shift_label = tk.Label(frame, text="Enter shift value:")
shift_label.grid(row=3, column=0, sticky=tk.W, pady=5)
shift_value = tk.Entry(frame)
shift_value.grid(row=3, column=1, pady=5)

button_frame = tk.Frame(frame)
button_frame.grid(row=4, column=0, columnspan=2, pady=10)

encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt_message, width=15)
encrypt_button.grid(row=0, column=0, padx=5)

decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_message, width=15)
decrypt_button.grid(row=0, column=1, padx=5)

clear_button = tk.Button(button_frame, text="Clear", command=clear_fields, width=15)
clear_button.grid(row=0, column=2, padx=5)

output_label = tk.Label(frame, text="Output:")
output_label.grid(row=5, column=0, sticky=tk.W, pady=5)
output_text = tk.Text(frame, height=5, width=40)
output_text.grid(row=6, column=0, columnspan=2, pady=5)

# Start the main loop
root.mainloop()
