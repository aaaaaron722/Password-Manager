import tkinter as tk
from tkinter import messagebox
from tkinter import PhotoImage
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets
import csv
import base64
import os

# Keys for AES and DES
key_aes = b'Sixteen byte key'
key_des = b'8bytekey'

# General encryption and decryption function
def encrypt(algorithm, password):
    if algorithm == "AES":
        return AES_encryption(password)
    elif algorithm == "DES":
        return DES_encryption(password)
    elif algorithm == "RSA":
        return RSA_encryption(password)
    else:
        return None

def decrypt(algorithm, ciphertext, nonce, tag):
    if algorithm == "AES":
        return AES_decryption(ciphertext, nonce, tag)
    elif algorithm == "DES":
        return DES_decryption(ciphertext, nonce, tag)
    elif algorithm == "RSA":
        return RSA_decryption(ciphertext, nonce, tag)
    else:
        return "Invalid algorithm selected"

def add():
    username = entryName.get()
    password = entryPassword.get()
    url = entryUrl.get()
    if len(username) == 0 or len(password) == 0 or len(url) == 0:
        messagebox.showwarning(title="Warning", message="Please fill up the field")
    else:
        algorithm = value.get()
        encryption_result = encrypt(algorithm, password)
        is_ok = messagebox.askokcancel(title="Password Check",
                message=f"Your information : \nUsername : {username}\nPassword : {password}\nUrl : {url}")
        if encryption_result and is_ok:
            ciphertext, nonce, tag = encryption_result
            password_data_list = [[username, url, ciphertext, nonce, tag]]
            with open("passwords.csv", 'a', newline="") as f:
                csv.writer(f).writerows(password_data_list) #writer writes data #create a writer
            messagebox.showinfo("Success", "Password added !!")
            entryName.delete(0, tk.END)
            entryPassword.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Please select a valid encryption algorithm")
            
def load_passwords():
    passwords = {}
    try:
        with open("passwords.csv", 'r', newline='') as f:
            password_reader = csv.reader(f) #create a reader to read file
            for row in password_reader:
                if len(row) == 5:
                    passwords[row[0]] = (row[1], row[2], row[3], row[4])
                else:
                    print(f"Invalid data format in line: {row}")
    except FileNotFoundError:
        print("No passwords found")
    except Exception as e:
        print(f"An error occured: {e}")
    return passwords
                
def get():
    # accepting input from the user
    username = entryName.get()
    # creating a dictionary to store the data in the form of key-value pairs
    passwords = load_passwords()
    if username in passwords:
        algorithm = value.get()
        url, ciphertext, nonce, tag  = passwords[username]
        decryption_result = decrypt(algorithm, ciphertext, nonce, tag)
        messagebox.showinfo("Passwords", f"Username : {username}\nPassword : {decryption_result}\nUrl : {url}")
    else:
        messagebox.showinfo("Passwords", "EMPTY LIST!!")


def getlist():
    # creating a dictionary
    passwords = load_passwords()
    if passwords:
        mess = "List of passwords:\n"
        for username, (url, ciphertext, nonce, tag) in passwords.items():
            algorithm = value.get()
            decryption_result = decrypt(algorithm, ciphertext, nonce, tag)
            # generating a proper message
            mess += f"[{username}] : [{decryption_result}] : [{url}]" + " " * 15 + "\n"
        # Showing the message
        messagebox.showinfo("Passwords", mess)
    else:
        messagebox.showinfo("Passwords", "Empty List !!")


def delete():
    # accepting input from the user
    username = entryName.get()

    # creating a temporary list to store the data
    temp_passwords = load_passwords()
    if username in temp_passwords:
        del temp_passwords[username] #delete passwords[username]
        with open("passwords.csv", 'w', newline="") as f:
            password_writer = csv.writer(f) #create a writer
            for user, (url, ciphertext, nonce, tag) in temp_passwords.items():
                password_writer.writerow([user, url, ciphertext, nonce, tag]) #writer writes data
        messagebox.showinfo("Success", f"User {username} deleted successfully!")
    else:
        messagebox.showinfo("Error", f"No such user: {username}")
        

def encryption_helper(algorithm, password, key, mode):
    cipher = algorithm.new(key, mode)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(nonce).decode('utf-8'), base64.b64encode(tag).decode('utf-8')

def decryption_helper(algorithm, ciphertext, nonce, tag, key, mode):
    try:
        ciphertext = base64.b64decode(ciphertext)
        nonce = base64.b64decode(nonce)
        tag = base64.b64decode(tag)
        
        cipher = algorithm.new(key, mode, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return plaintext.decode('utf-8')
    except ValueError as e:
        return f"Failed: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"
    
def AES_encryption(password):
    return encryption_helper(AES, password, key_aes, AES.MODE_EAX)

def AES_decryption(ciphertext, nonce, tag):
    return decryption_helper(AES, ciphertext, nonce, tag, key_aes, AES.MODE_EAX)

def DES_encryption(password):
    return encryption_helper(DES, password, key_des, DES.MODE_EAX)

def DES_decryption(ciphertext, nonce, tag):
    return decryption_helper(DES, ciphertext, nonce, tag, key_des, DES.MODE_EAX)
    

def check_and_generate_rsa_keys():
    if not os.path.exists('private.pem') or not os.path.exists('public.pem'):
        print("RSA keys not found, generating new keys...")
        generate_rsa_keys()
    else:
        print("RSA keys already exist, loading existing keys...")

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open('private.pem', 'wb') as f:
        f.write(private_key)
    with open('public.pem', 'wb') as f:
        f.write(public_key)
    
    return private_key, public_key

# Load RSA keys
def load_rsa_keys():
    try:
        with open('private.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())
        with open('public.pem', 'rb') as f:
            public_key = RSA.import_key(f.read())
        return private_key, public_key
    except FileNotFoundError:
        print("RSA key files not found. Please generate them.")
        return None, None
    except Exception as e:
        print(f"Error loading RSA keys: {e}")
        return None, None

# RSA encryption function
def RSA_encryption(password):
    private_key, public_key = load_rsa_keys()
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(password.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8'), '', ''  # nonce and tag are not used in RSA

# RSA decryption function
def RSA_decryption(ciphertext, nonce, tag):
    private_key, public_key = load_rsa_keys()
    cipher = PKCS1_OAEP.new(private_key)
    try:
        plaintext = cipher.decrypt(base64.b64decode(ciphertext))
        return plaintext.decode('utf-8')
    except ValueError:
        return "Key incorrect or message corrupted"


def random_password():
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+-"
    password = ''.join(secrets.choice(characters) for i in range(12))
    entryPassword.delete(0, tk.END)
    entryPassword.insert(0, password)

if __name__ == "__main__":
    app = tk.Tk()
    app.geometry("450x270")
    app.title("Password Manager")
    app.iconphoto(True, PhotoImage(file="icons/icons8-tools-96.png"))
    
    # Username block
    labelName = tk.Label(app, text="USERNAME:")
    labelName.grid(row=0, column=0, padx=15, pady=15)
    entryName = tk.Entry(app)
    entryName.grid(row=0, column=1, padx=15, pady=15)

    # Password block
    labelPassword = tk.Label(app, text="PASSWORD:")
    labelPassword.grid(row=1, column=0, padx=10, pady=5)
    entryPassword = tk.Entry(app)
    entryPassword.grid(row=1, column=1, padx=10, pady=5)
    
    
    #random button
    randomButton = tk.Button(text="Random", width=5, command=random_password)
    randomButton.grid(row=1, column=2)
    
    #Url block
    labelUrl = tk.Label(app, text="Url:")
    labelUrl.grid(row=2, column=0, padx=10, pady=5)
    entryUrl = tk.Entry(app)
    entryUrl.grid(row=2, column=1, padx=10, pady=5)
    
    #OptionList
    labelMenu = tk.Label(app, text="ALGORITHM:")
    labelMenu.grid(row=3, column=0, padx=10, pady=5)
    
    OptionList = ['AES', 'DES', 'RSA']
    value = tk.StringVar()
    value.set(' ')
    menu = tk.OptionMenu(app, value, *OptionList)
    menu.grid(row=3, column=1, padx=15, pady=8, sticky="we")
    
    # Add button
    buttonAdd = tk.Button(app, text="Add", command=add, activeforeground='#f00',font=('Arial',20,'bold'))
    buttonAdd.grid(row=4, column=0, ipadx=10, ipady=5, sticky="we")

    # Get button
    buttonGet = tk.Button(app, text="Get", command=get, activeforeground='#f00',font=('Arial',20,'bold'))
    buttonGet.grid(row=4, column=1, ipadx=15, ipady=5, sticky="we")

    # List Button
    buttonList = tk.Button(app, text="List", command=getlist, activeforeground='#f00',font=('Arial',20,'bold'))
    buttonList.grid(row=5, column=0, ipadx=10, ipady=5, sticky="we")

    # Delete button
    buttonDelete = tk.Button(app, text="Delete", command=delete, activeforeground='#f00',font=('Arial',20,'bold'))
    buttonDelete.grid(row=5, column=1,ipadx=15, ipady=5 , sticky="we")

    
    app.mainloop()
    
    