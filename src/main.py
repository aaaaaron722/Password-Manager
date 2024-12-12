import tkinter as tk
from tkinter import messagebox
from tkinter import PhotoImage
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from random import choice, shuffle
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
    else:
        return None

def decrypt(algorithm, ciphertext, nonce, tag):
    if algorithm == "AES":
        return AES_decryption(ciphertext, nonce, tag)
    elif algorithm == "DES":
        return DES_decryption(ciphertext, nonce, tag)
    else:
        return "Invalid algorithm selected"

def add():
    # accepting input from the user
    username = entryName.get()
    # accepting password input from the user
    password = entryPassword.get()
    if len(username) == 0 or len(password) == 0:
        messagebox.showwarning(title="Warning", message="Please fill up the field")
    else:
        algorithm = value.get()
        encryption_result = encrypt(algorithm, password)
        is_ok = messagebox.askokcancel(title="Password Check",
                message=f"Your information : \nUsername : {username}\nPassword : {password}")
        if encryption_result and is_ok:
            ciphertext, nonce, tag = encryption_result
            password_data_list = []
            password_data_list.append([username, ciphertext, nonce, tag])
            with open("passwords.csv", 'a', newline="") as f:
                password_writer = csv.writer(f) #create a writer
                password_writer.writerows(password_data_list) #writer writes data
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
                if len(row) == 4:
                    passwords[row[0]] = (row[1], row[2], row[3])
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
        ciphertext, nonce, tag  = passwords[username]
        decryption_result = decrypt(algorithm, ciphertext, nonce, tag)
        messagebox.showinfo("Passwords", f"Password for {username} is {decryption_result}")
    else:
        messagebox.showinfo("Passwords", "EMPTY LIST!!")


def getlist():
    # creating a dictionary
    passwords = load_passwords()
    if passwords:
        mess = "List of passwords:\n"
        for username, (ciphertext, nonce, tag) in passwords.items():
            algorithm = value.get()
            decryption_result = decrypt(algorithm, ciphertext, nonce, tag)
            # generating a proper message
            mess += f"Password for {username} is {decryption_result}\n"
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
            for user, (ciphertext, nonce, tag) in temp_passwords.items():
                password_writer.writerow([user, ciphertext, nonce, tag]) #writer writes data
        messagebox.showinfo("Success", f"User {username} deleted successfully!")
    else:
        messagebox.showinfo("Error", f"No such user: {username}")

def AES_encryption(password):
    #produce AES cipher object
    cipher = AES.new(key_aes, AES.MODE_EAX)
    #produce ciphertext and tag
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(nonce).decode('utf-8'), base64.b64encode(tag).decode('utf-8')
def AES_decryption(ciphertext, nonce, tag):
    ciphertext = base64.b64decode(ciphertext)
    nonce = base64.b64decode(nonce)
    tag = base64.b64decode(tag)
    
    cipher = AES.new(key_aes, AES.MODE_EAX, nonce=nonce)
    
    try:
        plaintext = cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return plaintext.decode('utf-8')
    except ValueError:
        return "Key incorrect or message corrupted"
    
def DES_encryption(plain_text):
    cipher = DES.new(key_des, DES.MODE_EAX)
    nonce = cipher.nonce  # 生成的隨機數
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(nonce).decode('utf-8'), base64.b64encode(tag).decode('utf-8')

def DES_decryption(ciphertext, nonce, tag):
    ciphertext = base64.b64decode(ciphertext)
    nonce = base64.b64decode(nonce)
    tag = base64.b64decode(tag)

    cipher = DES.new(key_des, DES.MODE_EAX, nonce=nonce)

    try:
        plaintext = cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return plaintext.decode('utf-8')
    except ValueError:
        return "Key incorrect or message corrupted"   

def random_password():
    numbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    symbols = ["~", "!", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+"]
    u_letters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    l_letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

    password_numbers = [choice(numbers) for _ in range(3)]
    password_symbols = [choice(symbols) for _ in range(3)]
    password_u_letters = [choice(u_letters) for _ in range(2)]
    password_l_letters = [choice(l_letters) for _ in range(2)]

    password_list = password_numbers + password_symbols + password_u_letters + password_l_letters
    shuffle(password_list)
    randomPassword = "".join(password_list)
    entryPassword.delete(0, tk.END)
    entryPassword.insert(0, randomPassword)  

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
    
    #OptionList
    labelMenu = tk.Label(app, text="ALGORITHM:")
    labelMenu.grid(row=2, column=0, padx=10, pady=5)
    
    OptionList = ['AES', 'DES']
    value = tk.StringVar()
    value.set(' ')
    menu = tk.OptionMenu(app, value, *OptionList)
    menu.grid(row=2, column=1, padx=15, pady=8, sticky="we")
    
    # Add button
    buttonAdd = tk.Button(app, text="Add", command=add, activeforeground='#f00',font=('Arial',20,'bold'))
    buttonAdd.grid(row=3, column=0, ipadx=10, ipady=5, sticky="we")

    # Get button
    buttonGet = tk.Button(app, text="Get", command=get, activeforeground='#f00',font=('Arial',20,'bold'))
    buttonGet.grid(row=3, column=1, ipadx=15, ipady=5, sticky="we")

    # List Button
    buttonList = tk.Button(app, text="List", command=getlist, activeforeground='#f00',font=('Arial',20,'bold'))
    buttonList.grid(row=4, column=0, ipadx=10, ipady=5, sticky="we")

    # Delete button
    buttonDelete = tk.Button(app, text="Delete", command=delete, activeforeground='#f00',font=('Arial',20,'bold'))
    buttonDelete.grid(row=4, column=1,ipadx=15, ipady=5 , sticky="we")

    
    app.mainloop()
    
    