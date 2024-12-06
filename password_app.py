import os
from cryptography.fernet import Fernet
import base64
import hashlib

# Files
ENCRYPTED_FILE = "encrypted_passwords.txt"
DECRYPTED_FILE = "decrypted_passwords.txt"

def generate_key(master_password):
    hashed_password = hashlib.sha256(master_password.encode()).digest()
    key = base64.urlsafe_b64encode(hashed_password)
    return key

def store_password(master_password, account, password):
    key = generate_key(master_password)
    cipher_suite = Fernet(key)
    
    # Encrypting the master password, account, and password
    encrypted_master_password = cipher_suite.encrypt(master_password.encode())
    encrypted_account = cipher_suite.encrypt(account.encode())
    encrypted_password = cipher_suite.encrypt(password.encode())
    
    # Storing encrypted data in the encrypted file
    with open(ENCRYPTED_FILE, 'a') as enc_file:
        enc_file.write(f"{encrypted_master_password.decode()}:{encrypted_account.decode()}:{encrypted_password.decode()}\n")
    
    # Storing decrypted data (including master password) in the decrypted file (for reference)
    with open(DECRYPTED_FILE, 'a') as dec_file:
        dec_file.write(f"Master Password: {master_password}, Account: {account}, Password: {password}\n")
    
    print("Password stored successfully!")

def retrieve_password(master_password, account):
    key = generate_key(master_password)
    cipher_suite = Fernet(key)
    
    if not os.path.exists(ENCRYPTED_FILE):
        print("No encrypted data found!")
        return
    
    with open(ENCRYPTED_FILE, 'r') as file:
        lines = file.readlines()
        for line in lines:
            encrypted_master_password, encrypted_account, encrypted_password = line.strip().split(':')
            try:
                decrypted_master_password = cipher_suite.decrypt(encrypted_master_password.encode()).decode()
                decrypted_account = cipher_suite.decrypt(encrypted_account.encode()).decode()
                if decrypted_account == account and decrypted_master_password == master_password:
                    decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                    print(f"Password for {account}: {decrypted_password}")
                    return
            except:
                continue
    print("Account not found!")

def delete_password(master_password, account):
    key = generate_key(master_password)
    cipher_suite = Fernet(key)
    
    if not os.path.exists(ENCRYPTED_FILE):
        print("No encrypted data found!")
        return
    
    with open(ENCRYPTED_FILE, 'r') as file:
        lines = file.readlines()
    
    with open(ENCRYPTED_FILE, 'w') as file:
        for line in lines:
            encrypted_master_password, encrypted_account, encrypted_password = line.strip().split(':')
            try:
                decrypted_master_password = cipher_suite.decrypt(encrypted_master_password.encode()).decode()
                decrypted_account = cipher_suite.decrypt(encrypted_account.encode()).decode()
                if decrypted_account != account:
                    file.write(line)
            except:
                continue
    print(f"Password for {account} deleted successfully!")

def display_all_passwords(master_password):
    key = generate_key(master_password)
    cipher_suite = Fernet(key)
    
    if not os.path.exists(ENCRYPTED_FILE):
        print("No encrypted data found!")
        return
    
    with open(ENCRYPTED_FILE, 'r') as file:
        lines = file.readlines()
        for line in lines:
            encrypted_master_password, encrypted_account, encrypted_password = line.strip().split(':')
            try:
                decrypted_master_password = cipher_suite.decrypt(encrypted_master_password.encode()).decode()
                decrypted_account = cipher_suite.decrypt(encrypted_account.encode()).decode()
                decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                print(f"Master Password: {decrypted_master_password}, Account: {decrypted_account}, Password: {decrypted_password}")
            except:
                continue

# Main program
def main():
    print("Welcome to the Secure Password Manager!")
    
    master_password = input("Enter your master password: ")
    
    while True:
        choice = input("\nOptions:\n1. Store Password\n2. Retrieve Password\n3. Delete Password\n4. Display All Passwords\n5. Exit\nChoose an option: ")
        
        if choice == '1':
            account = input("Enter the account name: ")
            password = input("Enter the password: ")
            store_password(master_password, account, password)
        
        elif choice == '2':
            account = input("Enter the account name to retrieve the password: ")
            retrieve_password(master_password, account)
        
        elif choice == '3':
            account = input("Enter the account name to delete the password: ")
            delete_password(master_password, account)
        
        elif choice == '4':
            print("\nDisplaying all stored passwords:")
            display_all_passwords(master_password)
        
        elif choice == '5':
            print("Exiting the password manager.")
            break
        else:
            print("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
