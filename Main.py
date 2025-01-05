import random , string , os , getpass , pyperclip , json
from aes_256 import aes_encrypt, aes_decrypt, key_expansion, key

MASTER_KEY_FILE = "master_key.enc"

#creating the master key file: 
def create_file():
    if not os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "a") as file:
            json.dump({}, file)
        print("Master Key File Created!")
        

#ensuring the byte length is 16 bytes for AES-256.
def byte_len_16(user_string: str) -> bytes :
    user_string_bytes = user_string.encode('utf-8')

    if len(user_string_bytes) > 16:
        user_string_bytes = user_string_bytes[:16]
    
    if len(user_string_bytes) < 16 :
        padding_length = 16 - len(user_string_bytes)
        padding = bytes([0] * padding_length)
        return user_string_bytes + padding
    return user_string_bytes

#defining the sign_up process:
def sign_up():
    signup_username = input("Please enter your username:", )
    master_key = getpass.getpass("Please Enter your Master Key:", )
    confirm_key = getpass.getpass("Please Enter the master key again to confirm:", )

    if master_key != confirm_key:
        print("Entries do not match. Please try again!")
        return
    
    print("Saving The Credentials..")
    

#converting the master_key to 16 bytes:
    padded_mk = byte_len_16(master_key)
    
    try:
        # Encrypting the master key using AES-256:
        encrypted_key = aes_encrypt(padded_mk,key)

         #aes_encrypt is giving a list, so changing it to bytes:
        if isinstance(encrypted_key, list):
            encrypted_key = bytes(encrypted_key)

        # Loading the existing data...
        data = {}
        if os.path.exists(MASTER_KEY_FILE):
            with open(MASTER_KEY_FILE, "r") as file:
                try:
                    data = json.load(file)
                except json.JSONDecodeError:
                    print("File was empty or corrupted. Reinitializing.")
                    data = {}

        # linking the credentials after encrypting the key:
        data[signup_username] = encrypted_key.hex()  

        # Saving the updated data back to the file..
        with open(MASTER_KEY_FILE, "w") as file:
            json.dump(data, file, indent=4)

        print(f"Username and master key saved successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")


#defining the login process:
def login():
    try:
        #Loading existing data from the file..
        if not os.path.exists(MASTER_KEY_FILE):
            print("No data found. Please sign up first.")
            return

        with open(MASTER_KEY_FILE, "r") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                print("File is empty. Please sign up first.")
                return

        #asking the user for their username to check if their account exists:
        login_username = input("Please enter your username: ")

        if login_username in data:
            master_key = getpass.getpass("Please enter your Master Key: ")
            padded_mk = byte_len_16(master_key)

            #Encrypting the entered master key using the same method as during sign-up
            encrypted_key = aes_encrypt(padded_mk, key)

            if isinstance(encrypted_key, list):
                encrypted_key = bytes(encrypted_key)

            #Retrieving the stored encrypted key (in hex format)...
            stored_encrypted_key_hex = data[login_username]
            stored_encrypted_key = bytes.fromhex(stored_encrypted_key_hex)

            #DEBUG:
            print(f"Entered Key (Encrypted): {encrypted_key.hex()}")
            print(f"Stored Key: {stored_encrypted_key_hex}")

            # Comparing the encrypted master key with the stored one:
            if encrypted_key == stored_encrypted_key:
                print("Login successful!")
                return login_username
            else:
                print("Invalid master key. Please try again.")
                return None
        else:
            print("Username not found. Please sign up first.")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


CREDS_FILE = "credentials.enc"

#creating the master key file: 
def create_file2():
    if not os.path.exists(CREDS_FILE):
        with open(CREDS_FILE, "a") as file:
            json.dump({}, file)
        print("Credentials File Created!")


#getting the saved master key to use it as the encryption key while saving the creds:
def get_master_key(username):
    if not os.path.exists(MASTER_KEY_FILE):
        raise FileNotFoundError(f"{MASTER_KEY_FILE} not found.")
    
    with open(MASTER_KEY_FILE, "r") as file:
        user_keys = json.load(file)                                              #Loading all user keys.
    
    if username not in user_keys:
        raise ValueError(f"No master key found for user: {username}")
    
    #since the master key is stored as a hex string
    hex_key = user_keys[username]
    
    if len(hex_key) != 32:
        raise ValueError("Master key must be a 16-byte (32-character) hexadecimal string.")
    try:
        key = bytes.fromhex(hex_key)                                             #Converting from hex to bytes.
    except ValueError:
        raise ValueError("Invalid hexadecimal characters in master key.")
    
    #Extending the 16-byte key to 32 bytes by duplication since AES-256 needs a 32 byte key for encryption.
    extended_key = key + key
    return extended_key


#defining the Function to add credentials linked to a user:
def add(username):
    website = input("Enter the website name: ")
    username_input = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    padded_password = password.ljust(16)[:16].encode()  

    encryption_key = get_master_key(username)
    
    # Encrypting the password..
    encrypted_password = aes_encrypt(padded_password, encryption_key)

    if isinstance(encrypted_password, list):
                encrypted_password = bytes(encrypted_password)
            
    #print("Encrypted password", encrypted_password)    #DEBUG..
    
    # Loading existing credentials:
    if not os.path.exists(CREDS_FILE):
        creds_data = {}
    else:
        with open(CREDS_FILE, "r") as file:
            creds_data = json.load(file)
    
  #linking the creds to that particular user and saving it..

    if username not in creds_data:
        creds_data[username] = {}

    if website not in creds_data[username]:
        creds_data[username][website] = []

    creds_data[username][website] = {
        "username": username_input,
        "password": encrypted_password.hex()
    }

    with open(CREDS_FILE, "w") as file:
        json.dump(creds_data, file, indent=4)
    
    print(f"Credentials for {website} added successfully for {username}!")


#defining the Function to retrieve the credentials linked to a user:
def retrieve(username):
    website = input("Enter the website name to retrieve credentials: ")

    #Checking if the credentials file exists..
    if not os.path.exists(CREDS_FILE):
        print(f"No credentials found. {CREDS_FILE} does not exist.")
        return

    #Loading credentials from the file..
    try:
        with open(CREDS_FILE, "r") as file:
            creds_data = json.load(file)
    except json.JSONDecodeError:
        print(f"{CREDS_FILE} is empty or corrupted.")
        return


    if username not in creds_data:
        print("No credentials found for this user.")
        return

    user_creds = creds_data[username]

    if website not in user_creds:
        print(f"No entries found for this website: {website}")
        return

    # Retrieving the entry for the specified website:
    website_entry = user_creds[website]

    try:
        # Retrieve the decryption key for the logged-in user
         decryption_key = get_master_key(username)

         encrypted_password_hex = website_entry["password"]
         encrypted_password = bytes.fromhex(encrypted_password_hex)

        #DEBUG:
         #print(f"Encrypted password hex: {encrypted_password_hex}")
         #print(f"Decryption key: {decryption_key}")
         #print(f"Encrypted password bytes: {encrypted_password}")

         expanded_key = key_expansion(decryption_key)
        #print("Expanded Key (debug):", expanded_key)

         decrypted_password = aes_decrypt(encrypted_password, expanded_key)
         #print(f"Decrypted password INT: {decrypted_password}")

         decrypted_password_bytes = bytes(decrypted_password)
         #print(f"Decrypted password BYTES: {decrypted_password_bytes}")

         padded_password = decrypted_password_bytes.decode('utf-8', errors='ignore')
         original_password = padded_password.rstrip()

        #Display the retrieved entry
         print("\nRetrieved Credentials:")
         print(f"Website: {website}")
         print(f"Username: {website_entry['username']}")
         print(f"Password: {original_password}") 
    except Exception as e:
         print(f"An error occurred during decryption: {e}")


#defining the Function to delete credentials linked to a user:
def delete(username):
    website = input("Enter the website name to delete credentials: ")

    if not os.path.exists(CREDS_FILE):
        print(f"No credentials found. {CREDS_FILE} does not exist.")
        return

    try:
        with open(CREDS_FILE, "r") as file:
            creds_data = json.load(file)
    except json.JSONDecodeError:
        print(f"{CREDS_FILE} is empty or corrupted.")
        return

    if username not in creds_data:
        print("No credentials found for this user.")
        return

    user_creds = creds_data[username]

    # Check if the website exists in the user's credentials
    if website not in user_creds:
        print(f"No entries found for this website: {website}")
        return

    # Retrieving the entry for the specified website
    website_entries = user_creds[website]

    # If multiple entries exist, prompting for username
    if isinstance(website_entries, list):  
        print(f"Multiple entries found for {website}.")
        for idx, entry in enumerate(website_entries):
            print(f"{idx + 1}. Username: {entry['username']}")

        selected_index = int(input("Enter the number corresponding to the username you want to delete: ")) - 1

        if selected_index < 0 or selected_index >= len(website_entries):
            print("Invalid selection.")
            return

        selected_entry = website_entries[selected_index]
    else:
        selected_entry = website_entries

    # Displaying the selected entry and asking for confirmation...
    print("\nSelected Entry:")
    print(f"Website: {website}")
    print(f"Username: {selected_entry['username']}")

    confirm_delete = input("Are you sure you want to delete this entry? (yes/no): ").strip().lower()

    if confirm_delete == "yes":
        #Deleting the entry from the user's credentials
        if isinstance(website_entries, list):
            website_entries.remove(selected_entry)  
            if len(website_entries) == 0:
                del user_creds[website]  
        else:
            del user_creds[website]  

        #Saving the updated credentials back to the file..
        try:
            with open(CREDS_FILE, "w") as file:
                json.dump(creds_data, file, indent=4)
            print(f"Entry for {website} deleted successfully.")
        except Exception as e:
            print(f"An error occurred while saving the file: {e}")
    else:
        print("Deletion canceled. Returning to menu.")


#defining a function to generate a random but strong password and copying it to the clipboard:
def generate(length):

    password = [
        random.choice(string.punctuation),
    ]

    rem_chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    password += [random.choice(rem_chars) for _ in range(length - 1)]

#shuffling so that the order is not following similar pattern and isn't easy to guess.
    random.shuffle(password)
    generated_password = ''.join(password)

    print(f"Generated Password: {generated_password}")

    pyperclip.copy(generated_password)
    print("Password copied to clipboard!")

    return generated_password


#Defining the actual flow of my application: 

if __name__ == "__main__":
    print("Welcome to your Password Manager. How may I help you?")
    create_file2() 
    
    while True:
        print("\nMain Menu:")
        print("1. Sign Up")
        print("2. Login")
        print("3. Exit the Application")

        choice = input("Enter your choice: ")

        if choice == "1":
            sign_up()
        elif choice == "2":
            print("Login to your existing account!")
            logged_in_user = login() 
            if logged_in_user:
               print(f"Welcome, {logged_in_user}!")
               while True:
                   print("\nMenu:")
                   print("1. Add Credentials")
                   print("2. Retrieve Credentials")
                   print("3. Delete Credentials")
                   print("4. Generate a strong password")
                   print("5. Return to the Main Menu")
                   choice = input("Enter your choice: ")

                   if choice == "1":
                      add(logged_in_user)
                   elif choice == "2":
                      retrieve(logged_in_user)
                   elif choice == "3":
                      delete(logged_in_user)
                   elif choice == "4":
                       length = input("What should be the length of your password? :", )
                       length = int(length)
                       generate(length)
                   elif choice == "5":
                       print("Returning to the Main Menu!")
                       break
                   else:
                       print("oops, Invalid choice. Please select from the options given in the menu.")
        
        elif choice == "3":
            print("Closing the application.Bye Bye!!")
            break
        else:
            print("oops, Invalid Choice. Please choose from the given options.")


#THE END!