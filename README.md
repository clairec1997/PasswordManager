# Password Manager Application
## By Claire Cannatti, Erika Ogino, Catherine Zhao


### We envision the system architecture to work in the following way:

#### Adding a new account

When the user wants to add a new account to be stored in the secure password manager, they are prompted to input the master password, URL and account name. A random sub-password is generated for the new account. Then, a master key is derived from the master password using PBKDF2. This key will be used to encrypt the generated sub-password in AES-CTR mode. Finally, the salt and encrypted sub-password will be stored in a dictionary. 

#### Retrieving a sub-password

When the user wants to access the password for a given account, the user must enter either the URL or account name so that the encrypted sub-password can be retrieved. Then the user must input the master password so that the master key can be derived again to decrypt the sub-password. Once the sub-password is decrypted, it is copied to the clipboard for use. 

### First time users 
run the following code to install necessary packages:  
`pip install -r requirements.txt`