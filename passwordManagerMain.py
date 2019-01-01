import sys
from Crypto.Cipher import AES 
from Crypto.Util import Counter
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import json
import pyperclip
import time
import getpass 

passDict = {}
dictFile = 'passDict.json'
characters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9','+','-']

# user chooses whether to input a new password or search for a password the first time he/she opens the application
def user_options_first():
	print("\n")
	print("Hello.")
	print("Welcome to the Secure Password Manager.")
	print("Would you like to: input new account information or search for a password?")
	print("\n")
	choice = input("Enter INPUT or SEARCH (or EXIT): ")
	print("You chose: " + str(choice))
	return choice
	
# user chooses whether to input a new password or search for a password
def user_options_second():
	choice = input("Enter INPUT or SEARCH (or EXIT): ")
	print("You chose: " + str(choice))
	return choice

# what to do after the user enters a choice
def next_steps(choice):
	# the user can enter "INPUT", "SEARCH", or "EXIT"
	while (True):
		if choice == "INPUT":
			user_input()
			print("\n")
			print("Would you like to run another action?")
			choice = input("Enter INPUT, SEARCH, or EXIT: ")
		elif choice == "SEARCH":
			user_search()
			print("\n")
			print("Would you like to run another action?")
			choice = input("Enter INPUT, SEARCH, or EXIT: ")
		elif choice == "EXIT":
			print("You have ended your session.")
			break 
		else:
			# user enters invalid command
			print("Please re-enter a valid command.")
			choice = input("Enter INPUT, SEARCH, or EXIT: ")

def shift_in_bit(b, B):
	if (b == 0):
		B = 2*B
	elif (b ==  1):
		B = 2*B + 1
	return B

def test_bit(i, B):
	for j in range(i): B = B//2
	if B%2 == 0: return 0
	else: return 1

def encode_pwd(s): # s must be a string with length that is a multiple of 4
	B = 0x00
	for c in s:
		c_index = characters.index(c)
		for i in range(6):
			if test_bit(5-i, c_index): B = shift_in_bit(1, B)
			else: B = shift_in_bit(0, B)
	return B.to_bytes(3*len(s)//4, byteorder='big')

def decode_pwd(B): # B must be a byte string with length that is multiple of 3
	L = len(B)
	s = 0x00
	for i in range(L):
		for j in range(8):
			B_index = 8*i + j
			if B_index%6 == 0:
				s = shift_in_bit(0, s)
				s = shift_in_bit(0, s)
			if test_bit(7-j, B[i]): s = shift_in_bit(1, s)
			else: s = shift_in_bit(0, s)
	s = s.to_bytes(4*L//3, byteorder='big')
	
	z = ''
	for i in range(len(s)): z += characters[s[i]]
	return z

# generate subpassword
def generate(length):
	password = ""
	for i in range (length):
		index = random.randint(0,63)
		password = password + characters[index] 
	return password


# user inputs account information
def user_input():
	global passDict 

	print("Please enter your account information.")
	account_name = input("Account name: ")
	url = input("Website URL: ")

	# generate sub password
	subPass = encode_pwd(generate(12))
	# generate master key
	masterKey = generate_master_key(user_master_input())

	# generate nonce and counter
	nonce = get_random_bytes(8)
	ctr = Counter.new(64, prefix=nonce, initial_value=0)

	cipher = AES.new(masterKey, AES.MODE_CTR, counter=ctr)

	# encrypt subpassword
	subPass = cipher.encrypt(subPass)

	securelyDelete(masterKey) # delete master key

	nonce_to_store = nonce.hex()
	subPass_to_store = subPass.hex()

	# store subpassword and nonce
	passDict[url] = {"key": subPass_to_store, "counter": nonce_to_store}
	passDict[account_name] = {"key": subPass_to_store, "counter": nonce_to_store}

	# store dictionary in json
	with open(dictFile, 'w') as outDict:
		json.dump(passDict, outDict)

# user searches for a password
def user_search():
	global passDict

	while (True):
		search_by = input("Enter account name or URL to search for password (or BACK): ")

		if search_by == "BACK": # user returns to other options
			next_steps(user_options_second())
			break
		
		try:
			stored_subPass = passDict.get(search_by)["key"]  

			# get nonce and sub password to decrypt
			subPass_encrypted = bytes.fromhex(stored_subPass)
			stored_nonce = passDict.get(search_by)["counter"]
			nonce = bytes.fromhex(stored_nonce)
			subCtr = Counter.new(64, prefix=nonce, initial_value=0)

			# get salt 
			stored_salt = passDict.get("salt")
			salt = bytes.fromhex(stored_salt)
			masterKey = generate_master_key(user_master_input()) # generate master key from salt

			# decrypt subpassword
			cipher = AES.new(masterKey, AES.MODE_CTR, counter=subCtr) 
			subPass = cipher.decrypt(subPass_encrypted)
			securelyDelete(masterKey) # delete masterkey

			subPass = decode_pwd(subPass)

			# copying 
			pyperclip.copy(subPass)
			print("Password copied to clipboard.")
			subPass = "" # delete subpassword
			time.sleep(10)
			pyperclip.copy('') # clear from clipboard
			print("Clipboard timeout.")
			break

		except TypeError: # user does not enter in a valid account name or url in the dictionary
			print("Please re-enter a valid input.")

# user inputs their master password
def user_master_input():
	print("Please input the master password.")
	bytearray_master_pwd = bytearray() # stored in a bytearray to securely delete later
	bytearray_master_pwd.extend(map(ord, getpass.getpass("Master password: "))) 
 
	# for in class demo, print out password
	# master_pwd = getpass.getpass("Master password: ")
	# print(master_pwd)
	# bytearray_master_pwd.extend(map(ord, master_pwd))

	return bytearray_master_pwd

# generate the master key from the master password and salt
def generate_master_key(bytearray_master_pwd):
	global passDict

	stored_salt = passDict.get("salt") # get the stored salt from the dictionary
	salt = bytes.fromhex(stored_salt)
	pwdkey = PBKDF2(bytearray_master_pwd.decode(), salt, dkLen=16, count=1000) # generate key with PBKDF2
	securelyDelete(bytearray_master_pwd) # delete master password
	bytearray_pwdkey = bytearray(pwdkey) # convert to bytearray to securely delete later

	return bytearray_pwdkey 

#overwriting bytearray 
def securelyDelete(key):
	for i in range(len(key)):
	    key[i] = 0

# main function
def main():
	global passDict

	try:
		with open(dictFile, 'r') as inDict:
			passDict = json.load(inDict)
	except FileNotFoundError: # if the json file does not exist yet, make a new dictionary and salt
		passDict = {}
		salt = get_random_bytes(16)
		salt_to_store = salt.hex()
		passDict["salt"] = salt_to_store

	next_steps(user_options_first())


main()
