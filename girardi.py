# Esercizio finale

# ALGORITMI USATI

# -- BLAKE2b -- 
# Scelto perché è il più veloce in software, versione b perché è appositamente
# stato creato per sistemi a 64 bit. 
# -- scrypt --
# KDF necessaria per ottenere una key derivata dalla password dell`utente,
# scelta perché è la migliore a disposizione (pyCryptodome non ha Argon2).
# -- AES-OCB --
# Miglior cifrario simmetrico autenticato.

#
# modules import
#

from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from getpass import getpass
import json
import os.path

#
# KDF
#

# Function that returns a derived 16 bytes key from a string using scrypt.
# -- init Parameters: --
# password: inserted by the user at the beginning of the system
# salt: generated random in save_and_exit() function

# -- scrypt Parameters: -- 
# password, salt, length of key in bytes, N = CPU/Memory cost parameter,
# r = Block size parameter, p = Number of keys

def process_pwd(password, salt):
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    return key

#
# DATA MANAGEMENT FUNCTIONS
#

# function that reads user file, decrypts it using OCB and
# returns a json file containing the credentials of the user 
# -- parameters: --
# path: username hashed with BLAKE2b in log_in() function
# password: inserted by the user at the beginning of the system

def load_data(path, password):
    with open(path, 'rb') as in_file:
        salt = in_file.read(16)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        ciphertext = in_file.read(-1)
    key = process_pwd(password, salt)
    cipher_ocb = AES.new(key, AES.MODE_OCB, nonce)
    data = cipher_ocb.decrypt_and_verify(ciphertext, tag)
    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(f'data not valid: {str(err)}')
    return credentials

# function that takes data, encrypts it using OCB and the key derivated
# from the user's password, and writes all the encryption parameters
# in the user file.
# -- parameters: --
# path: username hashed with BLAKE2b in log_in() function
# password: inserted by the user at the beginning of the system
# credentials: result of the load_data() function

def save_and_exit(path, password, credentials):
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    salt = get_random_bytes(16)
    key = process_pwd(password, salt)
    cipher_ocb = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher_ocb.encrypt_and_digest(data)
    with open(path, 'wb') as out_file:
        out_file.write(salt)
        out_file.write(cipher_ocb.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)

# function that searches an id (query) in the dictionary, if id exist shows the
# credentials stored in it, otherwise add a new id and asks the
# user new credentials.
# parameters:
# query: id inserted by the user in log_in() function
# dic: result of the load_data() function

def search_and_add(query, dic):
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')
            password_n = getpass("Password: ")
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic

#
# LOG IN FUNCTION
#

# function that hashes the username using BLAKE2b to use it as file name
# and controls if it already exists. If it exists calls the load_data()
# function, otherwise asks the user if he wants to add the new username.
# Then asks for credentials to search, if the credentials exists calls
# search_and_add(), otherwise asks the user if he wants to add new credentials.
# -- parameters: --
# username: username inserted by user at the beginning of the system
# password: inserted by the user at the beginning of the system

def log_in(username, password):
    h_obj = BLAKE2b.new(digest_bits=512)
    h_obj.update(bytes(username, 'utf8'))
    path_file = h_obj.hexdigest()
    if os.path.exists(path_file):
        try:
            credentials = load_data(path_file, password)
        except ValueError as err:
            print('Autentication failed')
            return
        except IOError as err:
            print('Error loading data:')
            print(err)
            return
    else:
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}
        else:
            return
    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    while True:
        query = input(prompt)
        if query != '':
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return

# MAIN: 
# asks the user username and password,
# if username is empty terminate the system.

while True:
    print('Insert username and password to load data,')
    print('leave blank and press "enter" to exit.')
    username = input('Username: ')
    if username == '':
        print('Goodbye!')
        exit()
    else:
        password = getpass('Password: ')
        log_in(username, password)

