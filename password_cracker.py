#Password Brute Force Cracker by Jason Velvick and Sy Pretto
from string import ascii_lowercase as letters
from itertools import product
from random import shuffle
from time import time
import hashlib, passlib, os

def sha256_handler(pass_list: list, file: str):
    attempts = 0
    with open(file, 'r') as hash_file:
        for line in hash_file:
            if not line.strip():
                continue
            salt, password_hash = line.strip().split('$')

            #brute force
            for password in pass_list:
                attempts += 1
                password_bytes = password.encode()
                candidate_hash = hashlib.sha256(salt.encode() + password_bytes).hexdigest()
                if password_hash == candidate_hash:
                    print(f"Found password: {password} for hash {password_hash} after {attempts} attempts")
                    return

def pbkdf2_handler(pass_list: list, file: str):
    print("pbkdf2 was called")

def hash_reader(pass_list: list):
    program_dir = os.path.dirname(__file__)
    entries = os.listdir(program_dir)
    for file in entries:
        if "sha256" in file:
            sha256_handler(pass_list, file)
        elif "pbkdf2" in file:
            pbkdf2_handler(pass_list, file)


def main():
    # all possible passwords
    all_pass_lex = [''.join(c) for c in product(letters, repeat=5)]
    random_pass_lex = all_pass_lex[:]
    shuffle(random_pass_lex)
    #random order cracking
    hash_reader(random_pass_lex)
    #lexographic order cracking
    #hash_reader(all_pass_lex)

if __name__ == "__main__":
    main()