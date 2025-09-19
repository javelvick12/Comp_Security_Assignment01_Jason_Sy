#Password Brute Force Cracker by Jason Velvick and Sy Pretto
from string import ascii_lowercase as letters
from itertools import product
from random import shuffle
from time import time
import hashlib, passlib, os

def sha256_handler(pass_list: list, file: str):
    with open(file, 'r') as hash_file:
        hashes = hash_file.readlines()
        for hash in hashes:
            if hash:
                sep_hash = hash.split('$')
                password_hash = sep_hash[1]
                print("found hash:", password_hash)

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
    hash_reader(all_pass_lex)

if __name__ == "__main__":
    main()