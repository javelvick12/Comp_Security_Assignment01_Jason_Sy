#Password Brute Force Cracker by Jason Velvick and Sy Pretto
from string import ascii_lowercase as letters
from itertools import product
from random import shuffle
from time import time
import hashlib, os
from passlib.hash import pbkdf2_sha256




def sha256_handler(pass_list: list, file: str):
    """
    Brute force hashes in SHA256 file.

    :param pass_list: Passwords to try
    :param file: Path to text file containing SHA256 hashes
    :return: Cracked Passwords found in file
    """
    attempts = 0
    start_time = time()
    found_passwords = set()

    with open(file, 'r') as hash_file:
        for line in hash_file:
            if not line.strip():
                continue
            salt, password_hash = line.strip().split('$')
            salt_bytes = bytes.fromhex(salt)
            for password in pass_list:
                attempts += 1
                candidate_hash = hashlib.sha256(salt_bytes + password.encode("utf-8")).hexdigest()
                if candidate_hash == password_hash:
                    end_time = time()
                    print(f"[+] Found password: {password} in {attempts} attempts inside of file {file}. Took {round((end_time - start_time), 2)} seconds.")
                    found_passwords.add(password)
    return found_passwords
 

def pbkdf2_handler(pass_list: list, file: str):
    """
    Processes pbkdf2-SHA256 files attempts to brute force. WILL TIMEOUT.

    :param pass_list: list of passwords
    :param file: path to file
    :return: set of plaintext passwords and attempts taken. WILL TIMEOUT for testing.
    """

    TIMEOUT= 10.0
    attempts = 0
    start_time = time()
    found_passwords = set()

    with open(file, 'r') as hash_file:
        for lineno, raw in enumerate(hash_file, start=1):
            line = raw.strip()
            if not line:
                continue

            per_hash_start = time()
            timed_out = False
            for password in pass_list:
                if (time() - per_hash_start) >= TIMEOUT:
                    timed_out = True
                    break

                attempts += 1
                try:
                    if pbkdf2_sha256.verify(password, line):
                        end_time = time()
                        print(f"[+]{file}: Found Password: {password} in {attempts} attempts. Took {round((end_time - start_time), 2)}s")
                        found_passwords.add(password)
                        break
                except Exception as e:
                    print(f"{file}: Invalid line: {lineno}")
                    break

            if timed_out and (password not in found_passwords):
                elapsed = round(time() - per_hash_start, 2)
                print(f"[~] Timeout on {file} line {lineno} after {elapsed}s and "
                      f"{attempts} total attempts so far.")

    return found_passwords


def hash_reader(pass_list: list):
    """
    Discover and process all hash files in the current directory. Iterates
    through the files in current directory. If file contains "sha256) pass
    to handler. If filename contains Pbkdf2 pass to pbkdf2 handler.

    :param pass_list: Password list
    """
    program_dir = os.path.dirname(__file__)
    entries = os.listdir(program_dir)
    for file in entries:
        if "sha256" in file:
            found_passwords = sha256_handler(pass_list, file)
            if "hash1" in file:
                file_name = "password1.txt"
            elif "hash2" in file:
                file_name = "password2.txt"
            with open(file_name, 'w') as f:
                for password in found_passwords:
                    f.write(password + "\n")

        elif "pbkdf2" in file:
            pbkdf2_handler(pass_list, file)


def main():
    """
    Main function, generates all 5-character lowercase strings.
    """
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