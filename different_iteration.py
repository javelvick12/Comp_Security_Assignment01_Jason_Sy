from string import ascii_lowercase as letters
from itertools import product
from random import shuffle
from time import time
import hashlib, os
from passlib.hash import pbkdf2_sha256
from statistics import mean


# Config
PASSWORD_LENGTH = 5
PROGRAM_DIR = os.path.dirname(__file__) or os.getcwd()
# filenames expected in same directory
SHA256_FILES = ["sha256_hash1.txt", "sha256_hash2.txt"]
PBKDF2_FILES = ["pbkdf2_hash1.txt", "pbkdf2_hash2.txt"]

#generate candidates
all_pass_lex = [''.join(c) for c in product(letters, repeat=PASSWORD_LENGTH)]


def crack_sha256_single(salt_hex: str, target_hash_hex: str, candidate_list):
    """
    Tries to crack a single SHA256 salted hash by iterating of candidate passwords.

    :param salt_hex: Str representing the salt bytes
    :param target_hash_hex: lowercase hex string
    :param candidate_list: iterable list of passwords to try
    :return: tuple found_passwords, attempts, elapsed seconds
    """

    salt_bytes = bytes.fromhex(salt_hex)
    attempts = 0
    start = time()
    for pwd in candidate_list:
        attempts += 1
        cand_hash = hashlib.sha256(salt_bytes + pwd.encode('utf-8')).hexdigest()
        if cand_hash == target_hash_hex:
            elapsed = time() - start
            return pwd, attempts, elapsed
    return None, attempts,  time() - start

def crack_pbkdf2_single(stored_hash_line: str, candidate_list, timeout=5.0):
    """
    Tries to crack a single pbkdf2-SHA256 stored hash string. Will timeout in
     5 seconds.

    :param stored_hash_line: stored line
    :param candidate_list: iterable list of password strings to try
    :param timeout: default timeout for testing so program won't run for a long time
    :return: tuple found password, attempts, elapsed time, timeout
    """

    stored = stored_hash_line.strip()
    attempts = 0
    start = time()

    for pwd in candidate_list:
        attempts += 1
        if pbkdf2_sha256.verify(pwd, stored):
            return pwd, attempts, time() - start, False
        if time() - start >= timeout:
            return None, attempts, time() - start, True

    return None, attempts, time() - start, False

def process_sha256_file(filepath: str, candidate_list):
    """
    Read SHA256 file and return results and found passwords

    :param filepath: path to sha256 file
    :param candidate_list: ordered candidates
    :return: result list, found passwords
    """

    results = []
    found_passwords = []
    with open(filepath, 'r') as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue
            salt_hex, target_hash = line.split('$',1)
            pwd, attempts, elapsed = crack_sha256_single(salt_hex, target_hash, candidate_list)
            results.append((pwd, attempts, elapsed))
            if pwd is not None:
                found_passwords.append(pwd)
            print(f"[{os.path.basename(filepath)}] line {lineno}: found={pwd} attempts={attempts} time={elapsed:.3f}s")
    return results, found_passwords

def process_pbkdf2_file(filepath: str, candidate_list, timeout=5.0):
    """
    Read pbkdf2 file and returns results any found passwords (will time out)

    :param filepath: path to file
    :param candidate_list: passwords to try
    :param timeout: per hash timeout
    :return: result list, found passwords
    """
    results = []
    found_passwords = []
    with open(filepath, 'r') as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue
            pwd, attempts, elapsed, timed_out = crack_pbkdf2_single(
                line, candidate_list, timeout=timeout
            )
            results.append((pwd, attempts, elapsed, timed_out))
            if pwd is not None:
                found_passwords.append(pwd)
            status = "TIMEOUT" if timed_out and pwd is None else ("FOUND" if pwd else "NOT FOUND")
            print(f"[{os.path.basename(filepath)}] line {lineno}: {status} "
                  f"(attempts={attempts}, time={elapsed:.3f}s)")
    return results, found_passwords

def compute_averages(results_list):
    """
    Computes ATC and TTC for each hash

    :param results_list: result tuples
    :return: returns tuple, floats or None if not hashes were cracked
    """

    attempts_list, time_list = [], []
    for r in results_list:
        pwd = r[0]
        attempts = r[1]
        t = r[2]
        if pwd is not None:
            attempts_list.append(attempts)
            time_list.append(t)
    if not attempts_list:
        return None, None
    return mean(attempts_list), mean(time_list)


def run_all(mode: str):
    """
    Executes the experiment for all four hash files in the directory

    :param mode: random or lexographically
    :return: dictionary keyed by filename includes: results, found, avg attempts, avg time
    """

    assert mode in ('random', 'lex')
    if mode == 'lex':
        candidates = all_pass_lex
    else:
        candidates = all_pass_lex[:]
        shuffle(candidates)

    overall = {}

    for sha_file in SHA256_FILES:
        path = os.path.join(PROGRAM_DIR, sha_file)
        if not os.path.isfile(path):
            print(f"[!] file {sha_file} not found in {PROGRAM_DIR}, skipping")
            overall[sha_file] = None
            continue
        results, found_pwds = process_sha256_file(path, candidates)
        avg_attempts, avg_time = compute_averages(results)
        overall[sha_file] = {
            'results': results,
            'found': found_pwds,
            'avg_attempts': avg_attempts,
            'avg_time': avg_time
        }

    for pbk_file in PBKDF2_FILES:
        path = os.path.join(PROGRAM_DIR, pbk_file)
        if not os.path.isfile(path):
            print(f"[!] file {pbk_file} not found in {PROGRAM_DIR}, skipping")
            overall[pbk_file] = None
            continue
        results, found_pwds = process_pbkdf2_file(path, candidates)
        avg_attempts, avg_time = compute_averages(results)
        overall[pbk_file] = {
            'results': results,
            'found': found_pwds,
            'avg_attempts': avg_attempts,
            'avg_time': avg_time
        }

    return overall

def main():

    print("=== Brute force ===")
    print("[*] Running RANDOM candidate order (shuffled)")
    summary_random = run_all('random')

    print("[*] Running LEXICOGRAPHIC candidate order")
    summary_lex = run_all('lex')

    found_pwds_map = {}
    for fname in SHA256_FILES:
        lex_data = summary_lex.get(fname)
        if lex_data and 'found' in lex_data:
            found_pwds_map[fname] = lex_data['found']
        else:
            rand_data = summary_random.get(fname)
            found_pwds_map[fname] = rand_data['found'] if rand_data and 'found' in rand_data else []


if __name__ == "__main__":
    main()
