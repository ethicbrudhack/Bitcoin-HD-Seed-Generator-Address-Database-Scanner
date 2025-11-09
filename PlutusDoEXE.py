import hashlib
import base58
import os
import sys
import ecdsa
import sqlite3
from bech32 import bech32_encode, convertbits
import time
import multiprocessing
import threading
import psutil
import random
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip49, Bip84, Bip44Coins, Bip49Coins, Bip84Coins, Bip44Changes

OUTPUT_FILE = "found_seeds.txt"
WORDLIST_FILE = "wordlist.txt"
PROCESSES = 6
USE_RANDOM = False
ALTERNATE_12_24 = True

DONATE_ADDRESS = "bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr"

def load_addresses():
    db_file = "addresses1111.db"
    print("[📦] Connecting to database dynamically (no RAM preload).", flush=True)
    if not os.path.exists(db_file):
        print(f"[❌] Missing file: {db_file}", flush=True)
        return None
    return True

def load_wordlist():
    print("[📖] Loading wordlist...", flush=True)
    if not os.path.exists(WORDLIST_FILE):
        print(f"[❌] Missing file: {WORDLIST_FILE}", flush=True)
        return []
    with open(WORDLIST_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def save_seed_to_db(seed_phrase):
    try:
        conn = sqlite3.connect("generated_seeds.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS generated_seeds (seed TEXT PRIMARY KEY)")
        cursor.execute("INSERT OR IGNORE INTO generated_seeds (seed) VALUES (?)", (seed_phrase,))
        conn.commit()
        conn.close()
        print(f"[💾] Saved seed to database: {seed_phrase}", flush=True)
    except Exception as e:
        print(f"[❌] Error saving seed: {e}", flush=True)

def seed_already_exists(seed_phrase):
    try:
        conn = sqlite3.connect("generated_seeds.db")
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM generated_seeds WHERE seed = ?", (seed_phrase,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    except Exception as e:
        print(f"[❌] Error checking seed: {e}", flush=True)
        return False

def generate_seed_stream(wordlist, use_random, alternate=True):
    mnemo = Mnemonic("english")
    used = set()
    toggle = True
    while True:
        num_words = 12 if not alternate else (12 if toggle else 24)
        if use_random:
            seed = random.sample(wordlist, num_words)
            phrase = " ".join(seed)
        else:
            phrase = mnemo.generate(strength=128 if num_words == 12 else 256)
        toggle = not toggle
        if phrase not in used:
            used.add(phrase)
            yield phrase

def private_key_to_addresses(private_key):
    sk = ecdsa.SigningKey.from_secret_exponent(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pubkey_bytes = b'\x04' + vk.to_string()

    ripemd160 = hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes).digest()).digest()
    extended = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    legacy_address = base58.b58encode(extended + checksum).decode()

    extended_p2sh = b'\x05' + ripemd160
    checksum_p2sh = hashlib.sha256(hashlib.sha256(extended_p2sh).digest()).digest()[:4]
    p2sh_address = base58.b58encode(extended_p2sh + checksum_p2sh).decode()

    hrp = "bc"
    data = convertbits(ripemd160, 8, 5, True)
    segwit_address = bech32_encode(hrp, data)

    return legacy_address, p2sh_address, segwit_address

def generate_hd_addresses(seed_phrase):
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    bip44_m = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    addr44 = bip44_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
    priv44 = bip44_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PrivateKey().Raw().ToInt()

    bip49_m = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
    addr49 = bip49_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
    priv49 = bip49_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PrivateKey().Raw().ToInt()

    bip84_m = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
    addr84 = bip84_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
    priv84 = bip84_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PrivateKey().Raw().ToInt()

    return priv44, (addr44,), priv49, (addr49,), priv84, (addr84,)

def address_exists_in_db(conn, address):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM addresses WHERE address = ?", (address,))
        return cursor.fetchone() is not None
    except Exception as e:
        print(f"[❌] Database query error: {e}", flush=True)
        return False

def search_process(wordlist, counter, process_id, lock):
    print(f"[🔁] Process {process_id} started!", flush=True)
    conn = sqlite3.connect("addresses1111.db")
    seed_gen = generate_seed_stream(wordlist, USE_RANDOM, ALTERNATE_12_24)

    for seed in seed_gen:
        if seed_already_exists(seed):
            print(f"[⛔] Seed already processed – skipping.", flush=True)
            continue

        save_seed_to_db(seed)

        try:
            print(f"[{process_id}] 🔤 Seed: {seed}", flush=True)
            pk44, addr44, pk49, addr49, pk84, addr84 = generate_hd_addresses(seed)

            print(f"[{process_id}] 🧪 BIP44: {addr44[0]}", flush=True)
            print(f"[{process_id}] 🧪 BIP49: {addr49[0]}", flush=True)
            print(f"[{process_id}] 🧪 BIP84: {addr84[0]}", flush=True)

            if (address_exists_in_db(conn, addr44[0]) or
                address_exists_in_db(conn, addr49[0]) or
                address_exists_in_db(conn, addr84[0])):

                print(f"[💥] MATCH FOUND in BTC database – saving to file!", flush=True)
                print(f"🎁 If this address has balance, please support my work with a 10% donation.")
                print(f"BTC donate: {DONATE_ADDRESS}\n")

                with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                    f.write(f"✅ HIT!\n")
                    f.write(f"Seed Phrase: {seed}\n")
                    f.write(f"BIP44: {addr44[0]} (priv: {hex(pk44)})\n")
                    f.write(f"BIP49: {addr49[0]} (priv: {hex(pk49)})\n")
                    f.write(f"BIP84: {addr84[0]} (priv: {hex(pk84)})\n")
                    f.write("🎁 If this address has balance, please support my work with a 10% donation.\n")
                    f.write(f"BTC donate: {DONATE_ADDRESS}\n")
                    f.write("------------------------------------------------------------\n\n")
            else:
                print(f"[🟡] Addresses not found – continuing.", flush=True)

            with lock:
                counter.value += 1

        except Exception as e:
            print(f"[{process_id}] ❌ Error: {e}", flush=True)

def print_counter(counter, lock):
    while True:
        with lock:
            print(f"[⏱️] Total seeds checked: {counter.value}", flush=True)
        time.sleep(2)

if __name__ == "__main__":
    print("🪙 If you find an address with balance, please support my work with a 10% donation 🙏")
    print(f"BTC donate: {DONATE_ADDRESS}\n")

    print("[🚀] Program started", flush=True)

    db_check = load_addresses()
    if not db_check:
        print("[⛔] Database not found. Exiting.", flush=True)
        sys.exit(1)

    wordlist = load_wordlist() if USE_RANDOM else []

    manager = multiprocessing.Manager()
    counter = multiprocessing.Value('i', 0)
    lock = multiprocessing.Lock()
    processes = []

    counter_thread = threading.Thread(target=print_counter, args=(counter, lock))
    counter_thread.daemon = True
    counter_thread.start()

    for i in range(PROCESSES):
        print(f"[⚙️] Launching process {i}", flush=True)
        p = multiprocessing.Process(target=search_process, args=(wordlist, counter, i, lock))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    print(f"[🏁] Finished. Total seeds checked: {counter.value}", flush=True)
