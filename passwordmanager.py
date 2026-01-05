#PASSWORD MANAGER (LOCAL ENCRYPTION)
#master password input- 
# Encryption setup- 
# Add new password records- 
# Retrieve & decrypt saved password
#store encrypted file

import os
import json #convert python dict <-> json entites
import base64 #encode binary to text to store in JSON
import uuid # generate unique ids for entites
import datetime #generate timestamp entites
import getpass #read password without echoing them to terminal(security)

from typing import Dict, List, Any, Optional, Tuple  #typing : hint for readability
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256    #| both used to dervie fixed length cryptographic from a human password
from cryptography.fernet import Fernet, InvalidToken   #fernet: symmetric authenticated encryption (encryption + integrity check)
                                                       #invalidtoken: exception handling if decrption failed(wrong key or tempered data)

#config
VAULT_PATH = "vault.json"
SALT_SIZE = 16
KDF_ITERATIONS = 390_000 #number of PBKDF2 rounds to slow brute force attacks


#key derivation: convert password to bytes. 
def derive_key(password: str, salt: bytes, iterations: int= KDF_ITERATIONS) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm= SHA256(),#used to genererate 32-byte cryptographic key from password+salt
        length=32,
        salt=salt,
        iterations= iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))  #fernet expected a base64-encoded key
    return key 
"""Human passwords are weak: PBKDF2 slow down brute-force attackers by doing many iterations
salt ensures same password across different vaults won't produce same key(prevent rainbow-table attacks)"""

def encrypt_db(db: Dict[str, Any], fernet: Fernet)-> bytes:
    """Encrypt python dict DB -> returns token bytes"""
    data = json.dumps(db, ensure_ascii=False).encode("utf-8")
    token = fernet.encrypt(data)  #serilizes the in-memory DB(python dict) to json and ecrypt
    return token

def decrypt_db(token: bytes, fernet: Fernet) -> Dict[str, Any]:
    """Decrypt token -> return python dict DB """
    decrypted = fernet.decrypt(token) #decrypt and verifies integrity(raises invalidToken on falilure)
    db = json.loads(decrypted.decode("utf-8"))
    return db

def save_vault(salt: bytes, token: bytes, path: str = VAULT_PATH) -> None: 
    """Write vault JSON with base64-encoded salt and token. """
    payload = {
        "salt" : base64.b64encode(salt).decode("utf-8"),
        "token" : base64.b64encode(token).decode("utf-8"),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload,f)

def load_vault(path: str = VAULT_PATH) -> Optional[Dict[str, str]]:
    """load vault json file. return parsed dict with 'salt' and 'token'. """
    """loads the JSON file and returns the structure with base64 string. if file missing returns None. """
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


#  ---------------------------
#  DB Operations 
#  ---------------------------

def safe_b64decode(value: Any) -> bytes:
    """Ensure vault salt/token decode safely regardless of stored type.."""
    if isinstance(value, bytes):
        value = value.decode("utf-8")

    value = value.strip().replace("\n", "").replace("\r", "")

    #auto fixing missing padding
    missing = len(value)%4
    if missing !=0:
        value += "=" * (4 - missing)
    return base64.b64decode(value)

def make_empty_db() -> Dict[str, Any]:
    return {"entries": []}

def ensure_short_ids(db:Dict[str, Any]) -> None:
    """Ensures every entry has a short_id. 
    old vault may not contain this key , so we auto generate it. """

    for i, e in enumerate(db.get("entries", []), start = 1):
        if "short_id" not in e:
            e["short_id"] = i


def add_entry(db: Dict[str, Any], title: str, username: str, password: str, notes: str = "") -> Dict[str, Any]:
    entry = {
        "id" : str(uuid.uuid4()),  #unique ID for later lookup
        "short_id": len(db["entries"]) + 1,  #easy to remember ID
        "title" : title,
        "username" : username,
        "password" : password, 
        "notes" : notes,
        "created_at": datetime.datetime.now(datetime.UTC).isoformat(), #timestamp in UTC(iso format)
    }
    """stores the password in plaintext inside the encrypted DB"""
    db["entries"].append(entry)
    return entry

def find_entry_by_id(db: Dict[str, Any], key:str) -> Optional[Dict[str, Any]]:
    key_lower = key.lower()

    #1. match short ID (if number entered)
    if key.isdigit():
        short_id = int(key)
        for e in db["entries"]:
            if e.get("short_id") == short_id:
                return e
    #2. match UUID
    for e in db["entrties"]:  #looping through entries and matches id
        if e.get("id") == key:
            return e
        
    #3. match title (case-insensitive)
    for e in db["entries"]:
        if e.get("title", "").lower() == key_lower:
            return e
    return None

def delete_entry(db: Dict[str, Any], entry_id: str) -> bool:
    entries = db.get("entries", [])
    for i,e in enumerate(entries):  #removing matching elements from the list
        if e.get("id") == entry_id:
            entries.pop(i)
            return True
        
    return False

def search_entries(db: Dict[str, Any], query: str) -> List[Dict[str, Any]]:
    q = query.lower()
    results = []
    for e in db.get("entries", []):
        if q in (e.get("title", "").lower() + " " + e.get("username", "").lower() + " " + e.get("notes", "").lower()):
            results.append(e)
    return results

# -----------------------------
# CLI / main flow
# -----------------------------

def initial_setup_flow(path: str = VAULT_PATH) -> Tuple[Fernet, Dict[str, Any], bytes]:
    """Runs when no vault exists. Prompts user to create a master password, 
    generates salts, derives key, creates empty DB, encrypt and writes vault. 
    Returns (Fernet, db, salt). """

    print("=== First-time setup ===")
    while True:
        pw1 = getpass.getpass("create a master password: ").strip()
        pw2 = getpass.getpass("confirm master password: ").strip()
        if pw1 == pw2 and len(pw1) >= 6:
            break
        print("Password mismatch or too short.  ")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(pw1, salt)
    f = Fernet(key)
    db = make_empty_db()
    ensure_short_ids(db)
    token = encrypt_db(db, f)
    save_vault(salt, token, path)
    print(f"Vault created and saved to {path}")
    return f, db, salt

def load_existing_vault_flow(path: str = VAULT_PATH) -> Tuple[Fernet, Dict[str, Any], bytes]:
    """loads vault file and prompts for master password to decrypt.
    Raises SystemExit if decryption fails consecutively.
    """

    raw = load_vault(path)
    if raw is None:
        raise FileNotFoundError("Vault File not found. ")
    salt = safe_b64decode(raw["salt"])
    token = safe_b64decode(raw["token"])
    
    for _ in range(3):
        pw = getpass.getpass("Enter master password: ")
        key = derive_key(pw, salt)
        f = Fernet(key)
        try:
            db = decrypt_db(token, f)
            ensure_short_ids(db)
            print("Vault unlocked. ")
            return f, db, salt
        except InvalidToken:
            print("Incorrect password. ")
    print("Too many failed attempts . Exiting. ")
    raise SystemExit(1)

def save_db_with_new_key(db: Dict[str, Any], password: str, path: str = VAULT_PATH) -> None:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    f = Fernet(key)
    token = encrypt_db(db, f)
    save_vault(salt, token, path)

def pretty_print_entry(e: Dict[str, Any], show_password: bool = False) -> None:
    print(f"ID: {e.get('id')}")
    print(f"Title: {e.get('title')}")
    print(f"Username: {e.get('username')}")
    if show_password:
        print(f"Password: {e.get('password')}")
    else:
        print("Password: **********")
    if e.get("notes"):
        print(f"Notes: {e.get('notes')}")
    print(f"Created: {e.get('created_at')}")


def menu_loop(fernet: Fernet, db: Dict[str, Any], salt: bytes, path: str = VAULT_PATH) -> None:
    """Interactive menu loop for user operation """
    while True:
        print("\n ------ Password manager ---  ")
        print("1). Add new entry  ")
        print("2). List entries (id +title + username)  ")
        print("3). View entry (show password) ")
        print("4). Search entries  ")
        print("5). Delete entry  ")
        print("6). Change master password ")
        print("7). Quit ")
        choice = input("Choose an option (1-7): ").strip()

        if choice == '1':
            title = input("Title(e.g. Gmail): ").strip()
            username = input("Username : ").strip()
            pw = getpass.getpass("Password (input hidden): ")
            notes = input("Notes (optional): ").strip()
            entry = add_entry(db, title, username, pw, notes)
            token = encrypt_db(db, fernet)
            save_vault(salt, token, path)
            print(f"Added entry {entry['id']}")

        elif choice == '2':
            entries = db.get("entries", [])
            if not entries:
                print("No entries.")
            else:
                for e in entries:
                    print(f"[{e['short_id']}] | {e['title']}  |  {e['username']}")
        
        elif choice == '3':
            eid = input("Entry ID/short number/ title: ").strip()
            e = find_entry_by_id(db, eid)
            if not e:
                print("Entry not found. ")

            else:
                pretty_print_entry(e, show_password=True)

        elif choice == '4':
            q = input("Search query(title/username/notes): ").strip()
            results = search_entries(db, q)
            if not results:
                print("No matches. ")
            else:
                for e in results:
                    pretty_print_entry(e, show_password= False)
                    print("-" * 25)

        elif choice == '5':
            eid = input("Entry ID to delete: ").strip()
            e = find_entry_by_id(db, eid)
            if not e:
                print("Entry not found. ")
                continue

            confirmed = input(f"Type 'DELETE' to remove '{e['title']}' ({e['short_id']}): ").strip()
            if confirmed == "DELETE":
                ok = delete_entry(db,eid)
                if ok:
                    token = encrypt_db(db, fernet)
                    save_vault(salt, token, path)
                    print("Deleted.. ")
                else:
                    print("ID not found. ")
            else:
                print("Deletion Cancelled. ")

        elif choice == '6':
            #change master password: ask new password, re-encrypt with new salt/key.
            Current = getpass.getpass("Current master password: ")
            # verify current password quickly by attempting decryption
            try:
                test_key = derive_key(Current,salt)
                _ = Fernet(test_key).decrypt(safe_b64decode(load_vault(path)['token']))

            except Exception:
                print("Current password verification failed. ")
                continue
            while True:
                npw1 = getpass.getpass("New master password: ")
                npw2 = getpass.getpass("Confirm new master password: ")
                if npw1 != npw2:
                    print("Password did not match. ")
                    continue
                if len(npw1) and len(npw2) < 6:
                    print("Choose at least 6 character. ")
                    continue
                break
            save_db_with_new_key(db,npw1, path)
            #updating running fernet and salt

            raw = load_vault(path)
            salt = safe_b64decode(raw["salt"])
            key = derive_key(npw1,salt)
            fernet = Fernet(key)
            print("Master Password changed successfully. ")

        elif choice == '7':
            print("Goodbye... ")
            break
        else:
            print("Invalid choice. Try again. .")

def main():
    print("Local Password Manager (Encrypts your DB with master password). ")
    # determines if vault exists
    if not os.path.exists(VAULT_PATH):
        f,db, salt = initial_setup_flow(VAULT_PATH)
    else:
        f, db, salt = load_existing_vault_flow(VAULT_PATH)

    menu_loop(f, db, salt, VAULT_PATH)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted . Exiting. ")