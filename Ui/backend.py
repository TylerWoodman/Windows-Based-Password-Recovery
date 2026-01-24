from Crypto.Hash import MD4
import time
import tempfile
import os
import datetime
import struct
from impacket.examples.secretsdump import LocalOperations, SAMHashes

def datetime_patch(self, filetime):
    try:
        if isinstance(filetime, bytes):
            filetime = struct.unpack('<Q', filetime)[0]

        days = (1970-1601)*(365)
        leap_years = (1970-1601) / 4 - 3
        days = days + round(leap_years) 
        seconds = days * 60 * 60 * 24
        nano_to_seconds = filetime / 10000000
        unix_time = nano_to_seconds - seconds

        if unix_time < 0:
            return datetime.datetime(1970, 1, 1)
        
        return datetime.datetime.utcfromtimestamp(unix_time)
    except (OSError, ValueError, OverflowError, struct.error):
        return datetime.datetime(1970, 1, 1)

SAMHashes.nt_time_to_datetime = datetime_patch

def generate_ntlm_hash(password):
    password_bytes = password.encode('utf-16le')
    md4_hash = MD4.new()
    md4_hash.update(password_bytes)
    return md4_hash.hexdigest().upper()

test_hash = generate_ntlm_hash("password")
print(f"Generated NTLM hash = {test_hash}")

if test_hash == "8846F7EAEE8FB117AD06BDD830B7586C":
    print("Function works.")
else:
    print("Function error.")


def dictionary_attack(target_hash, wordlist_file, progress_checker = None):
    target_hash = target_hash.upper()
    wordlist_file.seek(0)

    total_lines = sum(1 for _ in wordlist_file)
    wordlist_file.seek(0)
    start_time = time.time()

    for index, line in enumerate(wordlist_file):
        try:
            password_candidate = line.decode('latin-1').strip()
        except UnicodeDecodeError:
            continue

        candidate_hash = generate_ntlm_hash(password_candidate)

        if candidate_hash == target_hash:
            duration = time.time() - start_time
            return {
                "success" : True,
                "password" : password_candidate,
                "time" : duration
            }
          
        if progress_checker and index % 100 == 0:
            progress = min(index / total_lines, 1.0)
            progress_checker(progress)

    return {"success" : False, "time" : time.time() - start_time}

target_hash = "8846F7EAEE8FB117AD06BDD830B7586C"
file = open("test_wordlist.txt", "rb")
result = dictionary_attack(target_hash, file, None)
print(f"Test result = {result}")

def extract_ntlm_hash (SAM_file, SYSTEM_file):
    extracted_credentials = []
    SAM_file.seek(0)
    SYSTEM_file.seek(0)

    with tempfile.NamedTemporaryFile(delete=False) as temp_SAM:
        temp_SAM.write(SAM_file.read())
        SAM_path = temp_SAM.name

    with tempfile.NamedTemporaryFile(delete=False) as temp_SYSTEM:
        temp_SYSTEM.write(SYSTEM_file.read())
        SYSTEM_path = temp_SYSTEM.name

    try:
        local_operations = LocalOperations(SYSTEM_path)
        boot_key = local_operations.getBootKey()

        def save_hash_to_list(found_credentials):
            extracted_credentials.append(found_credentials)

        SAM_dump = SAMHashes(SAM_path, boot_key, isRemote=False, perSecretCallback=save_hash_to_list)
        SAM_dump.dump()
        SAM_dump.finish()

    except Exception as e:
        return (f"Error = {str(e)}")
    
    finally:
        try:
            os.remove(SAM_path)
            os.remove(SYSTEM_path)
        except:
            pass

    return extracted_credentials
        
