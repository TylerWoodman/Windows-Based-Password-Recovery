from Crypto.Hash import MD4
import time
import tempfile
import os
import datetime
import struct
from impacket.examples.secretsdump import LocalOperations, SAMHashes
import itertools
import msoffcrypto
from pypdf import PdfReader, PdfWriter

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

#test_hash = generate_ntlm_hash("password")
#print(f"Generated NTLM hash = {test_hash}")

#if test_hash == "8846F7EAEE8FB117AD06BDD830B7586C":
    #print("Function works.")
#else:
    #print("Function error.")

def dictionary_attack(target_hash, wordlist_file, rules = None, progress_checker = None):
    if rules is None:
        rules = {}

    file_path = os.path.isfile(target_hash)
    file_type = None

    if file_path:
        if target_hash.lower().endswith(".docx"): file_type = "word"
        elif target_hash.lower().endswith(".pdf"): file_type = "pdf"
    else:
        target_hash = target_hash.upper()

    wordlist_file.seek(0)
    total_lines = sum(1 for _ in wordlist_file)
    wordlist_file.seek(0)
    start_time = time.time()

    year_rule = rules.get("append_year", False)
    leet_rule = rules.get("leet_speak", False)
    custom_prefix = rules.get("custom_prefix", "")
    custom_suffix = rules.get("custom_suffix", "")
    reverse_rule = rules.get("reverse_rule", False)
    capitalize_rule = rules.get("capitalize_rule", False)

    for index, line in enumerate(wordlist_file):
        try:
            base_word = line.decode('latin-1').strip()
        except UnicodeDecodeError:
            continue

        candidates = [base_word]

        if leet_rule:
            leet_variations = leet_speak(base_word)
            for leet in leet_variations:
                if leet not in candidates:
                    candidates.append(leet)
            
        if capitalize_rule:
            capitalized_items = []
            for candidate in candidates:
                capital = capitalize_password(candidate)
                if capital not in candidates:
                    capitalized_items.append(capital)
            candidates.extend(capitalized_items)

        if reverse_rule:
            reversed_items = []
            for candidate in candidates:
                reversed_word = reverse_password(candidate)
                if reversed_word not in candidates:
                    reversed_items.append(reversed_word)
            candidates.extend(reversed_items)

        if custom_prefix or custom_suffix:
            prefix = custom_prefix if custom_prefix else ""
            suffix = custom_suffix if custom_suffix else ""

            add_to_existing = []
            for candidate in candidates:
                add_to_existing.append(f"{prefix}{candidate}{suffix}")
            candidates.extend(add_to_existing)

        if year_rule:
            new_variations = []
            for candidate in candidates:
                new_variations.extend(append_year(candidate))
            candidates.extend(new_variations)

        for candidate in candidates:
            print(f"{candidate}")
            found = False

            if file_path:
                if file_type == "word":
                    if check_msword_password(target_hash, candidate):
                        found = True
                elif file_type == "pdf":
                    if check_pdf_password(target_hash, candidate):
                        found = True
            
            else:
                if generate_ntlm_hash(candidate) == target_hash:
                    found = True

            if found:
                duration = time.time() - start_time
                return {
                    "success" : True,
                    "password" : candidate,
                    "time" : duration
                }
          
        if progress_checker and index % 100 == 0:
            progress = min(index / total_lines, 1.0)
            progress_checker(progress)

    return {"success" : False, "time" : time.time() - start_time}

# target_hash = "8846F7EAEE8FB117AD06BDD830B7586C"
# file = open("test_wordlist.txt", "rb")
# result = dictionary_attack(target_hash, file, None)
# print(f"Test result = {result}")

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
        
def capitalize_password(word):
    return word.capitalize()

def reverse_password(word):
    return word[::-1]

def append_year(word):
    variations = []
    current_year = datetime.datetime.now().year
    for y in range(current_year - 2, current_year + 0):
        variations.append(f"{word}{y}")
        #### print(variations) #####
    return variations
    
def leet_speak(word):
    substitutions = {
        'a':['a','@','4'],
        'b':['b','8'],
        'c':['c','[','('],
        'e':['e','3'],
        'g':['g','6'],
        'h':['h','#'],
        'i':['i','1'],
        'l':['i','1'],
        'o':['o','0'],
        's':['s','$','5'],
        't':['t','7','+'],
        'z':['z','2']
    }

    character_options = []
    for character in word.lower():
        options = substitutions.get(character, [character])
        character_options.append(options)

    all_variations = []
    for combination in itertools.product(*character_options):
        all_variations.append("".join(combination))

    return all_variations

def check_msword_password(file_path, password):
    try:
        with open(file_path, "rb") as f:
            file = msoffcrypto.OfficeFile(f)
            file.load_key(password=password, verify_password=True)
            return True
    except Exception:
        return False

def check_pdf_password(file_path, password):
    try:
        reader = PdfReader(file_path)
        if reader.is_encrypted:
            if reader.decrypt(password) > 0:
                return True
            else:
                return False
        else:
            return True
    except:
        return False