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
import concurrent.futures
import json
from google import genai

def generate_osint_wordlist(gemini_api_key, target_forename, target_surname, birth_year, partner_name, pets, company, hobbies, other, word_count):
    prompt = f"""
                You are a forensic cyber specialist. I will provide you with open source intelligence about a suspect.
                Your job is to generate a list of {word_count} highly probable base passwords this person might use.
                Combine their names, years, pets, and hobbies etc. Use command password patterns, such as capitalizing the first letter or adding numbers at the end.

                Target Forename = {target_forename}
                Target Surname = {target_surname}
                Birth Year = {birth_year}
                Partner Name = {partner_name}
                Pets = {pets}
                Company = {company}
                Hobbies = {hobbies}
                other = {other}

                IMPORTANT: Output only the passwords, one per line. Do not include any bullet points, numbering, or introductory text. Just provide the passwords. 
                """
    
    client = genai.Client(api_key=gemini_api_key)
    response = client.models.generate_content(
    model='gemini-2.5-flash',
    contents=prompt
)
    
    return response.text.strip()

def write_recovery_status(progress, state="running", password=None, total_time=0):
    try:
        task_data = {
            "progress":progress,
            "state": state,
            "password": password,
            "time": total_time
        } 
        with open("progress.json" , "w") as f:
            json.dump(task_data, f)
    except Exception:
        pass


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

def check_password_chunk(candidates_chunk, target_hash, file_path, file_type):
    for candidate in candidates_chunk:
        #print(f"Testing: {candidate}")
        if file_path:
            if file_type == "word":
                if check_msword_password(target_hash, candidate):
                    return candidate
            elif file_type == "pdf":
                if check_pdf_password(target_hash, candidate):
                    return candidate
        else:
            if generate_ntlm_hash(candidate) == target_hash:
                return candidate
    return None

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
    leet_max_length = rules.get("leet_max_length", 10)
    custom_prefix = rules.get("custom_prefix", "")
    custom_suffix = rules.get("custom_suffix", "")
    reverse_rule = rules.get("reverse_rule", False)
    capitalize_rule = rules.get("capitalize_rule", False)
    custom_code = rules.get("custom_code", False)

    custom_rule_function = None
    if custom_code:
        try:
            user_function = {}
            exec(custom_code, globals(), user_function)
            if 'custom_rule' in user_function and callable(user_function['custom_rule']):
                custom_rule_function = user_function['custom_rule']
        except Exception as error:
            pass

    #print("------------")
    #print(f"Target File: {target_hash}")
    #print(f"File Path: {file_path}")
    #print(f"File Type: {file_type}")
    #print("------------")

    chunk_size = 5000
    current_chunk = []
    waiting_list = []

    #with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
    with concurrent.futures.ProcessPoolExecutor(max_workers=8) as executor:

        for index, line in enumerate(wordlist_file):
            try:
                base_word = line.decode('latin-1').strip()
            except UnicodeDecodeError:
                continue

            candidates = [base_word]

            ordered_rules = rules.get("ordered_rules" , [])

            for rule_name in ordered_rules:
                current_batch = list(candidates)
                new_variations = []

                for candidate in current_batch:
                    if rule_name ==  "Capitalize First Letter":
                        new_variations.append(capitalize_password(candidate))
                    elif rule_name == "Reverse Word":
                        new_variations.append(reverse_password(candidate))
                    elif rule_name == "Append Year":
                        new_variations.extend(append_year(candidate))
                    elif rule_name == "Leet Speak Substitution":
                        leet_max_length = rules.get("leet_max_length" , 10)
                        new_variations.extend(leet_speak(candidate, leet_max_length)) 

                for item in new_variations:
                    if item not in candidates:
                        candidates.append(item)

                #print(f"{rule_name}:{candidates}")

            if custom_prefix or custom_suffix:
                prefix = custom_prefix if custom_prefix else ""
                suffix = custom_suffix if custom_suffix else ""

                add_to_existing = []
                for candidate in candidates:
                    add_to_existing.append(f"{prefix}{candidate}{suffix}")
                candidates.extend(add_to_existing)

            if custom_rule_function:
                custom_variations = []
                for candidate in candidates:
                    results_list = custom_rule_function(candidate)
                    if isinstance(results_list, list):
                        custom_variations.extend(results_list)
                        #print(results_list)
                candidates.extend(custom_variations)

            #print(f"Base Word: '{base_word}' | Testing {len(candidates)} variations: {candidates}")

            current_chunk.extend(candidates)

            if len(current_chunk) >= chunk_size:
                #print(f"{candidate}")
                future = executor.submit(check_password_chunk, current_chunk, target_hash, file_path, file_type)
                waiting_list.append(future)
                current_chunk = []
            
            if len(waiting_list) >= 16:
                done , not_done = concurrent.futures.wait(waiting_list, return_when=concurrent.futures.FIRST_COMPLETED)
            else:
                done , not_done = concurrent.futures.wait(waiting_list, timeout=0)
                
            for future in done:
                result = future.result()
                if result:
                    executor.shutdown(wait=False, cancel_futures=True)
                    save_to_golden_dictionary(result)
                    duration = time.time() - start_time
                    write_recovery_status(1.0, state="found", password=result, total_time=duration)
                    return

            waiting_list = list(not_done)
            progress = min((index + 1) / total_lines, 1.0)
            write_recovery_status(progress)

        if current_chunk:
            future = executor.submit(check_password_chunk, current_chunk, target_hash, file_path, file_type)
            waiting_list.append(future)

        for future in concurrent.futures.as_completed(waiting_list):
            result = future.result()
            if result:
                executor.shutdown(wait=False, cancel_futures=True)
                save_to_golden_dictionary(result)
                duration = time.time() - start_time
                write_recovery_status(1.0, state="found", password=result, total_time=duration)
                return
                
    duration = time.time() - start_time
    write_recovery_status(1.0, state="failed", total_time=duration)

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

def save_to_golden_dictionary(password):
    try:
        with open("golden_dictionary.txt" , "a") as f:
            f.write(f"{password}\n")
    except Exception as Error:
            print(f"Error saving to golden dictionary: {Error}")

def success_response(password, start_time):
    duration = time.time() - start_time
    return {
            "success" : True,
            "password" : password,
            "time" : duration
    }

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
    
def leet_speak(word, max_length = 10):
    if len(word) > max_length:
        return[word]
    
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
    
if __name__ == '__main__':
    try:
        with open("task.json" , "r") as f:
            task_data = json.load(f)

        target_hash = task_data["target_hash"]
        rules = task_data["rules"]

        with open("temporary_wordlist.txt" , "rb") as wordlist_file:
            dictionary_attack(target_hash, wordlist_file, rules)

    except Exception as e:
        write_recovery_status(0.0, state="failed")