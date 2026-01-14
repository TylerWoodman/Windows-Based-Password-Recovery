from Crypto.Hash import MD4
import time

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