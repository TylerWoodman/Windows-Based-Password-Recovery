import backend
from unittest.mock import patch, MagicMock, ANY
import io
import pytest
import os

def test_capitalize_password():
    assert backend.capitalize_password("lake") == "Lake"
    assert backend.capitalize_password("PASSWORD") == "Password"

def test_reverse_password():
    assert backend.reverse_password("12345") == "54321"
    assert backend.reverse_password("lake") == "ekal"

def test_generate_ntlm_hash():
    ntlm_expected_hash = "A4F49C406510BDCAB6824EE7C30FD852"
    assert backend.generate_ntlm_hash("Password") == ntlm_expected_hash

def test_leet_speak():
    leet_speak_results = backend.leet_speak("cat")
    assert "c@t" in leet_speak_results
    assert "[@7"in leet_speak_results

    long_word = "thiswordistoolong"
    assert backend.leet_speak(long_word, max_length=10) == [long_word]

@patch('backend.datetime')
def test_append_year(mock_datetime):
    mock_datetime.datetime.now.return_value.year = 2026
    append_year_results = backend.append_year("lake")
    assert append_year_results == ["lake2024" , "lake2025"]

@patch('backend.genai.Client')
def test_generate_osint_wordlist(mock_client_class):
    fake_response = MagicMock()
    fake_response.text = "Tyler2003\nAbby!135\nStaffyStudent\n"
    mock_instance = MagicMock()
    mock_instance.models.generate_content.return_value = fake_response
    mock_client_class.return_value = mock_instance

    gemini_results = backend.generate_osint_wordlist(
        gemini_api_key="FAKE_API_KEY",
        target_forename="Tyler",
        target_surname="Wood",
        birth_year="2003",
        partner_name="Abby",
        pets="Dottie",
        company="Plymouth",
        hobbies="Chess",
        other="blue"
    )

    assert "Tyler2003" in gemini_results
    assert "Abby!135" in gemini_results

####### SAM and SYSTEM Testing ####

def test_sam_and_system_extraction():
    sam_path = os.path.join(fixtures_directory, "SAM")
    system_path = os.path.join(fixtures_directory, "SYSTEM")

    if not os.path.exists(sam_path) or not os.path.exists(system_path):
        pytest.skip("SAM and SYSTEM files not found in fixtures folder.")

    with open(sam_path, "rb") as sam_file, open(system_path, "rb") as system_file:
        sam_and_system_results = backend.extract_ntlm_hash(sam_file, system_file)

    assert not (len(sam_and_system_results) > 0 and sam_and_system_results[0].startswith("Error"))
    assert len(sam_and_system_results) > 0

    admin_hash = "f56a8399599f1be040128b1dd9623c29"
    hash_found = any(admin_hash in account for account in sam_and_system_results)

    assert hash_found == True, f"Expected hash {admin_hash} was not found in the extraction results."
    

####### Word and PDF Testing ######

fixtures_directory = os.path.join(os.path.dirname(__file__), "fixtures")

def test_msword_password():
    word_path = os.path.join(fixtures_directory, "locked_WORD.docx")
    if not os.path.exists(word_path):
        pytest.skip("locked word doc not found in fixtures folder.")

    assert backend.check_msword_password(word_path, "secretpassword") == True
    assert backend.check_msword_password(word_path, "wrongpassword") == False

def test_pdf_password():
    pdf_path = os.path.join(fixtures_directory, "locked_PDF.pdf")
    if not os.path.exists(pdf_path):
        pytest.skip("locked pdf doc not found in fixtures folder.")

    assert backend.check_pdf_password(pdf_path, "secretpassword") == True
    assert backend.check_pdf_password(pdf_path, "wrongpassword") == False


###### Dictionary Attack Testing ###

@patch('backend.write_recovery_status')
@patch('backend.save_to_golden_dictionary')

def test_dictionary_attack(save_to_golden, write_recovery_status):
    dummy_wordlist = io.BytesIO(b"crocodile\nlizard\nsnake\npassword\n")
    target_hash = "8846F7EAEE8FB117AD06BDD830B7586C"
    backend.dictionary_attack(target_hash, dummy_wordlist)
    save_to_golden.assert_called_with("password")
    write_recovery_status.assert_called_with(1.0, state="found", password="password", total_time=ANY)

@patch('backend.write_recovery_status')
@patch('backend.save_to_golden_dictionary')

def test_dictionary_attack(save_to_golden, write_recovery_status):
    dummy_wordlist = io.BytesIO(b"crocodile\nlizard\nsnake\n")
    target_hash = "8846F7EAEE8FB117AD06BDD830B7586C"
    backend.dictionary_attack(target_hash, dummy_wordlist)
    save_to_golden.assert_not_called()
    write_recovery_status.assert_called_with(1.0, state="failed", total_time=ANY)


