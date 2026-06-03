# Windows-Based Password Recovery Tool 🔐

This **Windows-based password recovery tool** is a comprehensive forensic investigation tool built with Streamlit and Python. Designed as a dissertation project, this tool integrates dictionary attacks with Artificial Intelligence (Google Gemini), custom + existing password permutation rules, and automated SQLite logging.

It provides forensic investigators with an intuitive GUI to extract hashes, crack passwords, mutate dictionaries, and automatically generate chain-of-custody audit reports.

## ✨ Features

* **Evidence Processing & Hash Extraction:**
  * Upload Windows registry hives (`SAM` and `SYSTEM` files) to automatically extract NTLM hashes using Impacket.
  * Queue encrypted documents (MS Word `.docx` and PDFs) for direct password recovery using msoffcrypto and pypdf.
* **AI-Powered Biographical Profiling:**
  * Uses the **Google Gemini API** to analyse suspect OSINT data (names, birth years, pets, hobbies, etc.).
  * Dynamically generates highly targeted, context-aware password dictionaries.
* **Advanced Attack Engine:**
  * **Dictionary-Based Attacks:** Support for uploaded wordlists, built-in dictionaries, and a dynamically updated "Golden Dictionary" of previously cracked passwords.
  * **Rule Engine:** Apply chained mutations to wordlists (Capitalize, Reverse, Leet Speak, Append Year).
  * **Custom Python Rules:** Write and test custom Python scripts directly in the GUI to mutate wordlists.
  * **Multiprocessing Support:** Utilises `concurrent.futures.ProcessPoolExecutor` for rapid, concurrent chunk processing.
* **Forensic Auditing & Case Management:**
  * Integrated SQLite database for immutable audit logging.
  * Tracks timestamps, investigator actions, and attack configurations.
  * Exports detailed forensic reports in both **PDF** and **CSV** formats for legal and investigative use.

## 🛠️ Prerequisites

* **Python 3.8+**
* A [Google Gemini API Key](https://aistudio.google.com/app/apikey) (Required for the AI Biographical Dictionary feature).

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/TylerWoodman/Windows-Based-Password-Recovery.git
   cd Windows-Based-Password-Recovery
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Create the virtual enviroment in Windows
   py -m venv venv

   #Create the virtual enviroment in Mac/Linux
   python3 -m venv venv

   # Activate on Mac/Linux:
   source venv/bin/activate
   
   # Activate on Windows:
   venv\Scripts\activate
   ```

3. **Install required dependencies:**
   Make sure your `requirements.txt` file is in the project folder, then run:
   ```bash
   pip install -r Ui/requirements.txt
   ```

## 🚀 Usage

1. **Start the Streamlit interface:**
   ```bash
   streamlit run frontend.py
   ```

2. **Case Management:**
   * Enter your Case Reference and Investigator Name in the sidebar. This ensures all actions are properly logged to the database.

3. **General Workflow:**
   * **Hash Page:** Upload your `SAM`/`SYSTEM` files or target documents (PDFs or MS Word `.docx`)
   * **AI Dictionary (Optional):** Input suspect OSINT to generate a targeted wordlist.
   * **Attack Page:** Configure your attack type (e.g., Dictionary attack, select wordlists, apply Leet Speak rules).
   * **Recovery Progress Page:** Start the attack and monitor the progress bar in real-time.
   * **Audit & Report:** Once the investigation is complete, export your PDF/CSV report for the case file.

## 🧪 Running Tests
This project includes a comprehensive test suite covering the UI, backend logic, and database operations. To run the tests, ensure your virtual environment is active and run:

```bash
pytest -v
```

## 🗂️ Project Structure

* `frontend.py` - The main Streamlit GUI and frontend logic.
* `backend.py` - The cracking engine. Handles multiprocessing, hash matching, AI prompting, and file decryption.
* `database.py` - SQLite operations for case management and event logging.
* `wordlists/` - Directory containing built-in wordlists such as `RockYou.txt`.
* `progress.json` - Temporary state file used for inter-process communication between the frontend and backend.
* `task.json` - Stores current attack configurations and target hashes.
* `golden_dictionary.txt` - Automatically populated with successfully recovered passwords for future reuse.

**🧪 Test Suite and CI/CD:**
* `.github/workflows/python-test.yml` - GitHub Actions workflow for Continuous Integration (CI), ensuring automated test execution on every push.
* `test_ui.py` - Utilises Streamlit's `AppTest` framework to simulate user interactions and verify frontend rendering.
* `test_backend.py` - Unit tests for the core cracking engine, rule mutations, and AI integrations (utilising `unittest.mock`).
* `test_database.py` - Integration tests verifying SQLite database reads, writes, and audit logging functionality.

## ⚠️ Disclaimer

**Educational and Authorised Use Only.**
This tool was developed as a university dissertation project for forensic research purposes. It is designed solely for use by authorised professionals, forensic investigators, and students in controlled, legal environments. Do not use this software to attack or extract credentials from systems or files you do not have explicit, documented permission to audit. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
