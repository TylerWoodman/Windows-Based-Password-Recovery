import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime
import psutil
from fpdf import FPDF
import json
import subprocess
import backend
import database
from google import genai
import os
import sqlite3

########## Navigation sidebar ###########

st.set_page_config(page_title="AI Forensic Cracker", layout="wide", page_icon="🔐")

st.sidebar.header("Case Management 📁")
case_id = st.sidebar.text_input("Input Case Reference" , "CASE-0012025")
investigator = st.sidebar.text_input("Input investigator name" , "Woody Woodchip")

page = st.sidebar.radio("Navigation",[
    "Home Page",
    "Hash Page",
    "AI Biographical Dictionary",
    "Attack Page",
    "Recovery Progress Page",
    "Audit and Report Page"
    ])

st.sidebar.markdown('--------------------')
if st.sidebar.button("Terminate" , type="primary" , use_container_width=True):
    with st.spinner("Terminating processes..."):
        terminated = 0
        for process in psutil.process_iter(['pid' , 'name' , 'cmdline']):
            try:
                cmdline = process.info.get('cmdline') or []
                cmd_string = " ".join(cmdline).lower()
        
                if 'backend.py' in cmd_string:
                    for child in process.children(recursive=True):
                        child.kill()
                        terminated += 1
                    process.kill()
                    terminated +=1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if terminated > 0:
            try:
                with open("progress.json" , "w") as f:
                    json.dump({"progress" : 0.0, "state" : "failed", "password" : None, "time" : 0}, f)
            except Exception:
                pass
            st.sidebar.success(f"Terminated {terminated} processes.")
        else:
            st.sidebar.info("No backend processes to terminate.")

 
if 'audit_log' not in st.session_state:
    st.session_state['audit_log'] = []
if 'target_hashes' not in st.session_state:
    st.session_state['target_hashes'] = []

database.initalize_database()

def log_event(event_text):
    timestamp = database.log_event(case_id, investigator, event_text)
    if timestamp:
        st.session_state['audit_log'].append({"Time" : timestamp, "Event" : event_text})
    
########### Home page ##############

if page == "Home Page":
    st.title("Windows-Based Password Recovery 🔐")
    st.subheader(f"""Welcome to Windows-Based Password Recovery!
                 Current case: {case_id}""")

    st.markdown("""
    This tool allows forensic investigators to:
    - Upload hashed passwords / manually input hashes
    - Select recovery methods ( Brute-force , dictionary-based )
    - Monitor recovery progress
    - Create / export reports for legal and investigative use

    Use the sidebar to navigate between pages.
    """)

    cpu_usage = psutil.cpu_percent()

    col1,col2 = st.columns(2)
    col1.metric("Hashes Loaded", len(st.session_state['target_hashes']))
    col2.metric("CPU Load",f"{cpu_usage}%", "Live")

########### Upload hash page ###########

elif page == "Hash Page":
    st.title("Upload hash evidence #️⃣")
    st.write("Upload a hash list, windows artifact, document , or enter a hash manually!")

    tab1,tab2 = st.tabs(["Windows Artifacts" , "Document upload"])

    #with tab1:
        #hash_file = st.file_uploader("Upload a hash file" , type = ['txt','csv'])

    with tab1:
        col1,col2 = st.columns(2)
        with col1:
            SAM_file = st.file_uploader("Upload SAM file" , key="sam")
        with col2:
            system_file = st.file_uploader("Upload SYSTEM file" , key="sys")
        
        if SAM_file and system_file:
            if st.button("Extract NTLM hash"):
                with st.spinner("Finding boot key..."):
                    results = backend.extract_ntlm_hash(SAM_file, system_file)

                if results:
                    if len(results) > 0 and results[0].startswith("Error"):
                        st.error(results[0])
                    
                    else:
                        amount = len(results)
                        st.success(f"Successfully extracted {amount} accounts.")
                        with st.expander("Test"):
                            st.write(results)

                        for credentials in results:
                            parts = credentials.split(':')
                            if len(parts) > 3:
                                username = parts[0]
                                NTLM_hash = parts[3]
                                st.code(f"User = {username} , Hash = {NTLM_hash}" , language="yaml")
                                st.session_state['target_hashes'].append(NTLM_hash)

                        log_event("Extracted NTLM hash from windows artifact")

    #with tab3:
        #hash_input = st.text_input("Input hash")
        #col1,col2 = st.columns(2)
        #with col1:
        #    hash_type = st.selectbox("Hash type",["MD5","SHA-256","NTLM","MS Office 2013"])
        #with col2:
        #    salt_format = st.selectbox("Salt format",["Unsalted","hash:salt","salt:hash","hash:salt:pass"])
        #if st.button("Save input"):
        #    st.session_state['target_hashes'].append(f"{hash_type} - {hash_input}")
        #    st.success("Hash input saved")
        #    log_event(f"Manual input: {hash_type} (Format: {salt_format})")
    
    with tab2:
        st.subheader("Extract hash from a document")
        st.info("Supported formats include: MS Word (.docx) , Excel (.xlsx) , PDF")
        document_upload = st.file_uploader("Upload a document" , type = ['docx','xlsx','PDF'])

        if document_upload is not None:
            file_name = document_upload.name

            if st.button("Add to target list"):
                with open(file_name, "wb") as f:
                    f.write(document_upload.getbuffer())
                st.session_state['target_hashes'].append(f"{file_name}")
                st.success("Document saved")
                log_event(f"Document uploaded : {file_name}")

########### Gemini Biographical Dictionary ##########

elif page == "AI Biographical Dictionary":
    st.title("AI Biographical Dictionary")
    st.markdown("""
Use Open Source Intelligence to generate a highly targeted dictionary.
The Ai will analyse the suspects biographical profile and generate passwords based on this information.
                """)
    
    with st.expander("Enter Gemini API Key", expanded=True):
        gemini_api_key = st.text_input("Enter your Google Gemini API Key", type="password")
        st.caption("You can get a free API Key at https://aistudio.google.com/app/apikey")

    st.markdown("### Suspect's OSINT data")

    with st.form("OSINT_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            target_forename = st.text_input("Target's Forename" , placeholder="e.g. Jack")
            target_surname = st.text_input("Target's Surname" , placeholder="e.g. Smith")
            birth_year = st.text_input("Birth Year" , placeholder="e.g. 1982")
            partner_name = st.text_input("Partner Name" , placeholder="e.g. Sandra")
        with col2:
            pets = st.text_input("Pet Names" , placeholder="e.g. Bully , Tyson , violet")
            company = st.text_input("Company or School" , placeholder="e.g. Microsoft")
            hobbies = st.text_input("Hobbies / Sports Teams" , placeholder="e.g. Arsenal FC , Guitar")
        with col3:
            other = st.text_input("Other information?" , placeholder="e.g. blue , Jurassic Park , Tetris")

        submit_form = st.form_submit_button("Generate Targeted Wordlist", type="primary")

    if submit_form:
        if not gemini_api_key:
            st.error("Please enter your Gemini API key first.")
        else:
            with st.spinner("Gemini is profiling the target and generating passwords...."):
                try:
                    wordlist = backend.generate_osint_wordlist(
                        gemini_api_key,
                        target_forename,
                        target_surname,
                        birth_year,
                        partner_name,
                        pets,
                        company,
                        hobbies,
                        other
                    )

                    file_name = f"OSINT_wordlist_{target_forename}_{target_surname}.txt"
                    with open(file_name , "w") as f:
                        f.write(wordlist)

                    st.success(f"Generating OSINT wordlist was a success! Saved as **{file_name}**")
                    log_event(f"AI generated OSINT wordlist for target: {target_surname}_{target_forename}")

                    with st.expander("Preview Generated Passwords"):
                        st.code(wordlist)
                except Exception as e:
                    st.error(f"AI generation failed: {e}")

########### Attack selection page ##########

elif page == "Attack Page":
    st.title("Select recovery method ⚙️")

    attack_type = st.radio("Attack type",["Masked brute force attack" , "Dictionary-based" , "Rainbow attack"])

    st.markdown("-------------------------------")

    if attack_type == "Masked brute force attack":
        st.subheader("Brute Force Customization")

        bruteforce_mode = st.radio("Method" , ["Standard Brute force" , "Mask customisation"])

        if bruteforce_mode == "Standard Brute force":
            character_set = st.multiselect("Character Set",["Lowercase","Uppercase","Numbers","Special Characters"])
            max_password_length = st.slider("Maximum password length" , 1,20,8 )

        if bruteforce_mode == "Mask customisation":
            col1,col2 = st.columns(2)
            with col1:
                mask_input = st.text_input("Enter mask pattern")
            with col2:
                mask_presets = {
                    "Standard 8 Character Lower" : "?l?l?l?l?l?l?l?l",
                    "Name + Year" : "?u?l?l?l?l?1?9?d?d",
                    "Password + Digit" : "?l?l?l?l?l?l?l?l?d",
                    "Upper + Lower + Year" : "?u?l?l?l?l?l19?d?d",
                    "7-Bit Full ASCII" : "?a?a?a?a?a?a?a?a",
                }

                selected_preset = st.selectbox("Select Mask" , list(mask_presets.keys()))
                mask_code = mask_presets[selected_preset]


    elif attack_type == "Dictionary-based":
        st.subheader("Dictionary attack settings")
        dictionary_source = st.radio("Select Dictionary Source:" , ["Upload Wordlist" , "Use Built-in Wordlist" ,"Use Golden Dictionary"])
        if dictionary_source == "Upload Wordlist":
            uploaded_dictionary = st.file_uploader("Upload wordlist")
            if uploaded_dictionary is not None:
                st.session_state['wordlist_file'] = uploaded_dictionary
                st.success("Dictionary loaded successfully.")

        elif dictionary_source == "Use Built-in Wordlist":
            if not os.path.exists("wordlists"):
                os.makedirs("wordlists")
                st.warning("Created 'wordlists' folder. It is currently empty, add some .txt wordlists!")
            
            available_wordlists = [file for file in os.listdir("wordlists") if file.endswith('.txt')]

            if available_wordlists:
                selected_wordlist = st.selectbox("Choose a built-in dictionary:" , available_wordlists)
                if st.button("Load Load Built-in Dictionary"):
                    st.session_state['wordlist_file'] = open(os.path.join("wordlists" , selected_wordlist), "rb")
                    st.success(f"Loaded Built-in dictionary: {selected_wordlist}")
            else:
                st.error("No .txt files found in the 'wordlists' folder.")

        elif dictionary_source == "Use Golden Dictionary":
            if st.button("Load Golden Dictionary"):
                try:
                    st.session_state['wordlist_file'] = open("golden_dictionary.txt" , "rb")
                    st.success("Golden Dictionary loaded.")
                except FileNotFoundError:
                    st.error("No golden dictionary found. Have you cracked any passwords yet?")

        with st.expander("Rule Selection"):
            st.write("Select rules to apply to the dictionary:")

            rules = [
                "Capitalize First Letter",
                "Reverse Word",
                "Leet Speak Substitution",
                "Append Year"
            ]

            selected_rules = st.multiselect(
                "Select and Order Rules:",
                options = rules,
                default = ["Capitalize First Letter" , "Append Year"],
                help = "Click the rules in the order you want them applied."
            )

            if "Leet Speak Substitution" in selected_rules:
                leet_max_length = st.slider("Max word length" , min_value = 5 , max_value = 20)
            else:
                leet_max_length = 10

            st.markdown("-----------------")
            st.write('Custom User Rules')
            
            col_1c,col_2c = st.columns(2)
            with col_1c:
                custom_prefix = st.text_input("Add Prefix (start)", placeholder="e.g. Admin")
            with col_2c:
                custom_suffix = st.text_input("Add Suffix (end)", placeholder="e.g. !")

            st.markdown("----------------")
            st.write("Custom Python Rule Creation")
            custom_code = st.checkbox("Enable Python Script creation")
            default_custom_code = """def custom_rule(word):
            return [word + word, word + "?"]
            # This function takes the base password and returns a list of new variations.
            # The example above shows duplicating the word and then adding a question mark.
            """

            if custom_code:
                st.info("Write a python function named exactly 'def custom_rule(word)'. It must accept a single string 'word' and return a list of strings.")
                custom_code_input = st.text_area("Python Script" , value = default_custom_code, height = 150)
            else:
                custom_code_input = None

            current_rules = {
                "ordered_rules": selected_rules,
                "leet_max_length": leet_max_length,
                "custom_prefix": custom_prefix,
                "custom_suffix": custom_suffix,
                "custom_code":custom_code_input
            }

    elif attack_type == "Rainbow attack":
        st.subheader("Rainbow attack")

    if st.button("Save attack configuration"):
        st.session_state['attack_config'] = attack_type
        if attack_type == "Dictionary-based":
            st.session_state['attack_rules'] = current_rules
        else:
            st.session_state['attack_rules'] = {}

        st.success(f"Configuration saved: {attack_type}")
        log_event(f"Attack configured: {attack_type}")
        
########### Recovery Progress ###########

elif page == "Recovery Progress Page":
    st.title("Recovery Results 📥")

    if 'attack_config' not in st.session_state:
        st.warning("Please select and configure an attack on the **Attack Page**")
        st.stop()

    if not st.session_state['target_hashes']:
        st.warning("Please upload or extract a hash on the **Hash Page**")
        st.stop()

    hash_selection = st.selectbox("Select Target Hash" , st.session_state['target_hashes'])
    target_hash = hash_selection

    current_attack = st.session_state['attack_config']
    st.info(f"Target = **{target_hash}**\n\nAttack = **{current_attack}**")

    if st.button("Start attack"):
        rules_configuration = st.session_state.get('attack_rules', {})

        if 'wordlist_file' not in st.session_state:
            st.error("No dictionary found. Please go back to the attack page and upload a file.")
        else:
            wordlist = st.session_state['wordlist_file']

            with st.spinner("Preparing uploaded files..."):
                task_data = {
                    "target_hash": target_hash,
                    "rules": rules_configuration
                }
                with open("task.json" , "w") as f:
                    json.dump(task_data, f)

                with open("temporary_wordlist.txt" , "wb") as f:
                    wordlist.seek(0)
                    f.write(wordlist.read())

            with open("progress.json" , "w") as f:
                json.dump({"progress":0.0, "state":"running","password":None, "time": 0}, f)

            backend = subprocess.Popen(["python" , "backend.py"])

            start_message = st.empty()
            progress_container = st.empty()
            status_text = st.empty()

            start_message.info("Starting recovery process....")
            progress_bar = st.progress(0.0)
            
            while True:
                try:
                    with open("progress.json" , "r") as f:
                        progress_status = json.load(f)

                    current_progress = progress_status.get("progress", 0.0)
                    progress_bar.progress(current_progress)
                    status_text.text(f"Checking dictionary.... {int(current_progress * 100)}%")

                    if progress_status.get("state") == "found":
                        progress_container.empty()
                        status_text.empty()
                        start_message.empty()
                        st.balloons()
                        st.success("**Password found**")

                        password = progress_status.get('password')
                        total_time = round(progress_status.get('time' , 0), 4)

                        st.metric("Password found" , password)
                        st.caption(f"Time taken: {total_time} seconds")
                        log_event(f"Success: Recovered {password}")
                        break

                    elif progress_status.get("state") == "failed":
                        progress_container.empty()
                        status_text.empty()
                        start_message.empty()
                        st.error("Password not found in dictionary.")
                        
                        total_time = round(progress_status.get('time' , 0), 4)
                        st.caption(f"Time taken: {total_time} seconds")

                        log_event("Attack failed.")
                        break

                except (FileNotFoundError, json.JSONDecodeError):
                    pass

                time.sleep(0.5)

########### Audit and Report page ##########

elif page == "Audit and Report Page":
    st.title("Forensic Audit Log")

    with st.expander("Case History" , expanded=False):
        case_query = st.text_input("Search by case reference:", value=case_id)

        if st.button("Fetch Records"):
            try:
                con = sqlite3.connect("forensic_audit.db")
                query = f"SELECT timestamp, investigator, event FROM Audit_Logs WHERE case_reference = ?"

                database_logs = pd.read_sql_query(query, con, params=(case_query,))
                con.close()

                if not database_logs.empty:
                    st.success(f"Found {len(database_logs)} records for {case_query}")
                    st.dataframe(database_logs, use_container_width=True, hide_index=True)
                else:
                    st.warning(f"No database records found for {case_query}")
            except Exception as e:
                st.error(f"Failed to read database: {e}")

    if st.session_state['audit_log']:
        dataframe_log = pd.DataFrame(st.session_state['audit_log'])
        st.dataframe(dataframe_log, use_container_width=True)

    st.markdown("----------------------------")

    def create_pdf(log_data):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial','B', 16)
        pdf.cell(40,10, txt=f"Forensic Report: {case_id}")
        pdf.ln(10)

        pdf.set_font('Arial','B', 12)
        pdf.cell(0,10, txt=f"Investigator: {investigator}", ln=True)
        pdf.cell(0,10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d')}", ln=True)
        pdf.ln(5)

        pdf.set_font('Arial','B', 12)
        pdf.cell(0, 10, txt="Audit Log Events:" , ln=True)

        pdf.set_font('Arial', size=10)
        for entry in log_data:
            row = f"{entry['Time']} | {entry['Event']}"
            pdf.cell(0,8, txt=row, ln=True, border=1)

        return pdf.output(dest='S').encode('latin-1')  
    
    col1,col2 = st.columns(2)
    with col1:
        if st.session_state['audit_log']:
            pdf_bytes = create_pdf(st.session_state['audit_log'])

            st.download_button(
            label = "Download PDF Report 📄",
            data = pdf_bytes,
            file_name = f"Forensic_Report_{case_id}.pdf",
            mime = "application/pdf"
        )
            
    with col2:
        if st.session_state['audit_log']:
            csv = dataframe_log.to_csv(index=False).encode('utf-8')
            st.download_button(
                label = "Export CSV Log 💾",
                data = csv,
                file_name = f"Log_{case_id}.csv",
                mime = "text/csv"
            )