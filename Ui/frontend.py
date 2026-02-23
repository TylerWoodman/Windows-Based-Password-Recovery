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

########## Navigation sidebar ###########

st.set_page_config(page_title="AI Forensic Cracker", layout="wide", page_icon="🔐")

st.sidebar.header("Case Management 📁")
case_id = st.sidebar.text_input("Input Case Reference" , "CASE-0012025")
investigator = st.sidebar.text_input("Input investigator name" , "Woody Woodchip")

page = st.sidebar.radio("Navigation",["Home Page","Hash Page","Attack Page","Recovery Progress Page","Audit and Report Page"])

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

def log_event(event):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state['audit_log'].append({"Time" : timestamp, "Event" : event})
    
########### Home page ##############

if page == "Home Page":
    st.title("Ai Password Recovery Tool 🔐")
    st.subheader(f"""Welcome to your Ai Password Recovery Tool!
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

    tab1,tab2,tab3,tab4 = st.tabs(["Hash lists" , "Windows Artifacts" , "Manual entry" , "Document upload"])

    with tab1:
        hash_file = st.file_uploader("Upload a hash file" , type = ['txt','csv'])

    with tab2:
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

    with tab3:
        hash_input = st.text_input("Input hash")
        col1,col2 = st.columns(2)
        with col1:
            hash_type = st.selectbox("Hash type",["MD5","SHA-256","NTLM","MS Office 2013"])
        with col2:
            salt_format = st.selectbox("Salt format",["Unsalted","hash:salt","salt:hash","hash:salt:pass"])
        if st.button("Save input"):
            st.session_state['target_hashes'].append(f"{hash_type} - {hash_input}")
            st.success("Hash input saved")
            log_event(f"Manual input: {hash_type} (Format: {salt_format})")
    
    with tab4:
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

        dictionary_source = st.radio("Select Dictionary Source:" , ["Upload Wordlist" , "Use Golden Dictionary"])
        if dictionary_source == "Upload Wordlist":
            uploaded_dictionary = st.file_uploader("Upload wordlist")
            if uploaded_dictionary is not None:
                st.session_state['wordlist_file'] = uploaded_dictionary
                st.success("Dictionary loaded successfully.")

        elif dictionary_source == "Use Golden Dictionary":
            if st.button("Load Golden Dictionary"):
                try:
                    st.session_state['wordlist_file'] = open("golden_dictionary.txt" , "rb")
                    st.success("Golden Dictionary loaded.")
                except FileNotFoundError:
                    st.error("No golden dictionary found. Have you cracked any passwords yet?")

        with st.expander("Rule Selection"):
            st.write("Select rules to apply to the dictionary:")
            year_rule = st.checkbox("Append Year")
            leet_rule = st.checkbox("Leet Speak Substitution")
            capitalize_rule = st.checkbox("Capitalize First letter")
            reverse_rule = st.checkbox("Reverse word")

            st.markdown("-----------------")
            st.write('Custom User Rules')
            
            col_1c,col_2c = st.columns(2)
            with col_1c:
                custom_prefix = st.text_input("Add Prefix (start)", placeholder="e.g. Admin")
            with col_2c:
                custom_suffix = st.text_input("Add Suffix (end)", placeholder="e.g. !")

            current_rules = {
                "append_year": year_rule,
                "leet_speak": leet_rule,
                "custom_prefix": custom_prefix,
                "custom_suffix": custom_suffix,
                "capitalize_rule": capitalize_rule,
                "reverse_rule": reverse_rule
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
            
            st.success("Starting recovery process....")

            with open("progress.json" , "w") as f:
                json.dump({"progress":0.0, "state":"running","password":None, "time": 0}, f)

            backend = subprocess.Popen(["python" , "backend.py"])

            progress_bar = st.progress(0.0)
            status_text = st.empty()

            while True:
                try:
                    with open("progress.json" , "r") as f:
                        progress_status = json.load(f)

                    current_progress = progress_status.get("progress", 0.0)
                    progress_bar.progress(current_progress)
                    status_text.text(f"Checking dictionary.... {int(current_progress * 100)}%")

                    if progress_status.get("state") == "found":
                        progress_bar.progress(1.0)
                        status_text.empty()
                        st.balloons()
                        st.success("**Password found**")

                        password = progress_status.get('password')
                        total_time = round(progress_status.get('time' , 0), 4)

                        st.metric("Password found" , password)
                        st.caption(f"Time taken: {total_time} seconds")
                        log_event(f"Success: Recovered {password}")
                        break

                    elif progress_status.get("state") == "failed":
                        progress_bar.progress(1.0)
                        status_text.empty()
                        st.error("Password not found in dictionary.")
                        log_event("Attack failed.")
                        break

                except (FileNotFoundError, json.JSONDecodeError):
                    pass

                time.sleep(0.5)

########### Audit and Report page ##########

elif page == "Audit and Report Page":
    st.title("Forensic Audit Log")

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