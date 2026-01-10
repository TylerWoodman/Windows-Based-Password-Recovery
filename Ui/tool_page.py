import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime
import psutil
import fpdf
from fpdf import FPDF

########## Navigation sidebar ###########

st.set_page_config(page_title="AI Forensic Cracker", layout="wide", page_icon="🔐")

st.sidebar.header("Case Management 📁")
case_id = st.sidebar.text_input("Input Case Reference" , "CASE-0012025")
investigator = st.sidebar.text_input("Input investigator name" , "Woody Woodchip")

page = st.sidebar.radio("Navigation",["Home Page","Hash Page","Attack Page","Recovery Progress Page","Audit and Report Page"])
 
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
                st.session_state['target_hashes'].append("Woody001NTLMHASH")
                st.success("Extracted NTLM hash")
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
        uploaded_dictionary = st.file_uploader("Upload wordlist")

        with st.expander("Rule Selection"):
            st.write("Select rules to apply to the dictionary:")
            st.checkbox("rule1")
            st.checkbox("rule2")
            st.checkbox("rule3")

    elif attack_type == "Rainbow attack":
        st.subheader("Rainbow attack")

    if st.button("Save attack configuration"):
        st.session_state['attack_config'] = attack_type
        st.success(f"Configuration saved: {attack_type}")
        log_event(f"Attack configured: {attack_type}")
        
########### Recovery Progress ###########

elif page == "Recovery Progress Page":
    st.title("Recovery Results 📥")

    if 'attack_config' not in st.session_state:
        st.warning("Please select and configure an attack on the **Attack Page**")
        st.stop()

    current_attack = st.session_state['attack_config']
    st.info(f"Ready to start recovery process using: **{current_attack}**")

    if st.button("Start attack"):
        progress_bar = st.progress(0)
        status_text = st.empty()

        for i in range(100):
            status_text.text(f"Testing possible passwords {i * 400} .... please wait")
            progress_bar.progress(i + 1)
            time.sleep(0.03)

        st.success("**Password found!**")
        st.metric("Recovered Password" , "Password123")

        log_event(f"Success: Recovered password = 'Password123' using {current_attack}")

########### Audit and Report page ##########

elif page == "Audit and Report Page":
    st.title("Forensic Audit Log")

    if st.session_state['audit_log']:
        dataframe_log = pd.DataFrame(st.session_state['audit_log'])
        st.dataframe(dataframe_log, use_container_width=True)

    st.markdown("----------------------------")

    def create_pdf():
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial','B',size=16)
        pdf.cell(40,10, txt="Hello World")

    col1,col2 = st.columns(2)
    with col1:
        st.button("Generate PDF Report")
    with col2:
        st.button("Export log")