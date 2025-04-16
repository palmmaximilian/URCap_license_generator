import streamlit as st
import os
import datetime
import json
import hashlib
import base64
import io
import zipfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


def generate_and_bundle_keys():
    # Generate keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Create in-memory zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr('private_key.pem', private_pem)
        zip_file.writestr('public_key.pem', public_pem)
    
    zip_buffer.seek(0)
    
    return zip_buffer
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import json
import base64
import datetime
from dateutil.relativedelta import relativedelta

def generate_license(license_type, serial, expiration_date):
    """
    Generates a secure license with hardware binding and anti-tamper features
    
    Args:
        license_type: Type of license (e.g., "BarcodeLoader")
        serial: Robot serial number
        expiration_date: Date string in YYYY-MM-DD format
        
    Returns:
        JSON string containing signed license data
    """
    # Load private key securely from Streamlit secrets
    private_key_pem = st.secrets["keys"][f"SECRET_{license_type.upper()}"]    
    if not private_key_pem:
        raise ValueError(f"No private key found for license type {license_type}")

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}")


    # Build license data with multiple time references
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H:%M:%S")
    license_data = {
        "robot_serial_number": serial,
        "issue_date": now,
        "expiration_date": expiration_date,
        "time_guard": {
            "generation_timestamp": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "max_clock_skew": 86400  # 1 day in seconds
        }
    }

    # Create signature with additional context
    signing_payload = {
        "data": license_data
    }
    
    payload_json = json.dumps(signing_payload, sort_keys=True).encode('utf-8')
    
    try:
        signature = private_key.sign(
            payload_json,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

    # Build final license structure
    license = {
        "schema_version": "2.0",
        "data": license_data,
        "signature": base64.b64encode(signature).decode('utf-8')
    }

    return json.dumps(license, indent=2)


def send_license_email(serial_number, reference,product, license_content):
    msg = MIMEMultipart()
    msg['Subject'] = f'New License Generated - {reference} - {serial_number}'
    msg['From'] = st.secrets["email"]["sender"]
    msg['To'] = st.secrets["email"]["recipient"]  # Always send to yourself
    
    # Attach license as .lic file
    license_file = MIMEApplication(license_content)
    license_file.add_header('Content-Disposition', 'attachment', 
                          filename=f'license_{product}_{serial_number}.lic')
    msg.attach(license_file)
    
    # Add security warning to body
    msg.attach(MIMEText(f"""
    Security Alert: A new license was generated for:
    Reference: {reference}
    Serial Number: {serial_number}
    Timestamp: {datetime.datetime.now().isoformat()}
    """))

    try:
        with smtplib.SMTP_SSL(st.secrets["email"]["mailserver"], st.secrets["email"]["smtp_port"]) as server:
            server.login(st.secrets["email"]["sender"], 
                        st.secrets["email"]["password"])
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Failed to send license: {e}")
        return False

# Streamlit UI
st.title("🔑 License Generator")

# Initialize session state
if 'license_text' not in st.session_state:
    st.session_state.license_text = None


if st.button("Generate Key Pair"):
    zip_buffer = generate_and_bundle_keys()
    
    st.success("Key pair generated successfully!")
    
    st.download_button(
        label="Download Key Pair (ZIP)",
        data=zip_buffer,
        file_name="key_pair.zip",
        mime="application/zip"
    )
    

# Form for input
with st.form("license_form"):
    license_type = st.selectbox(
        "License Type",
        options=["BarcodeLoader", "FeatureFinder"],
        index=0
    )

    serial = st.text_input("Serial Number")
    reference= st.text_input("Reference")

    end_date = st.date_input("Expiration Date", value=datetime.datetime.now() + relativedelta(years=100), min_value="today", max_value= datetime.datetime.now() + relativedelta(years=100),format="YYYY-MM-DD", label_visibility="visible")
    # end_date = st.date_input("Expiration Date",format="YYYY-MM-DD", label_visibility="visible")

    submitted = st.form_submit_button("Generate")
    
    # if submitted and license_type and serial:
    #     st.session_state.license_text = generate_license_key(license_type, serial)
    if submitted and license_type and serial:
        st.session_state.license_text = generate_license(license_type, serial,"2026-12-31_00-00-00")
        license_content = st.session_state.license_text
        # Send via email instead of offering download
        if send_license_email(serial, reference, license_type, license_content):
            st.success("License generated and sent to secure inbox!")
            st.balloons()
            
            # No license shown/downloadable in UI
            st.info("Check your secure email for the license file")

# Display and download outside the form
if st.session_state.license_text:
    st.code(st.session_state.license_text, language="text")
    date_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fileLabel="license_"+serial+"_"+date_time+".lic"
    st.download_button(
        label="Download License",
        data=st.session_state.license_text,
        file_name=fileLabel,
        mime="text/plain"
    )