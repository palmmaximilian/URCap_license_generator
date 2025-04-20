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

import hmac
import json
from dateutil.relativedelta import relativedelta


def generate_and_bundle_keys():


    # Generate keys (same cryptographic material)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Serialize in PKCS1 format for better compatibility
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS1
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1  # PKCS1 instead of SubjectPublicKeyInfo
    )
    
    
    # Create in-memory zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr('private_key.pem', private_pem)
        zip_file.writestr('public_key.pem', public_pem)
    
    zip_buffer.seek(0)
    
    return zip_buffer


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
        public_key = private_key.public_key()
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}")

    # Build license data with multiple time references
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    license_data = {
        "robot_serial_number": serial,
        "issue_date": now,
        "expiration_date": expiration_date,
        "time_guard": {
            "generation_timestamp": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "max_clock_skew": 86400  # 1 day in seconds
        }
    }

    payload_json = json.dumps(license_data, 
        sort_keys=True,
        separators=(',', ':')  # Removes all whitespace
    ).encode('utf-8')

    try:
        signature = private_key.sign(
            payload_json,
            padding.PKCS1v15(),  # Changed from PSS to PKCS#1 v1.5
            hashes.SHA256()
        )
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

    # Immediate verification
    try:
        public_key.verify(
            signature,
            payload_json,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("✅ Signature verified successfully")
    except Exception as e:
        raise ValueError(f"🚨 Signature verification failed: {str(e)}")

    # Build final license structure
    license = {
        "schema_version": "2.0",
        "data": json.loads(payload_json),
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



# Initialize session state
if 'license_text' not in st.session_state:
    st.session_state.license_text = None

st.title("🛠️ Key Pair Generator")

if st.button("Generate Key Pair"):
    zip_buffer = generate_and_bundle_keys()
    
    st.success("Key pair generated successfully!")
    
    st.download_button(
        label="Download Key Pair (ZIP)",
        data=zip_buffer,
        file_name="key_pair.zip",
        mime="application/zip"
    )

st.markdown("---")

st.title("📄 License Generator")



# Form for input
with st.form("license_form"):
    license_type = st.selectbox(
        "License Type",
        options=["ScanPilot", "FeatureFinder"],
        index=0
    )

    serial = st.text_input("Serial Number")
    reference= st.text_input("Reference")

    end_date = st.date_input("Expiration Date", value=datetime.datetime.now() + relativedelta(years=100), max_value= datetime.datetime.now() + relativedelta(years=100),format="YYYY-MM-DD", label_visibility="visible")

    submitted = st.form_submit_button("Generate")
    
    if submitted and license_type and serial:
        license_content = generate_license(license_type, serial,end_date.strftime("%Y-%m-%d_%H-%M-%S"))

         
        # Send via email instead of offering download
        if send_license_email(serial, reference, license_type, license_content):
            st.success("License generated and sent to secure inbox!")
            st.balloons()
            
            # No license shown/downloadable in UI
            st.info("Check your secure email for the license file")
st.markdown("---")
st.header("🔍 Validate Existing License")

uploaded_license = st.file_uploader("Upload license file (.lic)", type=["lic"])
validation_license_type = st.selectbox(
    "License Type for Validation",
    options=["ScanPilot", "FeatureFinder"],
    index=0,
    key="validation_type"
)

if uploaded_license:
    try:
        license_content = uploaded_license.read().decode("utf-8")
        license_json = json.loads(license_content)

        # Extract the signature and payload
        signature = base64.b64decode(license_json["signature"])
        payload_json = json.dumps(
            license_json["data"],
            sort_keys=True,
            separators=(',', ':')
        ).encode("utf-8")

        # Load private key from secrets, then extract public key
        private_key_pem = st.secrets["keys"][f"SECRET_{validation_license_type.upper()}"]
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None
        )
        public_key = private_key.public_key()

        # Verify signature
        public_key.verify(
            signature,
            payload_json,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        st.success("✅ License is valid and untampered.")
        st.json(license_json["data"])

    except Exception as e:
        st.error(f"🚨 License validation failed: {str(e)}")
