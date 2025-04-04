import streamlit as st
import os
import datetime
import json
import hashlib
import base64

# Secrets management
SECRETS = {
    "BarcodeLoader": st.secrets.get("SECRET_BARCODELOADER", os.getenv("SECRET_BARCODELOADER")),
    "FeatureFinder": st.secrets.get("SECRET_FEATUREFINDER", os.getenv("SECRET_FEATUREFINDER"))
}



# Function to generate a unique license key based on robot serial number
def generate_license_key(license_type, serial):
    # Define the license data
    license_data = {
        "robot_serial_number": serial,
        "secret": SECRETS.get(license_type, "INVALID_LICENSE_TYPE")
    }

    # Serialize the data as JSON
    license_data_json = json.dumps(license_data)
    # print(license_data_json)


    # Create a license key by hashing the JSON data
    license_key = hashlib.sha256(license_data_json.encode()).digest()

    # Encode the binary key as a base64 string
    license_key_base64 = base64.b64encode(license_key).decode()

    return license_key_base64

# Streamlit UI
st.title("🔑 License Generator")

# Initialize session state
if 'license_text' not in st.session_state:
    st.session_state.license_text = None

# Form for input
with st.form("license_form"):
    license_type = st.selectbox(
        "License Type",
        options=["BarcodeLoader", "FeatureFinder"],
        index=0
    )
    serial = st.text_input("Serial Number")
    submitted = st.form_submit_button("Generate")
    
    if submitted and license_type and serial:
        st.session_state.license_text = generate_license_key(license_type, serial)

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