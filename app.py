import streamlit as st
import joblib
import pandas as pd
import numpy as np # For general array/numerical operations, though not directly used in this specific app structure

# Load the saved model and preprocessor
svm_model = joblib.load('svm_model.joblib')
preprocessor = joblib.load('preprocessor.joblib')

# Define features lists (copied from previous steps)
numerical_features = ['duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
categorical_features = ['protocol_type', 'service', 'flag']

# Define unique values for categorical features (from previous steps' outputs)
protocol_type_options = ['tcp', 'udp', 'icmp']
service_options = ['ftp_data', 'other', 'private', 'http', 'remote_job', 'name',
       'netbios_ns', 'eco_i', 'mtp', 'telnet', 'finger', 'domain_u',
       'supdup', 'uucp_path', 'Z39_50', 'smtp', 'csnet_ns', 'uucp',
       'netbios_dgm', 'urp_i', 'auth', 'domain', 'ftp', 'bgp', 'ldap',
       'ecr_i', 'gopher', 'vmnet', 'systat', 'http_443', 'efs', 'whois',
       'imap4', 'iso_tsap', 'echo', 'klogin', 'link', 'sunrpc', 'login',
       'kshell', 'sql_net', 'time', 'hostnames', 'exec', 'ntp_u',
       'discard', 'nntp', 'courier', 'ctf', 'ssh', 'daytime', 'shell',
       'netstat', 'pop_3', 'nnsp', 'IRC', 'pop_2', 'printer', 'tim_i',
       'pm_dump', 'red_i', 'netbios_ssn', 'rje', 'X11', 'urh_i',
       'http_8001']
flag_options = ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'RSTOS0', 'S3',
       'S2', 'OTH']

# Get the exact column order from the X_train_resampled DataFrame
# This is crucial for the preprocessor to work correctly
# From the kernel state, sample_input_df columns provide this order.
feature_columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

# Streamlit app layout
st.set_page_config(page_title="Network Intrusion Detection", layout="wide")

st.title("Network Intrusion Detection System")
st.markdown("Enter the network connection details to predict if it's normal or an anomaly.")

# Create input fields
user_input = {}

st.header("Connection Features")

# Group inputs for better layout
col1, col2, col3 = st.columns(3)

with col1:
    user_input['duration'] = st.number_input('Duration (seconds)', min_value=0, value=0)
    user_input['src_bytes'] = st.number_input('Source Bytes', min_value=0, value=0)
    user_input['dst_bytes'] = st.number_input('Destination Bytes', min_value=0, value=0)
    user_input['land'] = st.selectbox('Land Connection', options=[0, 1], index=0)
    user_input['wrong_fragment'] = st.number_input('Wrong Fragment', min_value=0, value=0)
    user_input['urgent'] = st.number_input('Urgent Packets', min_value=0, value=0)
    user_input['hot'] = st.number_input('Hot Indicators', min_value=0, value=0)
    user_input['num_failed_logins'] = st.number_input('Failed Logins', min_value=0, value=0)
    user_input['logged_in'] = st.selectbox('Logged In', options=[0, 1], index=0)
    user_input['num_compromised'] = st.number_input('Compromised Conditions', min_value=0, value=0)
    user_input['root_shell'] = st.selectbox('Root Shell', options=[0, 1], index=0)
    user_input['su_attempted'] = st.selectbox('SU Attempted', options=[0, 1], index=0)
    user_input['num_root'] = st.number_input('Root Accesses', min_value=0, value=0)
    user_input['num_file_creations'] = st.number_input('File Creations', min_value=0, value=0)

with col2:
    user_input['num_shells'] = st.number_input('Shell Prompts', min_value=0, value=0)
    user_input['num_access_files'] = st.number_input('Access to Files', min_value=0, value=0)
    user_input['num_outbound_cmds'] = st.number_input('Outbound Commands', min_value=0, value=0)
    user_input['is_host_login'] = st.selectbox('Host Login', options=[0, 1], index=0)
    user_input['is_guest_login'] = st.selectbox('Guest Login', options=[0, 1], index=0)
    user_input['count'] = st.number_input('Count', min_value=0, value=0)
    user_input['srv_count'] = st.number_input('Service Count', min_value=0, value=0)
    user_input['serror_rate'] = st.number_input('Serror Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['srv_serror_rate'] = st.number_input('Srv Serror Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['rerror_rate'] = st.number_input('Rerror Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['srv_rerror_rate'] = st.number_input('Srv Rerror Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['same_srv_rate'] = st.number_input('Same Srv Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['diff_srv_rate'] = st.number_input('Diff Srv Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['srv_diff_host_rate'] = st.number_input('Srv Diff Host Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)

with col3:
    user_input['dst_host_count'] = st.number_input('Dst Host Count', min_value=0, value=0)
    user_input['dst_host_srv_count'] = st.number_input('Dst Host Srv Count', min_value=0, value=0)
    user_input['dst_host_same_srv_rate'] = st.number_input('Dst Host Same Srv Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['dst_host_diff_srv_rate'] = st.number_input('Dst Host Diff Srv Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['dst_host_same_src_port_rate'] = st.number_input('Dst Host Same Src Port Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['dst_host_srv_diff_host_rate'] = st.number_input('Dst Host Srv Diff Host Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['dst_host_serror_rate'] = st.number_input('Dst Host Serror Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['dst_host_srv_serror_rate'] = st.number_input('Dst Host Srv Serror Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['dst_host_rerror_rate'] = st.number_input('Dst Host Rerror Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)
    user_input['dst_host_srv_rerror_rate'] = st.number_input('Dst Host Srv Rerror Rate', min_value=0.0, max_value=1.0, value=0.0, step=0.01)

st.header("Categorical Features")
col4, col5, col6 = st.columns(3)
with col4:
    user_input['protocol_type'] = st.selectbox('Protocol Type', options=protocol_type_options)
with col5:
    user_input['service'] = st.selectbox('Service', options=service_options)
with col6:
    user_input['flag'] = st.selectbox('Flag', options=flag_options)


# Predict button
if st.button("Predict"):n    # Convert user input to DataFrame
    input_df = pd.DataFrame([user_input])
    
    # Ensure column order matches the training data features
    input_df = input_df[feature_columns]

    # Preprocess the input
    processed_input = preprocessor.transform(input_df)

    # Make prediction
    prediction = svm_model.predict(processed_input)

    # Display result
    st.subheader("Prediction Result:")
    if prediction[0] == 'normal':
        st.success("The connection is predicted to be: Normal")
    else:
        st.warning("The connection is predicted to be: Anomaly (Intrusion Detected!)")
