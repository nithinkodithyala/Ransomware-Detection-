import io
import numpy as np
import streamlit as st
from model import classify

st.title('RANSOMWARE DETECTION')
st.markdown('### What we do?')
st.write('We will scan the .exe files and determine whether the file has Ransomware or not')
hide_streamlit_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)
exe_upload = st.file_uploader(label='Upload .exe File', type='exe')
if exe_upload is not None:
    # Process the uploaded .exe file
    file_contents = exe_upload.read()
    st.write(f"File uploaded: {exe_upload.name}")
    st.write(f"File size: {len(file_contents)} bytes")
    st.subheader("Features:")

    features, result=classify(io.BytesIO(file_contents))
    for key,value in features.items():
        st.write(key,":",value)
    st.write("### Ransomware detection result:", result)