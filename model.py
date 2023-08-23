import numpy as np
import streamlit as st
import pickle
import pefile
import math
import tempfile

def classify(exe_path):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(exe_path.read())
        temp_file_path = temp_file.name
    pe = pefile.PE(temp_file_path)
    section_entropies = []
    for section in pe.sections:
        section_data = section.get_data()
        size = len(section_data)
        if size > 0:
            entropy = sum((section_data.count(c) / size) * math.log2(section_data.count(c) / size) for c in set(section_data))
            section_entropies.append(entropy)
    # Extract the required features
    features = {
        'Machine': pe.FILE_HEADER.Machine,
        'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'SectionsMeanEntropy': sum(section_entropies) / len(section_entropies),
        'SectionsMaxEntropy': max(section_entropies),
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'ResourcesMaxEntropy': 6,
        'VersionInformationSize':12,
    }
    resource_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
    if resource_directory.VirtualAddress != 0:
        resource_section = pe.get_section_by_rva(resource_directory.VirtualAddress)
        resource_data = resource_section.get_data()
        resources_entropy = sum((resource_data.count(c) / len(resource_data)) * math.log2(resource_data.count(c) / len(resource_data)) for c in set(resource_data))
        features['ResourcesMaxEntropy'] = resources_entropy
        
        
        for resource_type in resource_directory.entries:
            if hasattr(resource_type, 'name') and resource_type.name.string.decode() == 'VERSIONINFO':
                for resource_id in resource_type.directory.entries:
                    version_info = resource_id.directory.entries[0].data.struct
                    features['VersionInformationSize'] = version_info.Length               

    # Print the extracted features
    lst=[]
    for feature, value in features.items():
        lst.append(value)
    with open('randomModel.pkl', 'rb') as file:
        model = pickle.load(file)
    pred = model.predict([lst])
    if(pred[0]==0):
        return features,"File is safe "
    else:
        return "File contains Ransomware" 
    os.unlink(temp_file_path)