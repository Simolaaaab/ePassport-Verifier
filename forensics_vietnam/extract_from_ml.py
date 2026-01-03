import os
from asn1crypto import cms, x509, core

class Colors:
    GREEN = '\033[92m'
    ENDC = '\033[0m'
    
# --- ICAO MASTER LIST STRUCTURE DEFINITION ---
# We need to teach Python how the list inside the envelope is structured
class CscaMasterList(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('cert_list', core.SetOf, {'spec': x509.Certificate})
    ]

# --- CONFIGURATION ---
# Place here the EXACT path of the .ml (or .p7m) file downloaded from BSI
# Assuming the masterlist file is in the data folder or root, adjust if necessary
masterlist_path = "../data/DE_ML_2025-11-27-07-39-21.ml" 
output_dir = "../data/certs"

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

print(f"Analyzing file: {masterlist_path}")

try:
    with open(masterlist_path, 'rb') as f:
        data = f.read()
    
    # 1. Load CMS structure (the "Envelope")
    content_info = cms.ContentInfo.load(data)
    signed_data = content_info['content']
    
    print("CMS envelope opened successfully.")
    
    # 2. Extract encapsulated content (the "Letter" inside the envelope)
    # encap_content_info contains the OID and the actual content
    encap_content = signed_data['encap_content_info']
    content_bytes = encap_content['content'].native
    
    print(f"Content extracted ({len(content_bytes)} bytes). Decoding list...")

    # 3. Decode Master List using the structure defined above
    master_list = CscaMasterList.load(content_bytes)
    certs = master_list['cert_list']
    
    print(f"\n{Colors.GREEN}--> SUCCESS! Found {len(certs)} certificates in the list.{Colors.ENDC}\n")
    
    found_vietnam = False
    
    for i, cert in enumerate(certs):
        # To be safe, reload the object to have all properties available
        # (Sometimes asn1crypto optimizes and doesn't load everything immediately)
        cert_obj = x509.Certificate.load(cert.dump())
        subject = cert_obj.subject.human_friendly
        
        # Visual filter to understand what is happening
        if "VN" in subject or "VNM" in subject:
            print(f"[{i}] Target found: {subject}")
            filename = os.path.join(output_dir, f"VIETNAM_CSCA_{i}.cer")
            with open(filename, 'wb') as f:
                f.write(cert.dump())
            print(f"    --> SAVED TO: {filename}")
            found_vietnam = True
        
        # Uncomment the line below if you want to save ALL certificates
        # with open(os.path.join(output_dir, f"cert_{i}.cer"), 'wb') as f: f.write(cert.dump())

    if not found_vietnam:
        print("\nWARNING: No certificate with 'Vietnam' or 'VN' in the name found.")
        print("Attempting to print the first 10 names to see what's inside:")
        for i, cert in enumerate(certs):
            if i >= 10: break
            print(f" - {x509.Certificate.load(cert.dump()).subject.human_friendly}")

except Exception as e:
    print(f"Error: {e}")
    print("Ensure the file is a binary .ml (DER) and not PEM (text).")
