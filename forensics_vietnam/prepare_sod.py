import os

def unwrap_sod(raw_bytes):
    """
    Removes the ICAO wrapper (Tag 0x77 and length) to expose 
    the PKCS#7 structure (Tag 0x30) directly.
    """
    if not raw_bytes: return raw_bytes
    
    # If it already starts with 0x30, it is already clean
    if raw_bytes[0] == 0x30: 
        return raw_bytes
        
    try:
        idx = 1
        # Check for tag 0x77 (Response Message Template)
        if raw_bytes[0] == 0x77:
            # Skip length bytes
            idx += 1 if raw_bytes[idx] < 0x80 else 1 + (raw_bytes[idx] & 0x7f)
            
            # Check for optional but common tag 0x82 (Response Data)
            if idx < len(raw_bytes) and raw_bytes[idx] == 0x82:
                idx += 1
                idx += 1 if raw_bytes[idx] < 0x80 else 1 + (raw_bytes[idx] & 0x7f)
            
            # Return everything from here onwards (should be 0x30...)
            return raw_bytes[idx:]
    except:
        pass
        
    # If parsing fails, return original
    return raw_bytes

# --- CONFIGURATION ---
# Path to the extracted Vietnamese SOD (Relative to forensics_vietnam/ folder)
INPUT_FILE = "../data/dumps/SOD.bin"
OUTPUT_FILE = "../data/dumps/SOD_CLEAN.bin"

# --- EXECUTION ---
if __name__ == "__main__":
    if os.path.exists(INPUT_FILE):
        with open(INPUT_FILE, 'rb') as f_in:
            raw_data = f_in.read()
            
        clean_data = unwrap_sod(raw_data)
        
        with open(OUTPUT_FILE, 'wb') as f_out:
            f_out.write(clean_data)
            
        print(f"[OK] Clean file generated: {OUTPUT_FILE}")
        print(f"     Now you can use it with 'openssl cms ...'")
    else:
        print(f"[ERROR] File not found: {INPUT_FILE}")
