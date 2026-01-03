import os
import json
import sys
from pypassport import epassport
from pypassport.epassport import EPassport
from pypassport.reader import ReaderManager

# --- CONFIGURATION ---
# Insert here the correct MRZ 
MRZ_STRING = "YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "..", "dumps")

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def encode_binary(obj):
    """Converte bytes in stringhe per il salvataggio JSON (metadata)."""
    if isinstance(obj, dict):
        return {k: encode_binary(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [encode_binary(item) for item in obj]
    elif isinstance(obj, bytes):
        return obj.decode('latin1').encode('unicode_escape').decode('ascii')
    else:
        return obj

def save_datagroup(ep, tag_id, filename_suffix, is_binary=True):
    """Helper per salvare i DataGroup in modo sicuro."""
    try:
        dg_object = ep[tag_id]
        
        if is_binary:
            if hasattr(dg_object, 'file'):
                data_to_save = dg_object.file
            elif hasattr(dg_object, 'encoded'):
                data_to_save = dg_object.encoded
            else:
                data_to_save = bytes(dg_object)
            
            out_path = os.path.join(OUTPUT_DIR, f"{MRZ_STRING}-{filename_suffix}.bin")
            with open(out_path, "wb") as f:
                f.write(data_to_save)
            print(f"[OK] Salvato BINARIO: {out_path} (Tipo: {type(data_to_save)})")

        else:
            clean_data = encode_binary(dg_object)
            json_str = json.dumps(clean_data, indent=3)
            out_path = os.path.join(OUTPUT_DIR, f"{MRZ_STRING}-{filename_suffix}.json")
            with open(out_path, "w") as f:
                f.write(json_str)
            print(f"[OK] Salvato JSON:   {out_path}")

    except Exception as e:
        print(f"[ERRORE] Fallito salvataggio {filename_suffix} (Tag {tag_id}): {e}")

def main():
    print(f"=== EPassport Scanner CLI ===")
    print(f"Output Directory: {OUTPUT_DIR}")
    ensure_dir(OUTPUT_DIR)

    print("In attesa del lettore e della carta...")
    reader_manager = ReaderManager()
    reader = reader_manager.waitForCard()
    
    print(f"Carta rilevata. Tentativo accesso BAC con MRZ: {MRZ_STRING}")
    ep = EPassport(reader, MRZ_STRING)
    
    
    # 1. DG1 
    save_datagroup(ep, "61", "DG1", is_binary=True)
    save_datagroup(ep, "61", "DG1-Meta", is_binary=False)

    # 2. DG2 (Photo)
    save_datagroup(ep, "75", "DG2", is_binary=True) 
    try:
        photo_data = ep["75"]["A1"]["5F2E"]
        photo_path = os.path.join(OUTPUT_DIR, f"{MRZ_STRING}-photo.jpg")
        with open(photo_path, "wb") as f:
            f.write(photo_data)
        print(f"[OK] Foto estratta:  {photo_path}")
    except Exception as e:
        print(f"[WARN] Impossibile estrarre anteprima JPG: {e}")

    # 3. SOD (Security Object) 
    save_datagroup(ep, "77", "SOD", is_binary=True)

    print("\n--- Scansione Completata ---")
    print(f"I file sono pronti in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
