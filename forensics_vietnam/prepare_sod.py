import os

def unwrap_sod(raw_bytes):
    """
    Rimuove il wrapper ICAO (Tag 0x77 e lunghezza) per esporre
    direttamente la struttura PKCS#7 (Tag 0x30).
    """
    if not raw_bytes: return raw_bytes
    
    # Se inizia già con 0x30, è già pulito
    if raw_bytes[0] == 0x30: 
        return raw_bytes
        
    try:
        idx = 1
        # Controlla se c'è il tag 0x77 (Response Message Template)
        if raw_bytes[0] == 0x77:
            # Salta i byte della lunghezza
            idx += 1 if raw_bytes[idx] < 0x80 else 1 + (raw_bytes[idx] & 0x7f)
            
            # Controlla se c'è il tag 0x82 (Response Data) opzionale ma comune
            if idx < len(raw_bytes) and raw_bytes[idx] == 0x82:
                idx += 1
                idx += 1 if raw_bytes[idx] < 0x80 else 1 + (raw_bytes[idx] & 0x7f)
            
            # Restituisce tutto da qui in poi (dovrebbe essere 0x30...)
            return raw_bytes[idx:]
    except:
        pass
        
    # Se fallisce il parsing, restituisce l'originale
    return raw_bytes

# --- CONFIGURAZIONE ---
# Metti qui il percorso del tuo SOD vietnamita estratto
INPUT_FILE = "dumps/SOD.bin"
OUTPUT_FILE = "dumps/SOD_CLEAN.bin"

# --- ESECUZIONE ---
if __name__ == "__main__":
    if os.path.exists(INPUT_FILE):
        with open(INPUT_FILE, 'rb') as f_in:
            raw_data = f_in.read()
            
        clean_data = unwrap_sod(raw_data)
        
        with open(OUTPUT_FILE, 'wb') as f_out:
            f_out.write(clean_data)
            
        print(f"[OK] Generato file pulito: {OUTPUT_FILE}")
        print(f"     Ora puoi usarlo con 'openssl cms ...'")
    else:
        print(f"[ERRORE] File non trovato: {INPUT_FILE}")
