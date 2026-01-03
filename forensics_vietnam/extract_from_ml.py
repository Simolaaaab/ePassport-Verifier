import os
from asn1crypto import cms, x509, core


class Colors:
    GREEN = '\033[92m'
    ENDC = '\033[0m'
    
# --- DEFINIZIONE STRUTTURA ICAO MASTER LIST ---
# Dobbiamo insegnare a Python come è fatta la lista dentro la busta
class CscaMasterList(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('cert_list', core.SetOf, {'spec': x509.Certificate})
    ]

# --- CONFIGURAZIONE ---
# Metti qui il percorso ESATTO del file .ml (o .p7m) che hai scaricato dalla BSI
masterlist_path = "DE_ML_2025-11-27-07-39-21.ml" 
output_dir = "extracted_certs_new"

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

print(f"Analisi file: {masterlist_path}")

try:
    with open(masterlist_path, 'rb') as f:
        data = f.read()
    
    # 1. Carichiamo la struttura CMS (la "Busta")
    content_info = cms.ContentInfo.load(data)
    signed_data = content_info['content']
    
    print("Busta CMS aperta correttamente.")
    
    # 2. Estraiamo il contenuto incapsulato (la "Lettera" dentro la busta)
    # encap_content_info contiene l'OID e il contenuto vero e proprio
    encap_content = signed_data['encap_content_info']
    content_bytes = encap_content['content'].native
    
    print(f"Contenuto estratto ({len(content_bytes)} bytes). Decodifica lista...")

    # 3. Decodifichiamo la Master List usando la struttura definita sopra
    master_list = CscaMasterList.load(content_bytes)
    certs = master_list['cert_list']
    
    print(f"\n{Colors.GREEN}--> SUCCESSO! Trovati {len(certs)} certificati nella lista.{Colors.ENDC}\n")
    
    found_vietnam = False
    
    for i, cert in enumerate(certs):
        # Per sicurezza, ricarichiamo l'oggetto per avere tutte le proprietà
        # (A volte asn1crypto ottimizza e non carica tutto subito)
        cert_obj = x509.Certificate.load(cert.dump())
        subject = cert_obj.subject.human_friendly
        
        # Filtro visivo per capire cosa sta succedendo
        if "VN" in subject or "VNM" in subject:
            print(f"[{i}] Trovato target: {subject}")
            filename = os.path.join(output_dir, f"VIETNAM_CSCA_{i}.cer")
            with open(filename, 'wb') as f:
                f.write(cert.dump())
            print(f"    --> SALVATO IN: {filename}")
            found_vietnam = True
        
        # Decommenta la riga sotto se vuoi salvare TUTTI i certificati del mondo
        # with open(os.path.join(output_dir, f"cert_{i}.cer"), 'wb') as f: f.write(cert.dump())

    if not found_vietnam:
        print("\nATTENZIONE: Nessun certificato con 'Vietnam' o 'VN' nel nome trovato.")
        print("Provo a stampare i primi 10 nomi per capire cosa c'è dentro:")
        for i, cert in enumerate(certs):
            if i >= 10: break
            print(f" - {x509.Certificate.load(cert.dump()).subject.human_friendly}")

except Exception as e:
    print(f"Errore: {e}")
    print("Assicurati che il file sia un .ml binario (DER) e non PEM (testo).")
