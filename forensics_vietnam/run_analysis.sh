#!/bin/bash

# Colori per l'output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configurazioni Path (Adattale se sposti i file)
# Assumiamo di essere nella root del progetto quando lanciamo lo script
DUMP_DIR="../data/dumps"
CERT_DIR="../data/certs"
SOD_BIN="$DUMP_DIR/SOD.bin"          # Il SOD grezzo estratto
SOD_CLEAN="$DUMP_DIR/SOD_CLEAN.bin"  # Il SOD pulito da Python
DS_CERT="$DUMP_DIR/extracted_DS.cer" # Il certificato DS estratto
CSCA_CERT="$CERT_DIR/vietnamCSCA.cer" # Il certificato CSCA (Masterlist)

echo -e "${CYAN}=== VIETNAM PASSPORT FORENSIC ANALYSIS ===${NC}"
echo -e "${CYAN}Target: Analisi interoperabilità curve ellittiche non standard${NC}\n"

# 1. PREPARAZIONE DEL FILE SOD
echo -e "${YELLOW}[STEP 1] Preparazione ambiente e pulizia SOD...${NC}"
# Chiama lo script Python per rimuovere l'header ICAO 0x77
python3 prepare_sod.py
if [ -f "$SOD_CLEAN" ]; then
    echo -e "${GREEN}✔ SOD pulito generato correttamente: $SOD_CLEAN${NC}"
else
    echo -e "${RED}✘ Errore nella generazione del SOD pulito.${NC}"
    exit 1
fi

echo -e "\n------------------------------------------------------------\n"

# 2. VERIFICA INTEGRITA' (CMS - NOVERIFY)
echo -e "${YELLOW}[STEP 2] Verifica Integrità Dati (OpenSSL CMS)${NC}"
echo "Comando: openssl cms -verify -noverify ..."
echo "Obiettivo: Verificare solo la matematica della firma (Bypass Trust Chain)"

openssl cms -verify -in "$SOD_CLEAN" -inform DER -noverify -signer "$DS_CERT" -out /dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✔ SUCCESS: CMS Verification Successful.${NC}"
    echo -e "${GREEN}  Conclusione: I dati biometrici sono INTEGRI e AUTENTICI.${NC}"
else
    echo -e "${RED}✘ FAIL: Errore nella verifica CMS.${NC}"
fi

echo -e "\n------------------------------------------------------------\n"

# 3. VERIFICA CHAIN OF TRUST (VERIFY - POLICY CHECK)
echo -e "${YELLOW}[STEP 3] Verifica Chain of Trust (OpenSSL Verify)${NC}"
echo "Comando: openssl verify -CAfile vietnamCSCA.cer extracted_DS.cer"
echo "Obiettivo: Validare la catena di fiducia secondo standard RFC 5480"

# Eseguiamo il comando e catturiamo l'output per mostrarlo, ma ci aspettiamo che fallisca
openssl verify -CAfile "$CSCA_CERT" "$DS_CERT"

# Controlliamo l'exit code. Se è diverso da 0 (errore), è quello che ci aspettiamo!
if [ $? -ne 0 ]; then
    echo -e "\n${RED}⚠ EXPECTED FAILURE: OpenSSL ha rifiutato il certificato.${NC}"
    echo -e "${RED}  Causa: Error 94 (Explicit ECC parameters).${NC}"
    echo -e "${CYAN}  Analisi: Il passaporto usa curve non standard bloccate dalle policy di sicurezza moderne.${NC}"
else
    echo -e "${GREEN}Wait, ha funzionato? (Forse hai una versione vecchia di OpenSSL!)${NC}"
fi

echo -e "\n${CYAN}=== ANALISI COMPLETATA ===${NC}"
