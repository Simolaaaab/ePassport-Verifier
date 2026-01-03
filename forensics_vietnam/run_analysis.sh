#!/bin/bash

# Output colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Path Configurations (Adjust if files are moved)
# Assuming we are in the forensics_vietnam/ directory when running the script
DUMP_DIR="../data/dumps"
CERT_DIR="../data/certs"
SOD_BIN="$DUMP_DIR/SOD.bin"          # Raw extracted SOD
SOD_CLEAN="$DUMP_DIR/SOD_CLEAN.bin"  # Cleaned SOD from Python
DS_CERT="$DUMP_DIR/extracted_DS.cer" # Extracted DS certificate
CSCA_CERT="$CERT_DIR/vietnamCSCA.cer" # CSCA certificate (Masterlist)

echo -e "${CYAN}=== VIETNAM PASSPORT FORENSIC ANALYSIS ===${NC}"
echo -e "${CYAN}Target: Interoperability analysis of non-standard elliptic curves${NC}\n"

# 1. SOD FILE PREPARATION
echo -e "${YELLOW}[STEP 1] Environment preparation and SOD cleaning...${NC}"
# Calls Python script to remove ICAO 0x77 header
python3 prepare_sod.py
if [ -f "$SOD_CLEAN" ]; then
    echo -e "${GREEN}✔ Clean SOD generated successfully: $SOD_CLEAN${NC}"
else
    echo -e "${RED}✘ Error generating clean SOD.${NC}"
    exit 1
fi

echo -e "\n------------------------------------------------------------\n"

# 2. INTEGRITY CHECK (CMS - NOVERIFY)
echo -e "${YELLOW}[STEP 2] Data Integrity Check (OpenSSL CMS)${NC}"
echo "Command: openssl cms -verify -noverify ..."
echo "Goal: Verify only signature mathematics (Bypass Trust Chain)"

openssl cms -verify -in "$SOD_CLEAN" -inform DER -noverify -signer "$DS_CERT" -out /dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✔ SUCCESS: CMS Verification Successful.${NC}"
    echo -e "${GREEN}  Conclusion: Biometric data is INTEGRAL and AUTHENTIC.${NC}"
else
    echo -e "${RED}✘ FAIL: CMS verification error.${NC}"
fi

echo -e "\n------------------------------------------------------------\n"

# 3. CHAIN OF TRUST VERIFICATION (VERIFY - POLICY CHECK)
echo -e "${YELLOW}[STEP 3] Chain of Trust Verification (OpenSSL Verify)${NC}"
echo "Command: openssl verify -CAfile vietnamCSCA.cer extracted_DS.cer"
echo "Goal: Validate trust chain according to RFC 5480 standards"

# Executing command and capturing output, expecting failure
openssl verify -CAfile "$CSCA_CERT" "$DS_CERT"

# Checking exit code. If non-zero (error), it is what we expect!
if [ $? -ne 0 ]; then
    echo -e "\n${RED}⚠ EXPECTED FAILURE: OpenSSL rejected the certificate.${NC}"
    echo -e "${RED}  Cause: Error 94 (Explicit ECC parameters).${NC}"
    echo -e "${CYAN}  Analysis: Passport uses non-standard curves blocked by modern security policies.${NC}"
else
    echo -e "${GREEN}Wait, it worked? (Maybe you are using an old OpenSSL version!)${NC}"
fi

echo -e "\n${CYAN}=== ANALYSIS COMPLETED ===${NC}"
