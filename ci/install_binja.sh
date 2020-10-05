#!/bin/bash

set -euo pipefail

# Decrypt any CI secrets
function decrypt {
    if [[ -f ${1}.gpg ]]
    then
        echo "Decrypting file: ${1}.gpg"
        gpg --quiet --batch --yes --decrypt \
            --passphrase="${BINJA_DECODE_KEY}" \
            --output "${1}" "${1}.gpg" 
    else
        echo "Could not find file: ${1}.gpg"
        return 1
    fi
}

EXTRACT_DIR=${VIRTUAL_ENV:-"/opt/vector35/binaryninja"}

echo "Decrypting Binja..."
decrypt BinaryNinja-headless.zip
echo "Decrypting license..."
decrypt license.txt

#Run this from the bmef root directory and it will install Binja for you
unzip BinaryNinja-headless.zip -d ${EXTRACT_DIR}
mkdir -p ~/.binaryninja/
cp license.txt ~/.binaryninja/license.dat
chmod +x ${EXTRACT_DIR}/binaryninja/scripts/linux-setup.sh
${EXTRACT_DIR}/binaryninja/scripts/linux-setup.sh -s -d -m -l &> /dev/null
# virtual env, use -v; if not don't use it
python3 ${EXTRACT_DIR}/binaryninja/scripts/install_api.py ${VIRTUAL_ENV+"-v"}
