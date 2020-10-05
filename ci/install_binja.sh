#!/bin/bash

set -euo pipefail

# Decrypt any CI secrets
function decrypt {
    gpg --quiet --batch --yes --decrypt \
        --passphrase="${BINJA_DECODE_KEY}" \
        --output ${1} ${1}.gpg 
}

EXTRACT_DIR=${VIRTUAL_ENV:-"/opt/vector35/binaryninja"}

decrypt BinaryNinja-headless.zip
decrypt license.txt

#Run this from the bmef root directory and it will install Binja for you
unzip BinaryNinja-headless.zip -d ${EXTRACT_DIR}
mkdir -p ~/.binaryninja/
cp license.txt ~/.binaryninja/license.dat
chmod +x ${EXTRACT_DIR}/binaryninja/scripts/linux-setup.sh
${EXTRACT_DIR}/binaryninja/scripts/linux-setup.sh -s -d -m -l
# virtual env, use -v; if not don't use it
python3 ${EXTRACT_DIR}/binaryninja/scripts/install_api.py ${VIRTUAL_ENV+"-v"}
