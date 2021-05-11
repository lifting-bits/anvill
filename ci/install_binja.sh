#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

set -euo pipefail

# Decrypt any CI secrets
function decrypt {
    if [[ -f ${1} ]]
    then
      echo "Skipping ${1}; already decrypted"
      return 0
    fi

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
mkdir -p "${EXTRACT_DIR}"

echo "Decrypting Binja..."
decrypt ${DIR}/BinaryNinja-headless.zip
echo "Decrypting license..."
decrypt ${DIR}/license.txt

#Run this from the bmef root directory and it will install Binja for you
unzip ${DIR}/BinaryNinja-headless.zip -d "${EXTRACT_DIR}"
mkdir -p ~/.binaryninja/
cp ${DIR}/license.txt ~/.binaryninja/license.dat
chmod +x "${EXTRACT_DIR}/binaryninja/scripts/linux-setup.sh"
"${EXTRACT_DIR}/binaryninja/scripts/linux-setup.sh" -s -d -m -l &> /dev/null
# virtual env, use -v; if not don't use it
python3.8 "${EXTRACT_DIR}/binaryninja/scripts/install_api.py" ${VIRTUAL_ENV+"-v"}
