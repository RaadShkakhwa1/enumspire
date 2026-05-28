#!/bin/bash

echo "[*] Installing EnumSpire System-Wide..."

# Magically find the exact folder where the user downloaded the tool
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Force executable permissions on the Python script
chmod +x "$SCRIPT_DIR/src/enumspire.py"

# Create the global system link pointing to that exact folder
sudo ln -sf "$SCRIPT_DIR/src/enumspire.py" /usr/local/bin/enumspire

echo "[+] Install Complete! You can now run 'enumspire' from anywhere."
