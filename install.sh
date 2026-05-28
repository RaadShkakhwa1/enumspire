#!/bin/bash
echo "[*] Installing EnumSpire..."

# Ensure the script is executable
chmod +x src/enumspire.py

# Create the global system link
sudo ln -sf $(pwd)/src/enumspire.py /usr/local/bin/enumspire

echo "[+] Install Complete! You can now type 'enumspire' from any folder."
