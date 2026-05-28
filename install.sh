#!/bin/bash

echo "[*] Installing EnumSpire System-Wide..."

# --- 1. Dependency Management ---
echo "[*] Checking dependencies..."
if ! command -v rustscan &> /dev/null; then
    echo "[!] RustScan not found. Downloading and installing..."
    wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
    sudo dpkg -i rustscan_2.0.1_amd64.deb
    rm rustscan_2.0.1_amd64.deb
else
    echo "[+] RustScan is already installed."
fi

# --- 2. System Permissions & Linking ---
echo "[*] Configuring global execution..."

# Find the exact folder where the user downloaded the tool
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Force executable permissions on the Python script
chmod +x "$SCRIPT_DIR/src/enumspire.py"

# Create the global system link
sudo ln -sf "$SCRIPT_DIR/src/enumspire.py" /usr/local/bin/enumspire

echo "[+] Install Complete! You can now run 'enumspire' from anywhere."
