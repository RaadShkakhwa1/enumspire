#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import shutil
# ---------------------------------------------------------
        # PHASE 3: XML Parsing & Cascade Handoff
        # ---------------------------------------------------------
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # 1. Build a dictionary of {port: service_name} for Cascade
            parsed_services = {}
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_num = port.get("portid")
                    service_elem = port.find("service")
                    service_name = service_elem.get("name") if service_elem is not None else "unknown"
                    parsed_services[port_num] = service_name
            
            # 2. Check if we actually found anything
            if not parsed_services:
                print("[-] Nmap did not return any identifiable services to enumerate.")
                sys.exit(0)
                
            print(f"[*] Initiating Phase 3: Handing off {len(parsed_services)} services to Cascade...")
            
            # 3. Setup Cascade variables
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            threads = 50
            no_ping = True
            
            # 4. The Correct Handoff: target_ip, dictionary, workspace_dir, wordlist, threads, no_ping
            generate_cascade_commands(target_ip, parsed_services, out_dir, wordlist, threads, no_ping)
            
            print("[+] EnumSpire pipeline complete! Check your output folder for the execution script.")
            
        except FileNotFoundError:
            print("[-] Error: Nmap XML file not found. Scan may have failed.")
        except Exception as e:
            print(f"[-] Error parsing Nmap results: {e}")# ---------------------------------------------------------
        # PHASE 3: XML Parsing & Cascade Handoff
        # ---------------------------------------------------------
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # 1. Build a dictionary of {port: service_name} for Cascade
            parsed_services = {}
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_num = port.get("portid")
                    service_elem = port.find("service")
                    service_name = service_elem.get("name") if service_elem is not None else "unknown"
                    parsed_services[port_num] = service_name
            
            # 2. Check if we actually found anything
            if not parsed_services:
                print("[-] Nmap did not return any identifiable services to enumerate.")
                sys.exit(0)
                
            print(f"[*] Initiating Phase 3: Handing off {len(parsed_services)} services to Cascade...")
            
            # 3. Setup Cascade variables
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            threads = 50
            no_ping = True
            
            # 4. The Correct Handoff: target_ip, dictionary, workspace_dir, wordlist, threads, no_ping
            generate_cascade_commands(target_ip, parsed_services, out_dir, wordlist, threads, no_ping)
            
            print("[+] EnumSpire pipeline complete! Check your output folder for the execution script.")
            
        except FileNotFoundError:
            print("[-] Error: Nmap XML file not found. Scan may have failed.")
        except Exception as e:
            print(f"[-] Error parsing Nmap results: {e}")import xml.etree.ElementTree as ET

# Import your Cascade engine
try:
    from cascade import generate_cascade_commands
except ImportError:
    print("[-] Error: cascade.py not found. Make sure it is in the same directory.")
    sys.exit(1)

def print_banner():
    banner = """
 ███████╗███╗   ██╗██╗   ██╗███╗   ███╗██████╗ ███████╗██████╗ ██╗██████╗ ███████╗
 ██╔════╝████╗  ██║██║   ██║████╗ ████║██╔══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝
 █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║██████╔╝███████╗██████╔╝██║██████╔╝█████╗  
 ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔═══╝ ╚════██║██╔═══╝ ██║██╔══██╗██╔══╝  
 ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║     ███████║██║     ██║██║  ██║███████╗
 ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
                 Automated Reconnaissance & Enumeration Pipeline
    """
    print(banner)

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="EnumSpire - Automated Reconnaissance")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--ports", help="Manually specify ports (e.g., 80,443)")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    args = parser.parse_args()

    target_ip = args.target

    # Create output directory based on the target IP
    out_dir = f"Enumspire_{target_ip.replace('.', '_')}"
    if not args.dry_run:
        os.makedirs(out_dir, exist_ok=True)

    # ---------------------------------------------------------
    # PHASE 1: Port Discovery (RustScan with Nmap Fallback)
    # ---------------------------------------------------------
    if args.ports:
        open_ports = args.ports
    else:
        if shutil.which("rustscan") is None:
            print("[!] Warning: RustScan is not installed.")
            print(f"[*] Falling back to standard Nmap for full port sweep against {target_ip} (This will take longer)...")
            open_ports = "-"  # Tells Phase 2 Nmap to scan all ports
        else:
            print(f"[*] Initiating Phase 1: RustScan against {target_ip}...")
            rustscan_cmd = f"rustscan -a {target_ip} -g"
            
            if args.dry_run:
                print(f"[DRY-RUN] Would execute: {rustscan_cmd}")
                open_ports = "22,80,443" # Dummy ports for dry-run
            else:
                process = subprocess.run(rustscan_cmd, shell=True, capture_output=True, text=True)
                if "[" in process.stdout and "]" in process.stdout:
                    open_ports = process.stdout.split("[")[1].split("]")[0]
                    print(f"[+] RustScan discovered open ports: {open_ports}")
                else:
                    print("[-] RustScan did not find any open ports or failed to execute.")
                    sys.exit(0)

    # ---------------------------------------------------------
    # PHASE 2: Service Enumeration (Nmap)
    # ---------------------------------------------------------
    print(f"[*] Initiating Phase 2: Nmap deep-scan on ports: {open_ports} ...")
    xml_file = os.path.join(out_dir, "nmap_scan.xml")
    
    # Build the Nmap command dynamically
    nmap_command = ["nmap", "-sV", "-sC", "-p", open_ports, "-oX", xml_file, target_ip]
    
    if args.dry_run:
        print(f"[DRY-RUN] Would execute: {' '.join(nmap_command)}")
    else:
        subprocess.run(nmap_command)
        print(f"[+] Nmap scan complete. Results saved to {xml_file}")

# ---------------------------------------------------------
        # PHASE 3: XML Parsing & Cascade Handoff
        # ---------------------------------------------------------
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # 1. Build a dictionary of {port: service_name} for Cascade
            parsed_services = {}
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_num = port.get("portid")
                    service_elem = port.find("service")
                    service_name = service_elem.get("name") if service_elem is not None else "unknown"
                    parsed_services[port_num] = service_name
            
            # 2. Check if we actually found anything
            if not parsed_services:
                print("[-] Nmap did not return any identifiable services to enumerate.")
                sys.exit(0)
                
            print(f"[*] Initiating Phase 3: Handing off {len(parsed_services)} services to Cascade...")
            
            # 3. Setup Cascade variables
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            threads = 50
            no_ping = True
            
            # 4. The Correct Handoff: target_ip, dictionary, workspace_dir, wordlist, threads, no_ping
            generate_cascade_commands(target_ip, parsed_services, out_dir, wordlist, threads, no_ping)
            
            print("[+] EnumSpire pipeline complete! Check your output folder for the execution script.")
            
        except FileNotFoundError:
            print("[-] Error: Nmap XML file not found. Scan may have failed.")
        except Exception as e:
            print(f"[-] Error parsing Nmap results: {e}")


if __name__ == "__main__":
    main()
