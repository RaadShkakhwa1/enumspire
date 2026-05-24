import subprocess
import sys
from parser import parse_nmap_xml  # <-- Importing your parser file!

def execute_nmap(nmap_command, workspace_dir):
    """Executes the Nmap command and hands the results to the parser."""
    xml_file = f"{workspace_dir}/nmap_scan.xml"
    
    # Insert the XML output flag right before the target IP
    target = nmap_command.pop()
    nmap_command.extend(["-oX", xml_file, target])
    
    try:
        subprocess.run(nmap_command, check=True, timeout=900)
        print(f"[+] Nmap scan complete. Results saved to {xml_file}")
        
        # Hand the file to parser.py to extract the services
        parsed_services = parse_nmap_xml(xml_file)
        return parsed_services
        
    except subprocess.TimeoutExpired:
        print("[!] FATAL: Nmap scan timed out after 15 minutes.")
        sys.exit(1)
    except FileNotFoundError:
        print("[!] FATAL: Nmap is not installed or not in your system PATH.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] FATAL: Nmap execution failed: {e}")
        sys.exit(1)
