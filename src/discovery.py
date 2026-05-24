import subprocess
import sys

def execute_rustscan(target_ip):
    """Runs RustScan to quickly discover open ports."""
    command = ["rustscan", "-a", target_ip, "-g"]
    
    try:
        # 5-minute timeout constraint
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
        output = result.stdout
        
        # Parse the greppable RustScan output (e.g., 127.0.0.1 -> [80,443])
        if "->" in output:
            ports_section = output.split("->")[1].strip()
            ports = ports_section.replace("[", "").replace("]", "")
            print(f"[+] RustScan discovered open ports: {ports}")
            return ports
        else:
            print("[-] RustScan did not find any open ports.")
            return None
            
    except subprocess.TimeoutExpired:
        print("[!] FATAL: RustScan timed out after 5 minutes.")
        sys.exit(1)
    except FileNotFoundError:
        print("[!] FATAL: RustScan is not installed or not in your system PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("[!] FATAL: RustScan encountered an error. Is the target online?")
        sys.exit(1)
    except Exception as e:
        print(f"[!] FATAL: RustScan execution failed: {e}")
        sys.exit(1)
