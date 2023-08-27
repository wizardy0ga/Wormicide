import sys
from os import system

system("")


BANNER = """
 ▄█     █▄   ▄██████▄     ▄████████   ▄▄▄▄███▄▄▄▄    ▄█   ▄████████  ▄█  ████████▄     ▄████████ 
███     ███ ███    ███   ███    ███ ▄██▀▀▀███▀▀▀██▄ ███  ███    ███ ███  ███   ▀███   ███    ███ 
███     ███ ███    ███   ███    ███ ███   ███   ███ ███▌ ███    █▀  ███▌ ███    ███   ███    █▀  
███     ███ ███    ███  ▄███▄▄▄▄██▀ ███   ███   ███ ███▌ ███        ███▌ ███    ███  ▄███▄▄▄     
███     ███ ███    ███ ▀▀███▀▀▀▀▀   ███   ███   ███ ███▌ ███        ███▌ ███    ███ ▀▀███▀▀▀     
███     ███ ███    ███ ▀███████████ ███   ███   ███ ███  ███    █▄  ███  ███    ███   ███    █▄  
███ ▄█▄ ███ ███    ███   ███    ███ ███   ███   ███ ███  ███    ███ ███  ███   ▄███   ███    ███ 
 ▀███▀███▀   ▀██████▀    ███    ███  ▀█   ███   █▀  █▀   ████████▀  █▀   ████████▀    ██████████ 
                         ███    ███                                                              """

AUTHOR  = "wizardy0ga"
GITHUB  = "https://github.com/wizardy0ga/wormicide"
VERSION = "1.0"

END     = '\033[0m'
BOLD    = '\033[1m'
GREEN   = "\033[0;32m"
RED     = "\033[0;31m"
YELLOW  = "\033[1;33m"
BLUE    = "\033[0;34m"
WHITE   = "\033[0;0m"

OTHER   = f"""
 {BLUE}XWorm Packet Tool{END}
 Author: {GREEN}kali-linex{END}
 Github: {GREEN}https://github.com/kali-linex/xworm-troll{END}

 {BLUE}XDump{END}
 Author: {GREEN}wizardy0ga{END}
 Github: {GREEN}https://github.com/wizardy0ga/XDump{END}
"""

MAIN_DESC = f"""
 {BANNER}{GREEN}{VERSION}{END}
 Author: {GREEN}{AUTHOR}{END}
 Github: {GREEN}{GITHUB}{END}

{OTHER}


{WHITE}Wormicide is a tool that automates the process of seeking out Xworm CnC's and performing 
denial of service attacks on them.  

To capture server details, wormicide queries the malware bazaar api and retrieves a user-defined 
amount of samples. XDump is used to dump the configuration and log the cnc information. Using this 
information, wormicide can perform a port scan, and then launch a denial of service attack on the 
servers. There is also functionality to perform a targeted attack on a single instance of an 
xworm command and control server. Wormicide retains logs from each configuration for re-processing
directly from the logs. 
{END}  


{RED}ATTACK METHODS{END}
    
    {YELLOW}conspam{END}
        {GREEN}Spam the server GUI with fake connections. Renders GUI inoperable.{END}

    {YELLOW}Winspam{END}
        {GREEN}Open various GUI's of Xworm to disturb main window focus.{END}

        
{RED}MODE TYPES{END}

    {YELLOW}passive{END}
        {GREEN}The passive scan will query the samples from the API and extract the configuration. Optionally,
        a port scan can be performed on the server to determine if it's online.{END}

    {YELLOW}active{END}
        {GREEN}Active scanning will extract configurations from live samples through api queries or from the logs.
        The scan checks the server connectivity and proceeds with the specified attack if the server is online.
        If the daemon argument is given, wormicide will background the attack and continue scanning
        for other xworm hosts.{END} 

    {YELLOW}targeted{END}
        {GREEN}Attack a single instance of an xworm server using the host, port and encryption key or through
        extracting a configuration from a sample.{END} 

{RED}Global Arguments{END}

    {BLUE}Argument           Description                                         Default   Type{END}

    {YELLOW}-v, --verbose{GREEN}    | Increase output about what is happening           | False   | bool
    {YELLOW}-a, --amount{GREEN}     | The amount of samples to process from logs or api | 50      | int
    {YELLOW}-t, --timeout{GREEN}    | Timeout for all socket operations                 | 5       | int
    {YELLOW}-s, --source{GREEN}     | Data source to retrieve samples from  [log, api]  | api     | string
    {YELLOW}-m, --method{GREEN}     | Attack method to hit xworm servers with           | conspam | string
    {YELLOW}-l, --lockon{GREEN}     | Re-initialize attack if server goes offline       | False   | bool
    {YELLOW}-q, --querytime{GREEN}  | Timer for displaying information about threads    | 60      | int (seconds)
    {YELLOW}--skipv{GREEN}          | Skip xworm server validation during port scan     | False   | bool

{RED}Passive Scan Arguments (passive) {END}

    {BLUE}Argument       Description                                                         Default  Type{END}

    {YELLOW}--connect{GREEN} | Check the connectivity of the server after extracting configuration |  bool  | False

{RED}Active Scan Arguments (active) {END}

    {BLUE}Argument       Description                                                         Default  Type{END}

    {YELLOW}-d, --daemon{GREEN} | Pass attack into daemon thread and continue searching for servers |  bool  | False


{RED}Connection Spam Arguments (conspam){END}
    
    {BLUE}Argument  Description                                              Default    Type {END}

    {YELLOW}--total{GREEN} | Amount of connections to create. Defaults to infinite. | Infinite | int

{RED}Targeted Arguments (targeted) {END}

    {BLUE}Argument       Description                                 Default   Type{END}

    {YELLOW}-b, --binpath {GREEN}| Filepath to an xworm client sample        | string | None
    {YELLOW}-i, --host {GREEN}   | Ip address or domain name of xworm server | string | None
    {YELLOW}-p, --port {GREEN}   | Port of xworm server                      | int    | 7000
    {YELLOW}-k, --key {GREEN}    | Encryption key for xworm server           | string | <123456789>
    
{RED}USAGE EXAMPLES{END}

{GREEN}python wormicide.py [global options] [MODE] [mode arguments]

{YELLOW}passive api query & config logging{END}
    {GREEN}python3 wormicide.py passive{END}

{YELLOW}passive query from logs{END}
    {GREEN}python3 wormicide.py -s log passive{END}

{YELLOW}active-passive query (check connectivity, no exploitation){END}:
    {GREEN}python3 wormicide.py{END}

{YELLOW}active api qeury with connection spam{END}
    {GREEN}python3 wormicide.py -m conspam active{END}

{YELLOW}active log query with window spam{END}
    {GREEN}python3 wormicide.py -m winspam active{END}

{YELLOW}targeted attack with window spam{END}
    {GREEN}python3 wormicide.py -m winspam targeted -i xwormserver.com -p 4444 -k somekeydata{END}    
"""

INFO    = f'{WHITE}[INFO]{END}'
VERBOSE = f'{WHITE}[{YELLOW}VERBOSE{WHITE}]{END}'
PROC    = f'{WHITE}[{BLUE}PROC{WHITE}]{END}'
SUCCESS = f'{WHITE}[{GREEN}SUCCESS{WHITE}]{END}'
ERROR   = f'{WHITE}[{RED}ERROR{WHITE}]{END}'

def print_good(data: str) -> None:
    print(f'{SUCCESS} {GREEN}{data}{END}')

def print_err(data: str) -> None:
    print(f'{ERROR} {RED}{data}{END}')

def print_verbose(data: str) -> None:
    print(f'{VERBOSE} {WHITE}{data}{END}')

def print_info(data: str) -> None:
    print(f'{INFO} {WHITE}{data}{END}')

def print_proc(data: str) -> None:
    print(f'{PROC} {BLUE}{data}{END}')

def print_banner() -> None:
    sys.stdout.write(f'{WHITE}{BANNER}{END} ')
    sys.stdout.write(f'{GREEN}{VERSION}{END}\n')
    print(f"{WHITE} Author: {GREEN}{AUTHOR}{END}")
    print(f"{WHITE} Github: {GREEN}{GITHUB}{END}")
    print(OTHER)
    print(f"\n")