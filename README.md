<div align="center">
 <img src="/resources/conspamdemo.gif" alt="Connection Spam Demo">

```
 ▄█     █▄   ▄██████▄     ▄████████   ▄▄▄▄███▄▄▄▄    ▄█   ▄████████  ▄█  ████████▄     ▄████████ 
███     ███ ███    ███   ███    ███ ▄██▀▀▀███▀▀▀██▄ ███  ███    ███ ███  ███   ▀███   ███    ███ 
███     ███ ███    ███   ███    ███ ███   ███   ███ ███▌ ███    █▀  ███▌ ███    ███   ███    █▀  
███     ███ ███    ███  ▄███▄▄▄▄██▀ ███   ███   ███ ███▌ ███        ███▌ ███    ███  ▄███▄▄▄     
███     ███ ███    ███ ▀▀███▀▀▀▀▀   ███   ███   ███ ███▌ ███        ███▌ ███    ███ ▀▀███▀▀▀     
███     ███ ███    ███ ▀███████████ ███   ███   ███ ███  ███    █▄  ███  ███    ███   ███    █▄  
███ ▄█▄ ███ ███    ███   ███    ███ ███   ███   ███ ███  ███    ███ ███  ███   ▄███   ███    ███ 
 ▀███▀███▀   ▀██████▀    ███    ███  ▀█   ███   █▀  █▀   ████████▀  █▀   ████████▀    ██████████ 
                         ███    ███                                                              
```
</div>
<div align="center">
<h3>An XWorm server take down tool</h3>
</div>

# Credits
Credit for discovery of the vulnerabilities goes to the author of the [XWorm Packet Tool](https://github.com/kali-linex/xworm-troll/), [kali-linex](https://github.com/kali-linex). The underlying vulnerabilities that allow a DoS attack were discovered by that individual. I have only built upon this persons work. I take no credit for the original research and discovery of the vulnerabilities. Please check out the [XWorm Troll](https://github.com/kali-linex/xworm-troll/) repository for more information on the Xworm server and the vulnerabilities. All credit for the code within the [xworm](/xworm/) directory goes to [kali-linex](https://github.com/kali-linex).

# About
Wormicide is a tool that's designed to seek out xworm servers and launch denial of service attacks on them. Wormicide has 3 methods of seeking out servers. It can query the malware bazaar api for a user-defined amount of samples, querying historical logs or querying a configuration retrieved from a sample passed as input.

Wormicide uses the [XDump](https://github.com/wizardy0ga/xdump) utility to decrypt and extract the command and control information from the samples retrieved via malwware bazaar. 

# Modes of Operation
Wormicide works from 3 modes of operation. These modes define the control flow of the main function. The mode of operation must always be specified by the operator.

### Passive
A passive scan will query the api for a number of samples and extract the configuration from the binary. The command and control configuration is saved to the [logs](/logs/) directory under **extracted.yaml** for future processing. 

Optionally, the user can specify **--connect** which will check the connectivity of the server.

### Active
An active scan will query the logs or malware bazaar api to retrieve xclient configuration information. Wormicide then checks the connectivity of the server and launches the user specified DoS method. If the **--daemon** argument is given, the attack will be placed in a child thread while the main thread continues checking for configurations. Without the **--daemon** argument, Wormicide halts the search and the attack takes over the main thread. 

### Targeted
Targeted mode allows the operator to direct an attack on a single server. The configuration information can be passed as arguments or the user can extract the config from a sample. 

# Installation Notes

If the operator is only processing from a log file, then this program may be executed within a linux environment. 

If the operator needs to extract configurations from live samples, then a Windows environment will be required due to the [XDump](https://github.com/wizardy0ga/xdump) dependency.

# Requirements

![Language](https://img.shields.io/badge/Language-Python-blue)

| Software | Version |
|-|-|
| Python   | 3.x.x
| Windows (If extracting live samples) | 10 / 11
| XDump (Included) | 1.0 

# Setup Instructions

> :warning: **Use virtualization**: It is best practice to execute this tool within a virtual environment. Do not execute this program on your host. 

1. Execute `pip install requirements.txt`.

2. Setup an account with [malware bazaar](https://bazaar.abuse.ch/) and retrieve an API token.

3. Assign the token as a string value to **APITOKEN** at line 20 in [wormicide.py](/wormicide.py).

# Usage 
```python womricide.py [global arguments] [MODE OF OPERATION] [mode arguments]```

## Global Arguments
|Argument|Description|Default|Type
|-|-|-|-|
|-v, --verbose| Increase output about what is happening|False|bool
|-a, --amount| The amount of samples to process from logs or api|50|int
|-t, --timeout| Timeout for all socket operations|5|int
|-s, --source| Data source to retrieve samples from  [log, api]|api| string
|-m, --method| Attack method to hit xworm servers with|conspam|string
|-l, --lockon| Re-initialize attack if server goes offline|False|bool
|-q, --querytime| Timer for displaying information about threads|60|int(seconds)
|--skipv| Skip xworm server validation during port scan|False|bool
## Modes of Operation
| Argument|Description|
|-|-|
|passive|The passive scan will query the samples from the API and extract the configuration. Optionally, a port scan can be performed on the server to determine if it's online.
|active|Active scanning will extract configurations from live samples through api queries or from the logs. The scan checks the server connectivity and proceeds with the specified attack if the server is online. If the daemon argument is given, the server will background the attack and continue scanning for other hosts.| 
|targeted|Attack a single instance of an xworm server using the host, port and encryption key or through extracting a configuration from a sample.|

## Passive Scan Arguments (passive)
|Argument|Description|Default|Type
|-|-|-|-|
|--connect|Check the connectivity of the server after extracting configuration|boolFalse

## Active Scan Arguments (active)
|Argument|Description|Default|Type
|-|-|-|-|
|-d, --daemon|Pass attack into daemon thread and continue searching for servers|bool|False

## Connection Spam Arguments (conspam)
|Argument|Description|Default|Type
|-|-|-|-|
|--total|Amount of connections to create. Defaults to infinite.|Infinite|int

## Targeted Arguments (targeted)
|Argument|Description|Default|Type
|-|-|-|-|
|-b, --binpath|Filepath to an xworm client sample|string|None
|-i, --host|Ip address or domain name of xworm server|string|None
|-p, --port|Port of xworm server|int|7000
|-k, --key|Encryption key for xworm server|string|<123456789>

# Attack method demonstration
###### Connection spam (conspam)
![Connection Spam Demo](/resources/conspamdemo.gif)  
The connection spam will fill a server with fake connections, rendering the GUI in-operable. 


###### Window spam (winspam)
![Window Spam Demo](/resources/winspamdemo.gif)  
The window spam continuously opens new windows on the server. 

# Log file syntax

###### Extracted.yaml

```
{SHA 256 Hash}:
  first_seen:
  host:
  key:
  port:
  sha256: 
  status: 
  updated:
```


