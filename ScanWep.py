import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

def scan_website(url):
    # Make a request to the website
    response = requests.get(url)
    html = response.text

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    # Check for SQL injection vulnerability
    sql_injection_vulnerability = check_sql_injection(soup)

    # Check for Cross-Site Scripting (XSS) vulnerability
    xss_vulnerability = check_xss(soup)

    # Check for Cross-Site Request Forgery (CSRF) vulnerability
    csrf_vulnerability = check_csrf(soup)

    # Check for Insecure Direct Object References vulnerability
    idor_vulnerability = check_idor(soup)

    # Check for Security Misconfiguration vulnerability
    misconfiguration_vulnerability = check_misconfiguration(soup)

    # Check for Sensitive Data Exposure vulnerability
    exposure_vulnerability = check_exposure(soup)

    # Check for Missing Function Level Access Control vulnerability
    acl_vulnerability = check_acl(soup)

    # Check for Cross-Site Request Forgery (CSRF) vulnerability
    csrf_vulnerability = check_csrf(soup)

    # Check for Using Components with Known Vulnerabilities vulnerability
    components_vulnerability = check_components(soup)

    # Check for Unvalidated Redirects and Forwards vulnerability
    redirects_vulnerability = check_redirects(soup)

    # Print the results
    print(f"SQL Injection Vulnerability: {sql_injection_vulnerability}")
    print(f"Cross-Site Scripting (XSS) Vulnerability: {xss_vulnerability}")
    print(f"Cross-Site Request Forgery (CSRF) Vulnerability: {csrf_vulnerability}")
    print(f"Insecure Direct Object References Vulnerability: {idor_vulnerability}")
    print(f"Security Misconfiguration Vulnerability: {misconfiguration_vulnerability}")
    print(f"Sensitive Data Exposure Vulnerability: {exposure_vulnerability}")
    print(f"Missing Function Level Access Control Vulnerability: {acl_vulnerability}")
    print(f"Using Components with Known Vulnerabilities Vulnerability: {components_vulnerability}")
    print(f"Unvalidated Redirects and Forwards Vulnerability: {redirects_vulnerability}")

def check_sql_injection(soup):
    # Check for SQL injection vulnerability
    for form in soup.find_all('form'):
        for input_tag in form.find_all('input'):
            if 'name' in input_tag.attrs:
                name = input_tag['name']
                if re.search(r'(select|insert|update|delete|drop|truncate)\s+', name, re.I):
                    return True
    return False

def check_xss(soup):
    # Check for Cross-Site Scripting (XSS) vulnerability
    for script in soup.find_all('script'):
        if re.search(r'<script>.*(document\.cookie|document\.location|localStorage|sessionStorage).*</script>', str(script), re.I):
            return True
    return False

def check_csrf(soup):
    # Check for Cross-Site Request Forgery (CSRF) vulnerability
    for form in soup.find_all('form'):
        if 'action' in form.attrs:
            action = form['action']
            if not re.match(r'^https://', action):
                return True
    return False

def check_idor(soup):
    # Check for Insecure Direct Object References vulnerability
    for link in soup.find_all('a'):
        if 'href' in link.attrs:
            href = link['href']
            if re.search(r'/user/\d+/profile', href):
                return True
    return False

def check_misconfiguration(soup):
    # Check for Security Misconfiguration vulnerability
    for meta in soup.find_all('meta'):
        if 'name' in meta.attrs and meta['name'].lower() == 'x-frame-options':
            return True
    return False

def check_exposure(soup):
    # Check for Sensitive Data Exposure vulnerability
    for input_tag in soup.find_all('input'):
        if 'type' in input_tag.attrs and input_tag['type'].lower() == 'password':
            return True
    return False

def check_acl(soup):
    # Check for Missing Function Level Access Control vulnerability
    for form in soup.find_all('form'):
        if 'action' in form.attrs:
            action = form['action']
            if not re.match(r'^https://', action):
                return True
    return False

def check_components(soup):
    # Check for Using Components with Known Vulnerabilities vulnerability
    for script in soup.find_all('script'):
        if 'src' in script.attrs:
            src = script['src']
            if re.search(r'jquery|bootstrap|angular', src, re.I):
                return True
    return False

def check_redirects(soup):
    # Check for Unvalidated Redirects and Forwards vulnerability
    for link in soup.find_all('a'):
        if 'href' in link.attrs:
            href = link['href']
            if re.search(r'^(https?|ftp):', href):
                return True
    return False

# Example usage
url = 'https://example.com'
scan_website(url)
