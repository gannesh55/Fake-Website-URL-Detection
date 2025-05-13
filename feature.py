import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.response = None
        self.soup = None
        self.urlparse = urlparse(url)

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
            self.domain = self.urlparse.netloc
        except:
            self.response = None
            self.soup = None

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.HTTPS(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ]

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def longUrl(self):
        return -1 if len(self.url) >= 75 else (0 if 54 <= len(self.url) < 75 else 1)

    def shortUrl(self):
        match = re.search(r'bit\.ly|goo\.gl|tinyurl\.com|ow\.ly', self.url)
        return -1 if match else 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    def SubDomains(self):
        dots = self.domain.count('.')
        return -1 if dots > 3 else (0 if dots == 3 else 1)

    def HTTPS(self):
        return 1 if self.urlparse.scheme == 'https' else -1

    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list): expiration_date = expiration_date[0]
            if isinstance(creation_date, list): creation_date = creation_date[0]
            age = (expiration_date - creation_date).days / 30
            return 1 if age >= 12 else -1
        except:
            return -1

    def Favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.domain in link['href']:
                    return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        return -1 if ':' in self.domain else 1

    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    def RequestURL(self):
        try:
            total = len(self.soup.find_all(['img', 'audio', 'embed', 'iframe']))
            success = 0
            for tag in self.soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True):
                if self.domain in tag['src']:
                    success += 1
            percentage = success / total if total else 0
            if percentage > 0.61: return 1
            elif 0.22 <= percentage <= 0.61: return 0
            else: return -1
        except:
            return 0

    def AnchorURL(self):
        try:
            unsafe = 0
            total = len(self.soup.find_all('a', href=True))
            for a in self.soup.find_all('a', href=True):
                if not (self.domain in a['href']):
                    unsafe += 1
            percentage = unsafe / total if total else 0
            return 1 if percentage < 0.31 else (0 if percentage < 0.67 else -1)
        except:
            return -1

    def LinksInScriptTags(self):
        try:
            total = len(self.soup.find_all(['script', 'link']))
            safe = 0
            for tag in self.soup.find_all(['script', 'link'], src=True):
                if self.domain in tag['src']:
                    safe += 1
            percentage = safe / total if total else 0
            return 1 if percentage < 0.17 else (0 if percentage < 0.81 else -1)
        except:
            return -1

    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                if self.domain not in form['action']:
                    return 0
            return 1
        except:
            return -1

    def InfoEmail(self):
        return -1 if re.search(r'mailto:', self.url) else 1

    def AbnormalURL(self):
        return -1 if self.whois_response is None else 1

    def WebsiteForwarding(self):
        try:
            if self.response:
                total_redirects = len(self.response.history)
                return 1 if total_redirects <= 1 else (0 if total_redirects <= 4 else -1)
            return 1
        except:
            return -1

    def StatusBarCust(self):
        return -1 if self.response and re.search(r'onmouseover', self.response.text) else 1

    def DisableRightClick(self):
        return -1 if self.response and re.search(r'event.button ?== ?2', self.response.text) else 1

    def UsingPopupWindow(self):
        return -1 if self.response and re.search(r'alert\(', self.response.text) else 1

    def IframeRedirection(self):
        return -1 if self.response and re.search(r'<iframe', self.response.text) else 1

    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            age = (date.today() - creation_date).days / 30
            return 1 if age >= 6 else -1
        except:
            return -1

    def DNSRecording(self):
        return 1 if self.whois_response else -1

    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={self.url}").read(), "xml").find("REACH")['RANK']
            return 1 if int(rank) < 100000 else 0
        except:
            return -1

    def PageRank(self):
        # Note: PageRank API is deprecated; you may skip or mock this feature
        return 1

    def GoogleIndex(self):
        try:
            results = list(search(self.url, num=5))
            return 1 if results else -1
        except:
            return 1

    def LinksPointingToPage(self):
        try:
            count = len(re.findall(r"<a href=", self.response.text))
            return 1 if count == 0 else (0 if count <= 2 else -1)
        except:
            return -1

    def StatsReport(self):
        try:
            ip = socket.gethostbyname(self.domain)
            blacklisted_ips = ['146.112.61.108', '121.50.168.88']
            return -1 if ip in blacklisted_ips else 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features
