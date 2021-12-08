from urllib.parse import urlparse,urlencode
import ipaddress
from bs4 import BeautifulSoup
from datetime import datetime
import whois
import re
import requests
from googlesearch import search

'''
def generate_data(url):
  try:
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
  except:
    response = ""
    soup = -999
'''


''' 1.Domain of the URL (Domain) '''

def get_Domain(url):  
  domain = urlparse(url).netloc
  #print(domain)
  if re.match(r"^www.",domain):
	       domain = domain.replace("www.","")
  return domain

'''
2. Checks for the presence of IP address in the URL. 
'''

def having_IP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  #print(ip)
  return ip

''' 3. "@" Symbol in URL '''

def having_ampersand(url):
  if "@" in url:
    ampersand = 1    
  else:
    ampersand = 0  
  print(ampersand)  
  return ampersand

''' 4. Checking length of the URL (Uniform Resource Locator) '''

def check_Length(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1            
  return length

''' 5.Checking number of '/' in URL (URL_Depth) '''

def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

''' 6.Checking for redirection '//' in the url (Redirection) '''

def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

''' 
7. Checking for "http/https" in Domain name.
'''

def httpDomainCheck(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

'''
8. Checking DNS Record

def DNSRecord(url):
  try:
    d = whois.whois(domain)
    except:
      dns=1
      if dns == 1:
        dns=1
      else:
        if registration_length / 365 <= 1:
          dns = 1
        else:
          dns=0
'''

'''
9. Web traffic
'''

def web_traffic(url):
  try:
    #Filling the whitespac  es in the URL if any
    url = urllib.parse.quote(url)
    rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
        "REACH")['RANK']
    rank = int(rank)
  except TypeError:
        return 1
  if rank <100000:
    return 1
  else:
    return 0

'''
10. Google_Index
'''
def Google_Index(url):
  site=search(url, 15)
  if site:
    temp=0
  else:
    temp=1
  return temp


'''
11 .Age of Domain
'''

def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age

'''
12. End Period of Domain**
'''

def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

'''
13. Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
'''

def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            
    else:
        return 0 
'''
14. IFrame Redirection (iFrame)
'''

def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1

'''
15. Checks the effect of mouse over on status bar (Mouse_Over)
'''

def mouseOver(response): 
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0
'''
16.Checks the status of the right click attribute (Right_Click)
'''

def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1

'''
17.Checks the number of forwardings (Web_Forwards)    
'''

def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1

'''
18. Links_pointing_to_page
'''    

def Links_pointing_to_page(url):
  if response == "":
    return 1
  else:
    number_of_links = len(re.findall(r"<a href=", response.text))
    if number_of_links == 0:
      return 1
    elif number_of_links <= 2:
      return 1
    else:
      return 0

''' 
19. Submitting_to_email
'''

def check_email(url):
  try:
    response = requests.get(url)
  except:
    response = ""
  if response == "":
    return 1
  else:
    if re.findall(r"[mail\(\)|mailto:?]", response.text):
      return 1
    else:
      return 0


# 18. Using URL Shortening Services “TinyURL”

#Function to extract features
def featureExtraction(url):

  features = []
  #Address bar based features (10)
  features.append(get_Domain(url))
  features.append(having_IP(url))
  features.append(having_ampersand(url))
  features.append(check_Length(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomainCheck(url))
  features.append(prefixSuffix(url))
  features.append(web_traffic(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  

  return features

