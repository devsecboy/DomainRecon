#Request URL:https://bgp.he.net/search?search%5Bsearch%5D=google&commit=Search

import requests
import urllib
from bs4 import BeautifulSoup
import hashlib
from GlobalVariables import *

class CollectIPSpaces(object):
	"""docstring for CollectIPSpaces"""
	def __init__(self):
		super(CollectIPSpaces, self).__init__()
		self.globalVariables=GlobalVariables()

	def get_path_cookie_digest(self):
		result=''
		headerVal=''
		requetURL="https://bgp.he.net/search?search%5Bsearch%5D=google&commit=Search"
		response=requests.head(requetURL, headers=self.globalVariables.bgp_headers, timeout=10)
		print (response)
		for header in (response.headers['Set-Cookie']).split(" "):
			if header.find("path=") == 0 and header.find("--") != -1:
				headerVal=header.split("=")[1]
				headerVal=headerVal.split(";")[0]
				decodedHeaderVal=urllib.unquote(headerVal)
				result=hashlib.md5(decodedHeaderVal.encode())
		return headerVal, result.hexdigest()

	def get_external_ip_digest(self):
		externalIP=requests.get('http://ip.42.pl/raw').text
		result=hashlib.md5(externalIP.encode())
		return result.hexdigest()

	def get_bgp_session_cookie(self):
		requetURL="https://bgp.he.net/jc"
		sessionCookieHeaderVal=''
		headerVal, cookieDigest=self.get_path_cookie_digest()
		response=requests.head(requetURL, data={'p':cookieDigest,'i':self.get_external_ip_digest()}, cookies={'path':headerVal}, headers=self.globalVariables.bgp_headers, timeout=10)
		for header in (response.headers['Set-Cookie']).split(" "):
			if header.find("c=") == 0 and header.find("--") != -1:
				headerVal=header.split("=")[1]
				sessionCookieHeaderVal=headerVal.split(";")[0]
		return sessionCookieHeaderVal

	def bgp_he_net_ipspaces(self, companyName, domain):
		ipRanges=[]
		finalRanges=[]
		outBgpHeNet="{}{}/{}".format(self.globalVariables.outputDir, domain, "bgp_he_net.txt")
		requetURL="https://bgp.he.net/search?search%5Bsearch%5D={}&commit=Search".format(companyName)
		#request = requests.get(requetURL, cookies={'c':self.get_bgp_session_cookie()}, headers=self.globalVariables.bgp_headers, timeout=10) //No cookie needed it's straight forward url call
		request = requests.get(requetURL, headers=self.globalVariables.bgp_headers, timeout=10)
		soup = BeautifulSoup(request.text, "lxml")
		result=''
		for column in soup.findAll("td"):
			try:
				data=column.find("a").string
				result+=data+"\n"
				ipRanges.append(data)
			except:
				"exception raised"
		self.globalVariables.WriteTextToFile(outBgpHeNet, result)
		
		resultIPv4=''
		resultIPv6=''
		self.outIPv4Ranges="{}{}/{}".format(self.globalVariables.outputDir, domain, "ipv4ranges.txt")
		self.outIPv6Ranges="{}{}/{}".format(self.globalVariables.outputDir, domain, "ipv6ranges.txt")
		for ipRange in ipRanges:
			if ipRange.find("/") != -1:
				if ipRange.find(":") != -1:
					resultIPv6+=ipRange+"\n"
				else:
					resultIPv4+=ipRange+"\n"

				if ipRange not in finalRanges:
					finalRanges.append(ipRange)
			elif ipRange.find("AS") == 0:
				for data in self.whoisIPSpaces(ipRange[2:]):
					if data not in finalRanges:
						if data.find(":") != -1:
							resultIPv6+=data+"\n"
						else:
							resultIPv4+=data+"\n"
						finalRanges.append(data)
		self.globalVariables.WriteTextToFile(self.outIPv4Ranges, resultIPv4)
		self.globalVariables.WriteTextToFile(self.outIPv6Ranges, resultIPv6)
		return finalRanges

	def whoisIPSpaces(self, asnNumber):
		output=self.globalVariables.CommandExecutor("whois -h whois.radb.net -- '-i origin {}' | grep -Eo '([0-9.]+){{4}}/[0-9]+' | sort -n | uniq -c | cut -d' ' -f8".format(asnNumber))
		return output.splitlines()
	
	def GetAllIPSpaces(self, companyName, domain):
		return self.bgp_he_net_ipspaces(companyName, domain)

#add ARIN & RIPE Processing
#whois.arin.net/ui/Query.do
#apps.db.ripe.net/db-web-ui