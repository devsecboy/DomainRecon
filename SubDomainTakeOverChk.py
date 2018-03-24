#!/usr/bin/python

from argparse import ArgumentParser, RawTextHelpFormatter
import subprocess
import shlex
import requests
import glob
import certifi #install it in ubuntu : pip install urllib3[secure]
import urllib3
import os

http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())

class SubDomainTakeOverChk(object):

	def __init__(self):
		self.COMMON_HOSTING_PROVIDERS = {"heroku": "heroku", 
                            "zendesk": "zendesk", 
                            "bitbucket": "bitbucket",
                            "shopify": "shopify",
                            "teamwork": "teamwork",
                            "unbounce": "unbounce",
                            "github": "github",
                            "helpjuice": "helpjuice",
                            "helpscout": "helpscout",
                            "cargocollective": "cargocollective",
                            "statuspage": "statuspage",
                            "tumblr": "tumblr"}
		self.UNMANAGED_DOMAIN_MSGS=["no application was found", "no such app",
                       "specified bucket does not exist", 
                       "there isn't a github page"]
		self.ANSI_GRN = '\033[0;32m' 
		self.ANSI_CLR = '\033[0;0m'
		self.userAgent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0"
		self.inPath = './Output/'
		self.outPath = './Output/SubTakeOver/'
		self.timeout = 10

	def runSubDomainTakeOverChk(self):
		try: 
			os.makedirs(self.outPath)
		except OSError:
			if not os.path.isdir(self.outPath):
				raise
		
		files = glob.glob(self.inPath + "*.txt")
		for file in files:
			print "\n\n" + file
			with open(file, "r") as f:
				domains_list = f.readlines()
				filename = file[file.rfind('/')+1:]
				self.checkSubDomainTakeOver(filename, domains_list)

	def outmsg(self, msg, f, start_color='\033[0;0m'):
		f.write(msg+"\n")
		end_color = self.ANSI_CLR
		print start_color + msg + end_color

	def checkSubDomainTakeOver(self, file, domains_list):
		outfile = self.outPath + file
		with open(outfile, "w") as f:
			for domain_line in domains_list:
				domain = domain_line.strip()
				domain = domain.replace("\n", "");
				# Check the hostname via DNS to discover any CNAME aliases
				cmdline = "host " + domain
				self.outmsg(domain, f)
				self.outmsg("---------------------------------------------------------------", f)
				self.outmsg("[*] Checking DNS.", f)

				host_resolve = ''
				p = subprocess.Popen(shlex.split(cmdline), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				out,err = p.communicate()
				if err == "":
					host_resolve = out
				else:
					host_resolve = out + err
				self.outmsg(host_resolve, f)

				# locate any CNAME aliases
				aliases = filter(lambda s: "alias" in s, host_resolve.split("\n"))
				headers = {"User-Agent": self.userAgent}

				# now, check each aliass
				for alias in aliases:
					result = ""

					# check if provider's url keyword exists in each alias
					for provider, provider_keyword in self.COMMON_HOSTING_PROVIDERS.items():
						result = ""
						if provider_keyword in alias:
							# If a known provider found - inform user!
							result = "[+] Common Hosting Provider found in an alias! Provider: %s, Domain: %s\n" % (provider,domain)
							self.outmsg(result, f, self.ANSI_GRN)

					self.outmsg("[*] Making HTTP/HTTPS request.\n", f)

				# Get both the http request and response to locate any signs of an unregistered app
				valid_http_resp = False
				valid_https_resp = False
				try:
					http_resp = requests.get("http://" + domain, headers=headers, verify=False, timeout=self.timeout)
					valid_http_resp = True
				except requests.exceptions.ConnectionError:
					self.outmsg("[-] No connection could be made to '%s'. Determine if DNS entry is defined for the domain.\n" % domain, f)
				except requests.exceptions.ReadTimeout:
					self.outmsg("[-] No connection could be made to '%s'. HTTP Request timed out. Try accessing website manually.\n" % domain, f)
				except requests.exceptions.TooManyRedirects:
					self.outmsg("[-] No connection could be made to '%s'. HTTP Request with excessive redirections. Try testing website manually.\n" % domain, f)

				try:
					https_resp = requests.get("https://" + domain, headers=headers, verify=False, timeout=self.timeout)
					valid_https_resp = True
				except requests.exceptions.ConnectionError:
					self.outmsg("[-] No connection could be made to '%s'. Determine if DNS entry is defined for the domain.\n" % domain, f)
				except requests.exceptions.ReadTimeout:
					self.outmsg("[-] No connection could be made to '%s'. HTTPS Request timed out. Try testing website manually.\n" % domain, f)
				except requests.exceptions.TooManyRedirects:
					self.outmsg("[-] No connection could be made to '%s'. HTTPS Request with excessive redirections. Try testing website manually.\n" % domain, f)

				# Do we have any messages that indicate unmanaged subdomain in the http/https output
				result = ""
				if valid_http_resp or valid_https_resp:
					for msg in self.UNMANAGED_DOMAIN_MSGS:
						msg_to_locate = msg.lower()
						if valid_http_resp:
							if msg_to_locate in http_resp.text.lower():
								# Located msgs that indicate an unmanaged app in HTTP response
								# that indicate susceptibility to takeover
								result = "[+] Unmanaged text '%s' found in response for '%s'! HTTP response is:" % (msg_to_locate, domain)
								result += http_resp.text+"\n"
								self.outmsg(result, f, self.ANSI_GRN)
						if valid_https_resp:
							if msg_to_locate in https_resp.text.lower():
								# Located msgs that indicate an unmanaged app in HTTPS response
								# that indicate susceptibility to takeover
								result = "[+] Unmanaged text '%s' found in response for '%s'! HTTPS response is:" % (msg_to_locate, domain)
								result += https_resp.text+"\n"
								self.outmsg(result, f, self.ANSI_GRN)