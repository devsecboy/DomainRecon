#!/usr/bin/python

#Files used to get subdomains using recon-ng and sublist3r
import sys
import datetime
import os
from Sublist3r import sublist3r
import csv
import string
import socket
import argparse
from GlobalVariables import *
import subprocess

cloudEnum = "./cloudflare_enum/"
sys.path.insert(0,cloudEnum)
from cloudflare_enum import *

reconPath = "./recon-ng/"
sys.path.insert(0,reconPath)
from recon.core import base
from recon.core.framework import Colors

class EnumSubDomain(object):

	def __init__(self):
		self.globalVariables=GlobalVariables()

	#subdomain bruteforcing
	def RunBruteForce(self, reconb, domain):
		module = reconb.do_load("recon/domains-hosts/brute_hosts")
		module.do_set("WORDLIST " + self.globalVariables.wordList)
		module.do_set("SOURCE " + domain)
		module.do_run(None)

	def RunModule(self, reconBase, module, domain):
	    module = reconBase.do_load(module)
	    module.do_set("SOURCE " + domain)
	    module.do_run(None)

	def RunRecon(self, domain, subDomains, bruteForce):
		stamp = datetime.datetime.now().strftime('%M:%H-%m_%d_%Y')
		wspace = domain+stamp

		reconb = base.Recon(base.Mode.CLI)
		reconb.init_workspace(wspace)
		reconb.onecmd("TIMEOUT=100")
		module_list = ["recon/domains-hosts/bing_domain_web", "recon/domains-hosts/google_site_web", "recon/domains-hosts/netcraft", "recon/domains-hosts/shodan_hostname", "recon/netblocks-companies/whois_orgs", "recon/hosts-hosts/resolve"]
	
		for module in module_list:
			self.RunModule(reconb, module, domain)
	
		if bruteForce:
			self.RunBruteForce(reconb, domain)
	
		#reporting output
		outFile = "FILENAME "+os.getcwd()+"/"+domain
		module = reconb.do_load("reporting/csv")
		module.do_set(outFile+".csv")
		module.do_run(None)

		reconNgOutput=domain+'.csv'
		with open(reconNgOutput, 'r') as csvfile:
			for row in csv.reader(csvfile, delimiter=','):
				subDomains.append(row[0])
		os.remove(reconNgOutput)

	def runSublist3r(self, domain, subDomains):	
		#Sublister enumeration
		sublisterOutput = sublist3r.main(domain, 30, None, None, False, False, False, None)
		for strDomain in sublisterOutput:
			subDomains.append(strDomain)

	def runCloudflareEnum(self, domain, subDomains, username, password):
		#CloudFlare enumeration
		cloud = cloudflare_enum()
		cloud.print_banner()
		cloud.log_in( username, password)
		cloud.get_spreadsheet( domain )
		cloudEnumOutput=string.replace(domain, '.', '_')+'.csv'
		with open(cloudEnumOutput, 'r') as csvfile:
			for row in csv.reader(csvfile, delimiter=','):
				if not row[0] in subDomains:
					subDomains.append(row[0])
		os.rename(cloudEnumOutput, self.globalVariables.cloudFlareDir+cloudEnumOutput)

	def GetSubDomains(self, domain, isRunSublist3r, isRunReconNG, isRunMassDNS, isRunCloudFlare, coudFlareUserName, cloudFlarePassword, isBruteForce):
		subDomains=list()
		outFile = self.globalVariables.outputDir + domain+'.txt'

		try:
			if isRunReconNG:
				self.RunRecon(domain, subDomains, isBruteForce)
		except:
			print "Error in recon-ng"

		try:
			if isRunSublist3r:
				self.runSublist3r(domain, subDomains)
		except: 
			print "Error in Sublist3r"

		try:
			if isRunMassDNS:
				cmd = './massdns/scripts/ct.py ' + domain +' | ./massdns/bin/massdns -r massdns/lists/resolvers.txt -t A -o S -w ' + outFile
				subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
				with open (outFile, 'r') as fp:
					for line in fp:
						line = line[0: line.find(" ") - 1]
						if not line in subDomains:
							subDomains.append(line)
		except:
			print "Error in MassDNS"

		try:
			if isRunCloudFlare:
				self.runCloudflareEnum(domain, subDomains, coudFlareUserName, cloudFlarePassword)
		except:
			print "Error in Enum cloud flare"
		
		with open (outFile, 'w') as fp:
			for subDomain in subDomains:
				fp.write("%s\n" % subDomain)

	def create_cli_parser(self):
		self.parser = argparse.ArgumentParser(add_help=False, description="Domain recon is a tool to gather information about target")
		self.parser.add_argument('-h', '-?', '--h', '-help', '--help', action="store_true", help=argparse.SUPPRESS)
		input_options = self.parser.add_argument_group('Input Options')
		input_options.add_argument('--domain', metavar='DomainName', default=None, help='Website domain name')
		input_options.add_argument('--cloud_enum', default=False, action='store_true', help='Is it require to do cloud flare enumeration')
		input_options.add_argument('--username', metavar='Username', default=None, help='CloudFlare username')
		input_options.add_argument('--password', metavar='Password', default=None, help='CloudFlare password')
		input_options.add_argument('--bruteforce', default=False, action='store_true', help='Is it require to do subdomain bruteforce using recon-ng')
		input_options.add_argument('--sublist3r', default=False, action='store_true', help='Run sublist3r module')
		input_options.add_argument('--reconng', default=False, action='store_true', help='Run recon-ng module')
		input_options.add_argument('--massdns', default=False, action='store_true', help='Run MassDNS module')
		args = self.parser.parse_args()
		return args

if __name__ == "__main__":
	domainRecon=EnumSubDomain()
	cli_parsed = domainRecon.create_cli_parser()
	if cli_parsed.h:
		domainRecon.parser.print_help()
		sys.exit()
	domainRecon.GetSubDomains(cli_parsed.domain, 
		cli_parsed.sublist3r,
		cli_parsed.reconng,
		cli_parsed.massdns,
		cli_parsed.cloud_enum, 
		cli_parsed.username, 
		cli_parsed.password, 
		cli_parsed.bruteforce)