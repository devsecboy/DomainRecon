#!/usr/bin/python

#Files used to get subdomains using recon-ng and sublist3r
import sys
import datetime
import os
from Sublist3r import sublist3r
import csv
import string
import glob
import socket
import argparse
from GlobalVariables import *
import subprocess
import dns.resolver
import logging
import coloredlogs

seBucketScanner = "./S3Scanner/"
sys.path.insert(0,seBucketScanner)
import s3utils as s3

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

	def EnumCNAMEOfDomain(self):
		files = glob.glob(self.globalVariables.outputDir + "*.txt")
		for file in files:
			cnameFileName=self.globalVariables.cnameEnumDir+(file[file.rfind("/")-len(file)+1:])
			cnameEnumFile = open(cnameFileName, 'w')

			with open(file, "r") as f:
				for line in f:
					isPrint=True
					domain = line.split('\n')
					
					try:
						# Basic query
						for rdata in dns.resolver.query(domain[0], 'CNAME') :
							if isPrint:
								cnameEnumFile.write("\n" + domain[0] + " ==> ")
								isPrint=False
							cnameEnumFile.write(str(rdata.target));
					except:
						try:
							resolver = dns.resolver.Resolver()
							resolver.nameservers = ['8.8.8.8'] 	
							for rdata in resolver.query(domain, 'CNAME') :
								if isPrint:
									cnameEnumFile.write("\n" + domain[0] + " ==> ")
									isPrint=False
								cnameEnumFile.write(str(rdata.target));
						except:
							isPrint=False
			cnameEnumFile.close()

	def ScanS3Bucket(self):
		files = glob.glob(self.globalVariables.outputDir + "*.txt")
		if not s3.checkAwsCreds():
			s3.awsCredsConfigured = False
			slog.error("Warning: AWS credentials not configured. Open buckets will be shown as closed. Run: `aws configure` to fix this.\n")
		else:
			for file in files:
				s3Bucket=self.globalVariables.s3Bucket+(file[file.rfind("/")-len(file)+1:])
				
					# Create file logger
				flog = logging.getLogger('s3scanner-file')
				flog.setLevel(logging.DEBUG)              # Set log level for logger object

				# Create file handler which logs even debug messages
				fh = logging.FileHandler(s3Bucket)
				fh.setLevel(logging.DEBUG)

				# Add the handler to logger
				flog.addHandler(fh)

				# Create secondary logger for logging to screen
				slog = logging.getLogger('s3scanner-screen')
				slog.setLevel(logging.INFO)

				levelStyles = {
			        'info': {'color': 'blue'},
			        'warning': {'color': 'yellow'},
			        'error': {'color': 'red'}
			    }

				fieldStyles = {
			        'asctime': {'color': 'white'}
			    }

				# Use coloredlogs to add color to screen logger. Define format and styles.
				coloredlogs.install(level='DEBUG', logger=slog, fmt='%(asctime)s   %(message)s',
			                    	level_styles=levelStyles, field_styles=fieldStyles)
				with open(file, "r") as f:
					for line in f:
						domain = line.split('\n')
						s3.checkBucket(domain[0], slog, flog, True, True)

	def GetSubDomains(self, domain, isRunSublist3r, isRunReconNG, isRunMassDNS, isBruteForce, isCnameEnum, isS3BucketScan):
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
		
		if isRunReconNG | isRunSublist3r | isRunMassDNS:
			with open (outFile, 'w') as fp:
				for subDomain in subDomains:
					fp.write("%s\n" % subDomain)

		try:
			if isCnameEnum:
				self.EnumCNAMEOfDomain()
		except:
			print "Error in CName Enumeration"

		try:
			if isS3BucketScan:
				self.ScanS3Bucket()
		except:
			print "Error in s3 bucket scan"

	def create_cli_parser(self):
		self.parser = argparse.ArgumentParser(add_help=False, description="Domain recon is a tool to gather information about target")
		self.parser.add_argument('-h', '-?', '--h', '-help', '--help', action="store_true", help=argparse.SUPPRESS)
		input_options = self.parser.add_argument_group('Input Options')
		input_options.add_argument('--domain', metavar='DomainName', default=None, help='Website domain name')
		input_options.add_argument('--bruteforce', default=False, action='store_true', help='Is it require to do subdomain bruteforce using recon-ng')
		input_options.add_argument('--sublist3r', default=False, action='store_true', help='Run sublist3r module')
		input_options.add_argument('--reconng', default=False, action='store_true', help='Run recon-ng module')
		input_options.add_argument('--massdns', default=False, action='store_true', help='Run MassDNS module')
		input_options.add_argument('--filename', metavar='FilePath', default=None, help='Filepath contains a list of Subdomains')
		input_options.add_argument('--cname_enum', default=False, action='store_true', help='CNAME Enumeration of domains')
		input_options.add_argument('--s3_bucket_scan', default=False, action='store_true', help='amazon s3 bucket scan')
		args = self.parser.parse_args()
		return args

if __name__ == "__main__":
	domainRecon=EnumSubDomain()
	cli_parsed = domainRecon.create_cli_parser()
	if cli_parsed.h:
		domainRecon.parser.print_help()
		sys.exit()
	if cli_parsed.filename:
		print cli_parsed.filename
		with open(cli_parsed.filename, "r") as ins:
			for line in ins:
				domainRecon.GetSubDomains(line, 
					cli_parsed.sublist3r,
					cli_parsed.reconng,
					cli_parsed.massdns,
					cli_parsed.bruteforce,
					cli_parsed.cname_enum,
					cli_parsed.s3_bucket_scan)
	else:
		domainRecon.GetSubDomains(cli_parsed.domain, 
			cli_parsed.sublist3r,
			cli_parsed.reconng,
			cli_parsed.massdns,
			cli_parsed.bruteforce,
			cli_parsed.cname_enum,
			cli_parsed.s3_bucket_scan)