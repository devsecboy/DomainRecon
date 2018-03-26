import socket
from EnumSubDomain import *
from SubDomainTakeOverChk import *
import argparse
#from EyeWitness import *

class DomainRecon(object):

	def __init__(self):
		self.enumSubDomain=EnumSubDomain()
		#self.eyeWitness=EyeWitness()
		self.subDomainTakeOverChk=SubDomainTakeOverChk()
	
	def create_cli_parser(self):
		self.parser = argparse.ArgumentParser(add_help=False, description="Domain recon is a tool to gather information about target")
		self.parser.add_argument('-h', '-?', '--h', '-help', '--help', action="store_true", help=argparse.SUPPRESS)
		input_options = self.parser.add_argument_group('Input Options')
		input_options.add_argument('--domain', metavar='DomainName', default=None, help='Website domain name')
		input_options.add_argument('--cloud_enum', default=False, action='store_true', help='Is it require to do cloud flare enumeration')
		input_options.add_argument('--username', metavar='Username', default=None, help='CloudFlare username')
		input_options.add_argument('--password', metavar='Password', default=None, help='CloudFlare password')
		input_options.add_argument('--bruteforce', default=False, action='store_true', help='Is it require to do subdomain bruteforce using recon-ng')
		args = self.parser.parse_args()
		return args

	def collectSubDomain(self, domain, isRunCloudFlare, cloudFlareUserName, cloudFlarePassword, isBruteForce):
		self.enumSubDomain.GetSubDomains(domain, isRunCloudFlare, cloudFlareUserName, cloudFlarePassword, isBruteForce)

	'''def collectScreenShot(self):
		self.eyeWitness.CaptureScreenShots()'''

	def chkSubDomainTakeOver(self):
		self.subDomainTakeOverChk.runSubDomainTakeOverChk()

if __name__ == "__main__":
	domainRecon=DomainRecon()
	cli_parsed = domainRecon.create_cli_parser()
	if cli_parsed.h:
		domainRecon.parser.print_help()
		sys.exit()
	domainRecon.collectSubDomain(cli_parsed.domain, cli_parsed.cloud_enum, cli_parsed.username, cli_parsed.password, cli_parsed.bruteforce)
	#domainRecon.collectScreenShot()
	domainRecon.chkSubDomainTakeOver()
