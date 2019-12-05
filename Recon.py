
from SubDomainCollector import *
import os
import sys
import commands
import argparse
from FindJenkins import *

class Recon(object):
	"""docstring for Recon"""
	def __init__(self):
		super(Recon, self).__init__()

	def createVariables(self, domain):
		self.globalVariables=GlobalVariables()
		self.outSubDomainPath="{}{}/{}".format(self.globalVariables.outputDir, domain, "all_domains.txt")
		self.outUpHosts="{}{}/{}".format(self.globalVariables.outputDir, domain, "uphosts.txt")
		self.outUniqUpHostsAll="{}{}/{}".format(self.globalVariables.outputDir, domain, "uphosts_uniq_all.txt")
		self.outUniqUpHosts="{}{}/{}".format(self.globalVariables.outputDir, domain, "uphosts_uniq.txt")
		self.outUniqUpHostsIP="{}{}/{}".format(self.globalVariables.outputDir, domain, "uphosts_ip.txt")
		self.outUniqUpHostsUniqIP="{}{}/{}".format(self.globalVariables.outputDir, domain, "uphosts_ip_uniq.txt")
		self.outHostToIPMapping="{}{}/{}".format(self.globalVariables.outputDir, domain, "host_to_ip_mapping.txt")
		self.outCURLRequestOutput="{}{}/{}".format(self.globalVariables.outputDir, domain, "check_for_internalIP.txt")
		self.outCRLFInjectionOutput="{}{}/{}".format(self.globalVariables.outputDir, domain, "check_for_CRLFInjection.txt")
		self.outOpenRedirectionOutput="{}{}/{}".format(self.globalVariables.outputDir, domain, "check_for_OpenRedirection.txt")
		self.outToolAndTechOutput="{}{}/{}".format(self.globalVariables.outputDir, domain, "tools_and_tech.txt")
		self.outWelknownDirGoBuster="{}{}/{}".format(self.globalVariables.outputDir, domain, "WellKnownDir_Gobuster.txt")
		self.outSSLScanResult="{}{}/{}".format(self.globalVariables.outputDir, domain, "sslscan_results.xml")
		self.s3scannerOutput="{}{}/{}".format(self.globalVariables.outputDir, domain, "s3scanner.txt")
		self.massDNSOutput="{}{}/{}".format(self.globalVariables.outputDir, domain, "massDNS.txt")
		self.outCNAMEs="{}{}/{}".format(self.globalVariables.outputDir, domain, "cnames.txt")
		self.webScreenShotReportDir="{}{}/{}".format(self.globalVariables.outputDir, domain, "WebScreenShot")
		self.massScanOutputDir="{}{}/{}".format(self.globalVariables.outputDir, domain, "MassScan")


	def WebScreenshotOnUpHost(self):
		print "WebScreenShot process running.." 
		self.globalVariables.CommandExecutor("webscreenshot -i {} -o {}".format(self.outUniqUpHosts, self.webScreenShotReportDir))

	def SSLScanOnUpHost(self):
		print "SSLScan process running.." 
		self.globalVariables.CommandExecutor("sslscan --targets={} --ssl2 --ssl3 --xml={}".format(self.outUniqUpHosts, self.outSSLScanResult))

	def S3ScannerUpHosts(self):
		print "S3Scanner process running.." 
		self.globalVariables.CommandExecutor("python {} {} --out-file {}".format(self.globalVariables.S3ScannerPath, self.outUniqUpHosts, self.s3scannerOutput))

	def WellKnownFilesDirGoBuster(self):
		print "GoBuster process running.." 
		upHostFile = open(self.outUniqUpHosts, "r")
		for host in upHostFile:
			try:
				output=self.globalVariables.CommandExecutor("gobuster dir -u https://{} -w {} -s \"200,204,301,302,307\" -k".format(host.strip(), self.globalVariables.goBusterCommonWordlist))
				self.globalVariables.WriteTextToFile(self.outWelknownDirGoBuster, output)
			except:
				print "Gobuster error"

	def ToolAndTechOutput(self):
		print "Webtech process running.."
		output='' 
		tmpFileName='temp.txt'
		if os.path.exists(tmpFileName):
			os.remove(tmpFileName)
		tempFile = open(self.outUniqUpHosts)
		line = tempFile.readline()
		while line:
			output+='https://'+line
			line = tempFile.readline()
		tempFile.close()
		self.globalVariables.WriteTextToFile(tmpFileName, output)
		self.globalVariables.CommandExecutor("webtech --ul={} | tee {}".format(tmpFileName, self.outToolAndTechOutput))
		os.remove(tmpFileName)

	def MassScanOnUpHost(self, specificPort="", topPort=True):
		print "MassScan process running.." 
		upHostFile = open(self.outUniqUpHosts, "r")
		for host in upHostFile:
			try:
				output="\n"+host
				textToWrite=self.globalVariables.CommandExecutor("dig +short {} | grep -oE '\\b([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}\\b'".format(host.strip()))
				output+=textToWrite
				self.globalVariables.WriteTextToFile(self.outHostToIPMapping, output)
				self.globalVariables.WriteTextToFile(self.outUniqUpHostsIP, textToWrite)
				self.globalVariables.CommandExecutor("sed -i '/^$/d' {} | sort {} | uniq > {}".format(self.outUniqUpHostsIP, self.outUniqUpHostsIP, self.outUniqUpHostsUniqIP))
			except:
				"MassScan Error"

		if not specificPort:
			if topPort:
				self.globalVariables.CommandExecutor("sudo masscan -p{} -iL {} --max-rate 10000 -oG {}".format(self.globalVariables.topNMapPort, self.outUniqUpHostsUniqIP, self.massScanOutputDir))
			else:
				self.globalVariables.CommandExecutor("sudo masscan -p1-65535 -iL {} --max-rate 10000 -oG {}".format(self.outUniqUpHostsUniqIP, self.massScanOutputDir))
		else:
			self.globalVariables.CommandExecutor("sudo masscan -p{} -iL {} --max-rate 10000 -oG {}".format(specificPort, self.outUniqUpHostsUniqIP, self.massScanOutputDir))

	def CheckForOpenRedirection(self):
		print "Open redirection script running.." 
		upHostFile = open(self.outUniqUpHosts, "r")
		for host in upHostFile:
			output="\n\nHTTP Request\n"+host
			status, rawOutput = commands.getstatusoutput("curl -v --connect-timeout 5 --expect100-timeout 5 https://{}//attacker.com".format(host.strip()))
			output+=rawOutput
			status, rawOutput = commands.getstatusoutput("curl -v --connect-timeout 5 --expect100-timeout 5 http://{}//attacker.com".format(host.strip()))
			output+=rawOutput
			self.globalVariables.WriteTextToFile(self.outOpenRedirectionOutput, output)
			#cat check_for_OpenRedirection.txt | grep Location:

	def CheckForInternalIPDisclosure(self):
		print "Check for internal IP script running.." 
		upHostFile = open(self.outUniqUpHosts, "r")
		for host in upHostFile:
			output="\n\nHTTP Request\n"+host
			status, rawOutput = commands.getstatusoutput("curl -v -H \"Host:\" --http1.0 --connect-timeout 5 --expect100-timeout 5 http://{}".format(host.strip()))
			output+=rawOutput
			self.globalVariables.WriteTextToFile(self.outCURLRequestOutput, output)

	def CheckForCRLFInjection(self):
		print "CRLF Injection script running.." 
		upHostFile = open(self.outUniqUpHosts, "r")
		for host in upHostFile:
			output="\n\nHTTP Request\n"+host
			status, rawOutput = commands.getstatusoutput("curl -v --connect-timeout 5 --expect100-timeout 5 http://{}/%0d%0a%09CRLFInjection:%20CRLFInjection".format(host.strip()))
			output+=rawOutput
			self.globalVariables.WriteTextToFile(self.outCRLFInjectionOutput, output)
			#cat check_for_CRLFInjection.txt | grep " CRLFInjection"

	def FindJenkinsIntance(self, domain):
		findJenkins=FindJenkins()
		findJenkins.EnumerateIPToFindJenkins(domain)

	def create_cli_parser(self):
		self.parser = argparse.ArgumentParser(add_help=False, description="Domain recon is a tool to gather information about target")
		self.parser.add_argument('-h', '-?', '--h', '-help', '--help', action="store_true", help=argparse.SUPPRESS)
		input_options = self.parser.add_argument_group('Usage')
		input_options.add_argument('--domain', metavar='DomainName', default="", help='Website domain name')
		input_options.add_argument('--organization', metavar='OrganizationName', default="", help='Website organization name')
		input_options.add_argument('--bgpipspace', default=False, action='store_true', help='collect organization ip ranges from bgp.he.net')
		input_options.add_argument('--bgpamass', default=False, action='store_true', help='collect domains from bgp.he.net + amass')
		input_options.add_argument('--censys', default=False, action='store_true', help='collect domains from censys')
		input_options.add_argument('--certdomain', default=False, action='store_true', help='collect domain using cert domain finder')
		input_options.add_argument('--amassactive', default=False, action='store_true', help='collect domain using amass active scan')
		input_options.add_argument('--amasspassive', default=False, action='store_true', help='collect domain using amass passive scan')
		input_options.add_argument('--subfinder', default=False, action='store_true', help='collect domain using subfinder')
		input_options.add_argument('--ctfr', default=False, action='store_true', help='collect domain using CTFR')
		input_options.add_argument('--ctexposer', default=False, action='store_true', help='collect domain using CTFRExposer')
		input_options.add_argument('--certgraph', default=False, action='store_true', help='collect domain using certgraph')
		input_options.add_argument('--certspotter', default=False, action='store_true', help='collect domain using certspotter')
		input_options.add_argument('--fdnsr7', default=False, action='store_true', help='collect domain using fdns rapid7 project sonar opendata')
		input_options.add_argument('--commonspeak', default=False, action='store_true', help='collect domain using commonspeak wordlist')
		input_options.add_argument('--cnames', default=False, action='store_true', help='Collect CNAMEs of all the collected domains')
		input_options.add_argument('--s3scanner', default=False, action='store_true', help='Run s3scanner on all the collected domains')
		input_options.add_argument('--webscreenshot', default=False, action='store_true', help='Capture screenshot of all the collected domains')
		input_options.add_argument('--sslscan', default=False, action='store_true', help='Run sslscan on all collected domains')
		input_options.add_argument('--webtech', default=False, action='store_true', help='Run webtech on all collected domains')
		input_options.add_argument('--internalip', default=False, action='store_true', help='Run internal ip script on all collected domains')
		input_options.add_argument('--crlfinjection', default=False, action='store_true', help='Run crlf injection script on all collected domains')
		input_options.add_argument('--gobuster', default=False, action='store_true', help='Run sublist3r module')
		input_options.add_argument('--openredirection', default=False, action='store_true', help='Run open redirection on all collected domains')
		input_options.add_argument('--masscan', default=False, action='store_true', help='Run masscan on all collected domains')
		input_options.add_argument('--jenkins', default=False, action='store_true', help='Run jenkins on all collected IP ranges collected using bgp.he.net')
		args = self.parser.parse_args()
		return args

	def GeDomainRecon(self, domain, organization, bgpipspace, bgpamass, censys, certdomain, amassactive, amasspassive, subfinder, ctfr, ctexposer, certgraph, certspotter, fdnsr7, commonspeak, cnames, s3scanner, webscreenshot, sslscan, webtech, internalip, crlfinjection, gobuster, openredirection, masscan, jenkins):
		self.createVariables(domain)
		self.subDomainCollector=SubDomainCollector()
		
		outputDir="{}{}".format(self.globalVariables.outputDir, domain)
		print outputDir
		if not os.path.exists(outputDir):
			os.makedirs(outputDir)

		self.subDomainCollector.GetAllDomains(domain, organization, bgpipspace, bgpamass, censys, certdomain, amassactive, amasspassive, subfinder, ctfr, ctexposer, certgraph, certspotter, fdnsr7, commonspeak, self.outSubDomainPath)
		self.subDomainCollector.checkForUpHostUsingFilterResolved(self.outSubDomainPath, self.outUpHosts)
		self.globalVariables.CommandExecutor("sed -i '/^$/d' {} | sort {} | uniq > {}".format(self.outUpHosts, self.outUpHosts, self.outUniqUpHostsAll))
		self.globalVariables.CommandExecutor("cat {} | grep {} > {}".format(self.outUniqUpHostsAll, domain, self.outUniqUpHosts))

		#Can be call in individual thread as they can be run as parallel
		#cat cnames.txt | grep -P '(?<!tomtom\.com\.)$'
		if cnames:
			self.subDomainCollector.checkForCNAMEUsingMassDNS(self.outUniqUpHosts, self.massDNSOutput, self.outCNAMEs)
		if s3scanner:
			self.S3ScannerUpHosts()
		if webscreenshot:
			self.WebScreenshotOnUpHost()
		if sslscan:
			self.SSLScanOnUpHost()
		if webtech:
			self.ToolAndTechOutput()
		if internalip:
			self.CheckForInternalIPDisclosure()
		if crlfinjection:
			self.CheckForCRLFInjection()
		if gobuster:
			self.WellKnownFilesDirGoBuster()
		if openredirection:
			self.CheckForOpenRedirection()
		if masscan:
			self.MassScanOnUpHost()
		if jenkins:
			self.FindJenkinsIntance(domain)

def print_banner():
	banner=	(" ____                        _         ____                       \n"+
	"|  _ \\  ___  _ __ ___   __ _(_)_ __   |  _ \\ ___  ___ ___  _ __  \n"+
	"| | | |/ _ \\| '_ ` _ \\ / _` | | '_ \\  | |_) / _ \\/ __/ _ \\| '_ \\ \n"+
	"| |_| | (_) | | | | | | (_| | | | | | |  _ <  __/ (_| (_) | | | |\n"+
	"|____/ \\___/|_| |_| |_|\\__,_|_|_| |_| |_| \\_\\___|\\___\\___/|_| |_|\n")
	print banner

if __name__ == "__main__":
	'''file = open('domains.txt', "r")
	lines = file.readlines()
	for line in lines:
		data=(line.strip()).split(",")
		recon=Recon(data[1])
		recon.GeDomainRecon(data[0], data[1])
	file.close() '''
	print_banner()
	recon=Recon()
	cli_parsed = recon.create_cli_parser()
	if cli_parsed.h:
		recon.parser.print_help()
		sys.exit()
	if cli_parsed.domain == "" and cli_parsed.organization == "" or (cli_parsed.bgpipspace is False and cli_parsed.bgpamass is False and cli_parsed.censys is False and cli_parsed.certdomain is False and cli_parsed.amassactive is False and cli_parsed.amasspassive is False and cli_parsed.subfinder is False and cli_parsed.ctfr is False and cli_parsed.ctexposer is False and cli_parsed.certgraph is False and cli_parsed.certspotter is False and cli_parsed.fdnsr7 is False and cli_parsed.commonspeak is False and cli_parsed.cnames is False and cli_parsed.s3scanner is False and cli_parsed.webscreenshot is False and cli_parsed.sslscan is False and cli_parsed.webtech is False and cli_parsed.internalip is False and cli_parsed.crlfinjection is False and cli_parsed.gobuster is False and cli_parsed.openredirection is False and cli_parsed.masscan is False and cli_parsed.jenkins is False):
			recon.parser.print_help()
			sys.exit()
	else:
		recon.GeDomainRecon(cli_parsed.domain,
						cli_parsed.organization,
						cli_parsed.bgpipspace,
						cli_parsed.bgpamass,
						cli_parsed.censys,
						cli_parsed.certdomain,
						cli_parsed.amassactive,
						cli_parsed.amasspassive,
						cli_parsed.subfinder,
						cli_parsed.ctfr,
						cli_parsed.ctexposer,
						cli_parsed.certgraph,
						cli_parsed.certspotter,
						cli_parsed.fdnsr7,
						cli_parsed.commonspeak,
						cli_parsed.cnames,
						cli_parsed.s3scanner,
						cli_parsed.webscreenshot,
						cli_parsed.sslscan,
						cli_parsed.webtech,
						cli_parsed.internalip,
						cli_parsed.crlfinjection,
						cli_parsed.gobuster,
						cli_parsed.openredirection,
						cli_parsed.masscan,
						cli_parsed.jenkins)