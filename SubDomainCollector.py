from CollectIPSpaces import *
import os
import json

class SubDomainCollector(object):
	"""docstring for SubDomainCollector"""
	def __init__(self):
		super(SubDomainCollector, self).__init__()
		self.globalVariables=GlobalVariables()

	def SubDomainsFromIPSpaces(self, domain):
		ipRanges=[]
		self.outIPv4Ranges="{}{}/{}".format(self.globalVariables.outputDir, domain, "ipv4ranges.txt")
		file = open(self.outIPv4Ranges, "r")
		for ipRange in file:
			ipRanges.append(ipRange)
		
		self.outIPv6Ranges="{}{}/{}".format(self.globalVariables.outputDir, domain, "ipv6ranges.txt")
		file = open(self.outIPv6Ranges, "r")
		for ipRange in file:
			ipRanges.append(ipRange)

		output=''
		for ipRange in ipRanges: 
			output+=self.globalVariables.CommandExecutor("amass intel -cidr {}".format(ipRange))
			output+="\n"
		return output

	def CollectIPSpaces(self, companyName, domain):
		collectIPSpaces=CollectIPSpaces()
		collectIPSpaces.GetAllIPSpaces(companyName, domain)
				
	def SubDoainsFromAmass(self, domain, amassactive, amasspassive):
		output=''
		if amassactive:
			print ("processing amass active scan..")
			output+=self.globalVariables.CommandExecutor("amass enum -active -d {}".format(domain))
		if amasspassive:
			print ("processing amass passive scan..")
			output+=self.globalVariables.CommandExecutor("amass enum -passive -d {}".format(domain))
		return output

	def SubDomainsSubFinder(self, domain):
		return self.globalVariables.CommandExecutor("subfinder -d {}".format(domain))

	def SubDomainsGitHubSubDomains(self, domain):
		return self.globalVariables.CommandExecutor("github-subdomains -d {} -t {} |sed -r 's/.*(dm[^\\.]*\\.[^/ ]*).*/\1/g' | grep -v 'github.com\\|keyword:\\|current search' | cut -d ' ' -f 2 | sed 's/\x1B\\[[0-9;]\\{{1,\\}}[A-Za-z]//g'".format(domain, self.globalVariables.gitHubToken))

	def SubDomainsGitLabSubdomains(self, domain):
		return self.globalVariables.CommandExecutor("gitlab-subdomains -d {} -t {}".format(domain, self.globalVariables.gitLabToken))

	def SubDomainsAssetFinder(self, domain):
		return self.globalVariables.CommandExecutor("assetfinder --subs-only {}".format(domain))

	def SubDomainsCommonSpeak(self, domain):
		return self.globalVariables.CommandExecutor("gobuster dns -d {} -w {} -t {} | cut -d' ' -f2".format(domain, self.globalVariables.subdomainWordlist, self.globalVariables.goBusterThread))

	def SubDomainsCertDomainFinder(self, domain):
		#old tool so removed
		#return self.globalVariables.CommandExecutor("certdomainfinder {}".format(domain))
		return ""

	def SubDomainsFDNSRapid7(self, domain):
		fDNSRapid7URL=''
		request = requests.get(self.globalVariables.fDNSRapid7, headers=self.globalVariables.bgp_headers, timeout=10)
		soup = BeautifulSoup(request.text, "lxml")
		
		for row in soup.findAll("tr", class_="gated"):
			column=row.findAll('td', {"class": "filename"})
			filename=column[0].get_text().strip()
			if filename.find("fdns_any") != -1:
				fDNSRapid7URL=filename
		fDNSRapid7URL=self.globalVariables.fDNSRapid7 + fDNSRapid7URL
		print (fDNSRapid7URL)
		return self.globalVariables.CommandExecutor("fdns --domains {} --records \"A,AAAA,CNAME\" --goroutines 4 --url {}".format(domain, fDNSRapid7URL))

	def SubDomainsFindDomain(self, domain):
		return self.globalVariables.CommandExecutor("findomain -t {} | cut -d' ' -f3".format(domain))

	def SubDomainsCTFR(self, domain):
		return self.globalVariables.CommandExecutor("ctfr.py -d {} | cut -d' ' -f3".format(domain))

	def SubDomainsCTExposer(self, domain):
		return self.globalVariables.CommandExecutor("ct-exposer.py -d {} | cut -f2".format(domain))

	def SubDomainsCertGraph(self, domain):
		return self.globalVariables.CommandExecutor("certgraph {}".format(domain))

	def SubDomainsCensys(self, domain):
		os.environ['CENSYS_API_ID']=self.globalVariables.censysApiID
		os.environ['CENSYS_API_SECRET']=self.globalVariables.censysApiSecret
		return self.globalVariables.CommandExecutor("censys-subdomain-finder.py {} | cut -d' ' -f4".format(domain))

	def SubDomainsCertSpotter(self, domain):
		requetURL="{}{}".format(self.globalVariables.certSpotterURL, domain)
		request = requests.get(requetURL, headers=self.globalVariables.bgp_headers, timeout=10)
		jsonData=json.loads(request.text)
		output=''
		for items in jsonData:
			for item in items['dns_names']:
				output += item +"\n"
		return output

	def ExtractDomainOnly(self, fileName, outFileName):
		self.globalVariables.CommandExecutor("cat {} | grep '\\.' | sed -r 's/.(dm[^.].[/ ])./\\1/g' | sort -u | grep -v '+' > {}".format(fileName, outFileName))

	def checkForUpHostUsingHttpProbe(self, fileName, outFileName):
		print ("Chacking domain using httprobe")
		self.globalVariables.CommandExecutor("cat {} | httprobe > {}".format(fileName, outFileName))

	def checkForResolvedDomain(self, fileName, outFileName, uniqResolvDomain):
		print ("Resolving domain using resolve.py")
		self.globalVariables.CommandExecutor("resolv.py {} | grep . | sort -u > {}".format(fileName, outFileName))
		self.globalVariables.CommandExecutor("cat {} | grep -v 'unresolvable\\|RType' > {}".format(outFileName, uniqResolvDomain))
	
	def checkForCNAMEUsingMassDNS(self, fileName, resolverOutPutFileName, outFileName):
		print ("Checking CNAMEs using MassDNS")
		self.globalVariables.CommandExecutor("massdns -r {}lists/resolvers.txt {} > {}".format(self.globalVariables.massDNSPath, fileName, resolverOutPutFileName))
		self.globalVariables.CommandExecutor("cat {} | grep CNAME > {}".format(resolverOutPutFileName, outFileName))

	def GetAllDomains(self, domain, organization, bgpipspace, bgpamass, censys, assetfinder, github, gitlab, finddomain, certdomain, amassactive, amasspassive, subfinder, ctfr, ctexposer, certgraph, certspotter, fdnsr7, commonspeak, outFileName):

		if bgpipspace:
			print ("processing bgp.net..")
			self.CollectIPSpaces(organization, domain)

		if bgpamass:
			print ("processing bgp ip ranges + amass..")
			output=self.SubDomainsFromIPSpaces(domain)
			self.globalVariables.WriteTextToFile(outFileName, "BGP IP Ranges + Amass\n" + output)
		
		if censys:
			print ("processing Censys..")
			output=self.SubDomainsCensys(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Censys\n" + output)

		if gitlab:
			print ("processing Gitlab subdomains..")
			output=self.SubDomainsGitLabSubdomains(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Gitlab\n" + output)

		if assetfinder:
			print ("processing assetfinder..")
			output=self.SubDomainsAssetFinder(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Assetfinder\n" + output)

		if github:
			print ("processing GitHub subdomains..")
			output=self.SubDomainsGitHubSubDomains(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Github\n" + output)
		
		if finddomain:
			print ("processing FindDomain..")
			output=self.SubDomainsFindDomain(domain)
			self.globalVariables.WriteTextToFile(outFileName, "FindDomain\n" + output)

		if certdomain:
			print ("processing certdomainfinder..")
			output=self.SubDomainsCertDomainFinder(domain)
			self.globalVariables.WriteTextToFile(outFileName, "cert domain finder\n" + output)
		
		output=self.SubDoainsFromAmass(domain, amassactive, amasspassive)
		if amassactive or amasspassive:
			self.globalVariables.WriteTextToFile(outFileName, "amass\n" + output)
		
		if subfinder:
			print ("processing subfinder..")
			output=self.SubDomainsSubFinder(domain)
			self.globalVariables.WriteTextToFile(outFileName, "subfinder\n" + output)
		
		if ctfr:
			print ("processing CTFR..")
			output=self.SubDomainsCTFR(domain)
			self.globalVariables.WriteTextToFile(outFileName, "CTFR\n" + output)

		if ctexposer:
			print ("processing CT-EXposer..")
			output=self.SubDomainsCTExposer(domain)
			self.globalVariables.WriteTextToFile(outFileName, "CT-Exposer\n" + output)

		if certgraph:
			print ("processing CertGraph..")
			output=self.SubDomainsCertGraph(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Cert Graph\n" + output)
		
		if certspotter:
			print ("processing CertSpotter..")
			output=self.SubDomainsCertSpotter(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Cert Spotter\n" + output)

		if fdnsr7:
			print ("processing Rapid7..")
			output=self.SubDomainsFDNSRapid7(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Rapid7\n" + output)
			
		if commonspeak:
			print ("processing CommonSpeak.." + domain)
			output=self.SubDomainsCommonSpeak(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Common Speak\n" + output)

