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
			print "processing amass active scan.."
			output+=self.globalVariables.CommandExecutor("amass enum -active -d {}".format(domain))
		if amasspassive:
			print "processing amass passive scan.."
			output+=self.globalVariables.CommandExecutor("amass enum -passive -d {}".format(domain))
		return output

	def SubDomainsSubFinder(self, domain):
		return self.globalVariables.CommandExecutor("subfinder -d {}".format(domain))

	def SubDomainsCommonSpeak(self, domain):
		return self.globalVariables.CommandExecutor("gobuster dns -d {} -w commonspeak-wordlist.txt | cut -d' ' -f2".format(domain))

	def SubDomainsCertDomainFinder(self, domain):
		return self.globalVariables.CommandExecutor("certdomainfinder {}".format(domain))

	def SubDomainsFDNSRapid7(self, domain):
		fDNSRapid7URL=''
		request = requests.get(self.globalVariables.fDNSRapid7, headers=self.globalVariables.bgp_headers, timeout=10)
		soup = BeautifulSoup(request.text, "lxml")
		for row in soup.findAll("tr", class_="ungated"):
			column=row.findAll('td')
			filename=column[0].find('a').get_text().strip()
			if filename.find("fdns_any") != -1:
				fDNSRapid7URL=filename
		fDNSRapid7URL=self.globalVariables.fDNSRapid7 + fDNSRapid7URL
		return self.globalVariables.CommandExecutor("fdns -domain {} -record A -t 4 -url {}".format(domain, fDNSRapid7URL))

	def SubDomainsFindDomain(self, domain):
		return self.globalVariables.CommandExecutor("findomain-linux -t {} | cut -d' ' -f3".format(domain))

	def SubDomainsCTFR(self, domain):
		return self.globalVariables.CommandExecutor("ctfr.py -d {} | cut -d' ' -f3".format(domain))

	def SubDomainsCTExposer(self, domain):
		return self.globalVariables.CommandExecutor("ct-exposer.py -d {} | cut -f2".format(domain))

	def SubDomainsCertGraph(self, domain):
		return self.globalVariables.CommandExecutor("certgraph {}".format(domain))

	def SubDomainsCensys(self, domain):
		os.environ['CENSYS_API_ID']=self.globalVariables.censysApiID
		os.environ['CENSYS_API_SECRET']=self.globalVariables.censysApiSecret
		return self.globalVariables.CommandExecutor("censys_subdomain_finder.py {} | cut -d' ' -f4".format(domain))

	def SubDomainsCertSpotter(self, domain):
		requetURL="{}{}".format(self.globalVariables.certSpotterURL, domain)
		request = requests.get(requetURL, headers=self.globalVariables.bgp_headers, timeout=10)
		jsonData=json.loads(request.text)
		output=''
		for items in jsonData:
			for item in items['dns_names']:
				output += item +"\n"
		return output

	def checkForUpHostUsingFilterResolved(self, fileName, outFileName):
		self.globalVariables.CommandExecutor("cat {} | filter-resolved > {}".format(fileName, outFileName))
	
	def checkForCNAMEUsingMassDNS(self, fileName, resolverOutPutFileName, outFileName):
		self.globalVariables.CommandExecutor("massdns -r {}lists/resolvers.txt {} > {}".format(self.globalVariables.massDNSPath, fileName, resolverOutPutFileName))
		self.globalVariables.CommandExecutor("cat {} | grep CNAME > {}".format(resolverOutPutFileName, outFileName))

	def GetAllDomains(self, domain, organization, bgpipspace, bgpamass, censys, certdomain, amassactive, amasspassive, subfinder, ctfr, ctexposer, certgraph, certspotter, fdnsr7, commonspeak, outFileName):

		if bgpipspace:
			print "processing bgp.net.."
			self.CollectIPSpaces(organization, domain)

		if bgpamass:
			print "processing bgp ip ranges + amass.."
			output=self.SubDomainsFromIPSpaces(domain)
			self.globalVariables.WriteTextToFile(outFileName, "BGP IP Ranges + Amass\n" + output)
		
		if censys:
			print "processing Censys.."
			output=self.SubDomainsCensys(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Censys\n" + output)
		
		if certdomain:
			print "processing certdomainfinder.."
			output=self.SubDomainsCertDomainFinder(domain)
			self.globalVariables.WriteTextToFile(outFileName, "cert domain finder\n" + output)
		
		output=self.SubDoainsFromAmass(domain, amassactive, amasspassive)
		if amassactive or amasspassive:
			self.globalVariables.WriteTextToFile(outFileName, "amass\n" + output)
		
		if subfinder:
			print "processing subfinder.."
			output=self.SubDomainsSubFinder(domain)
			self.globalVariables.WriteTextToFile(outFileName, "subfinder\n" + output)
		
		if ctfr:
			print "processing CTFR.."
			output=self.SubDomainsCTFR(domain)
			self.globalVariables.WriteTextToFile(outFileName, "CTFR\n" + output)

		if ctexposer:
			print "processing CT-EXposer.."
			output=self.SubDomainsCTExposer(domain)
			self.globalVariables.WriteTextToFile(outFileName, "CT-Exposer\n" + output)

		if certgraph:
			print "processing CertGraph.."
			output=self.SubDomainsCertGraph(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Cert Graph\n" + output)
		
		if certspotter:
			print "processing CertSpotter.."
			output=self.SubDomainsCertSpotter(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Cert Spotter\n" + output)

		if fdnsr7:
			print "processing Rapid7.."
			output=self.SubDomainsFDNSRapid7(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Rapid7\n" + output)
			
		if commonspeak:
			print "processing CommonSpeak.." + domain
			output=self.SubDomainsCommonSpeak(domain)
			self.globalVariables.WriteTextToFile(outFileName, "Common Speak\n" + output)

