import socket
from EnumSubDomain import *
from SubDomainTakeOverChk import *
#from EyeWitness import *

class DomainRecon(object):

	def __init__(self):
		self.enumSubDomain=EnumSubDomain()
		#self.eyeWitness=EyeWitness()
		self.subDomainTakeOverChk=SubDomainTakeOverChk()
	
	def collectSubDomain(self, domain, False):
		self.enumSubDomain.GetSubDomains(domain)

	'''def collectScreenShot(self):
		self.eyeWitness.CaptureScreenShots()'''

	def chkSubDomainTakeOver(self):
		self.subDomainTakeOverChk.runSubDomainTakeOverChk()

if __name__ == "__main__":
	domainRecon=DomainRecon()
	domain = input("Enter domain to find subdomain : ")
	#domainRecon.collectScreenShot()
	domainRecon.collectSubDomain(domain)
	domainRecon.chkSubDomainTakeOver()
