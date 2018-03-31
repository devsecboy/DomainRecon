import os, errno

class GlobalVariables(object):
    def __init__(self):
        self.outputDir = './Output/'
        self.screenShotDir = self.outputDir + "ScreenShot/"
        self.cloudFlareDir = self.outputDir + "CloudFlare/"
        self.subDomainTakeOverDir = self.outputDir + "SubDomainTakeOver/"
        self.wordList = "./recon-ng/data/hostnames.txt"

        try:
    		os.makedirs(self.outputDir)
		except OSError as e:
    		if e.errno != errno.EEXIST:
        		raise

        try:
    		os.makedirs(self.screenShotDir)
		except OSError as e:
    		if e.errno != errno.EEXIST:
        		raise

        try:
    		os.makedirs(self.subDomainTakeOverDir)
		except OSError as e:
    		if e.errno != errno.EEXIST:
        		raise

        try:
    		os.makedirs(self.cloudFlareDir)
		except OSError as e:
    		if e.errno != errno.EEXIST:
        		raise