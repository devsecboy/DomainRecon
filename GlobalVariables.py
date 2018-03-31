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
        except OSError:
            if not os.path.isdir(self.outputDir):
                raise

        try: 
            os.makedirs(self.screenShotDir)
        except OSError:
            if not os.path.isdir(self.screenShotDir):
                raise

        try: 
            os.makedirs(self.subDomainTakeOverDir)
        except OSError:
            if not os.path.isdir(self.subDomainTakeOverDir):
                raise

        try: 
            os.makedirs(self.cloudFlareDir)
        except OSError:
            if not os.path.isdir(self.cloudFlareDir):
                raise