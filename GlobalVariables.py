import os, errno

class GlobalVariables(object):
    def __init__(self):
        self.outputDir = './Output/'
        self.screenShotDir = self.outputDir + "ScreenShot/"
        self.cloudFlareDir = self.outputDir + "CloudFlare/"
        self.cnameEnumDir = self.outputDir + "CNameEnum/"
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
            os.makedirs(self.cnameEnumDir)
        except OSError:
            if not os.path.isdir(self.cnameEnumDir):
                raise

        try: 
            os.makedirs(self.cloudFlareDir)
        except OSError:
            if not os.path.isdir(self.cloudFlareDir):
                raise