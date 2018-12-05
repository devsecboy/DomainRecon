apt install python-pip
pip install -r Sublist3r/requirements.txt
pip install -r recon-ng/REQUIREMENTS
pip install -r S3Scanner/requirements.txt
./EyeWitness/setup/setup.sh
touch ./Sublist3r/__init__.py
apt-get install libldns-dev
make -C massdns
