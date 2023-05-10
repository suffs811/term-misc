#!/usr/bin/python3
# author: suffs811
# Copyright (c) 2023 suffs811
# https://github.com/suffs811/term-misc.git
# read the README.md file for more details; software distributed under MIT license
#
# <> purpose: automate enumeration using nmap, curl, gobuster, enum4linux, and showmount


import os
import argparse
import time
import re


parser = argparse.ArgumentParser(description="script for automating common enumeration techniques")
parser.add_argument("ip", help="ip or domain to enumerate")
parser.add_argument("-w", "--wordlist", help="specify wordlist for directory walking (gobuster)")
args = parser.parse_args()
ip = args.ip
wordlist = args.wordlist



print('''
 _______ _    _ ______ 
|__   __| |  | |  ____|  
   | |  | |__| | |__                                            |
   | |  |  __  |  __|  > - - - - - - - - - - - - - - - - - - +++ +++
   | |  | |  | | |____                                          | 
   |_|  |_|  |_|______|
 _______ ______ _____  __  __ _____ _   _       _______ ____  _____  
|__   __|  ____|  __ \|  \/  |_   _| \ | |   /\|__   __/ __ \|  __ \ 
   | |  | |__  | |__) | \  / | | | |  \| |  /  \  | | | |  | | |__) |
   | |  |  __| |  _  /| |\/| | | | | . ` | / /\ \ | | | |  | |  _  / 
   | |  | |____| | \ \| |  | |_| |_| |\  |/ ____ \| | | |__| | | \ \ 
   |_|  |______|_|  \_\_|  |_|_____|_| \_/_/    \_\_|  \____/|_|  \_\ 
\n
\\ created by: suffs811
\\ https://github.com/suffs811/the-terminator.git
''')

time.sleep(2)


# enumeration ###############################

# run nmap scans
def init_scan(ip):
   ports = []
   services = []

   # make terminator directory for output files
   os.system("mkdir /terminator/")
   os.system("chmod 777 /terminator/")
   os.system("touch /terminator/enum.txt")
   os.system("echo '### enumeration details for {} ###' > /terminator/enum.txt".format(ip))

   # run initial port scan
   print("\n### finding open ports... ###")
   os.system("nmap -vv -sS -n -Pn -T5 -p- {} -oN /terminator/scan_1".format(ip))

   # get ports for next scan
   with open("/terminator/scan_1") as scan_1:
      lines_1 = scan_1.readlines()
      for line in lines_1:
         number = re.search("\A[1-9][0-9]",line)
         if number:
            line_split = line.split(" ")
            first_word = line_split[0]
            ports.append(first_word[:-4].strip())
         else:
            continue

   print("\n### open ports: {}".format(ports))
   time.sleep(3)
   print("\n### finding services for ports... ###")
   port_scan = ",".join(ports)
   os.system("nmap -vv -A -p {} {} -oN /terminator/scan_2".format(port_scan,ip))

   # get services for open ports
   with open("/terminator/scan_2") as scan_2:
      lines_2 = scan_2.readlines()
      for line in lines_2:
         number = re.search("\A[1-9][0-9]",line)
         if number:
            services.append(line)
         else:
            continue

   os.system("echo ''")
   os.system("echo '### open ports and services on {} ###'| tee -a /terminator/enum.txt".format(ip))
   for item in services:
      os.system("echo '{}' | tee -a /terminator/enum.txt /terminator/services.txt".format(item))

   time.sleep(3)

   return services


# enumerate web service with nikto, gobuster, curl
def web(ip,wordlist,services):
   print("\n### initiating web enumeration... ###")
   web_port = []
   for line in services:
      if "http" in line or "web" in line:
         split = line.split(" ")
         tcp = split[0]
         psplit = tcp.split("/")
         web_port.append(psplit[0])
      else:
         continue

   print("\n### running nikto... ###")
   os.system("echo '### nikto results ###' >> /terminator/enum.txt")
   os.system("nikto -h {} -t 3 -ask no | tee -a /terminator/enum.txt".format(ip))
   print("\n### running gobuster... ###")
   if wordlist:
      os.system("echo '### gobuster results ###' >> /terminator/enum.txt")
      os.system("gobuster dir -u {} -w {} | tee -a /terminator/enum.txt".format(ip,wordlist))
   else:
      os.system("echo '### gobuster results ###' >> /terminator/enum.txt")
      os.system("gobuster dir -u {} -w directory-list.txt | tee -a /terminator/enum.txt".format(ip))
   os.system("echo '### robots.txt results ###' >> /terminator/enum.txt")
   for port in web_port:
      print("\n### curling robots.txt for {}:{}... ###".format(ip,port))
      os.system("curl http://{}:{}/robots.txt | tee /terminator/robots.txt".format(ip,port.strip()))
      with open("/terminator/robots.txt") as rob:
         r = rob.readlines()
         for line in r:
            if "/" in line:
               os.system("echo '{}' >> /terminator/enum.txt".format(line))
               os.system("echo '{}' >> /terminator/robots_dir.txt".format(line))
            else:
               continue

      # look for 'username' and 'password' in web page source code
      os.system("echo '/# curl results #' > /terminator/curl.txt")
      os.system("curl http://{}:{} >> /terminator/curl.txt".format(ip,port.strip()))
      curl = open("/terminator/curl.txt")
      c = curl.readlines()
      os.system("echo '# possible username/password from webpages: #' >> /terminator/curl_find.txt")
      for line in c:
         x = line.split('"')
         for sec in x:
            if "html" in sec or "htm" in sec or "php" in sec or "css" in sec:
               os.system("curl http://{}:{}/{} > /terminator/curltmp.txt".format(ip,port.strip(),sec.strip()))
               os.system("grep -e 'username' -e 'password' /terminator/curltmp.txt >> /terminator/curl_find.txt")
               os.system("echo '' > /terminator/curltmp.txt")
            else:
               continue
      curl.close()


   print("\n### web enum output saved to /terminator/enum.txt ###")
   os.system("rm -f /terminator/curl.txt")


# use enum4linux and nmap to enumerate smb shares/users
def smb(ip):
   print("\n### initiating smb enumeration... ###")
   os.system("echo '### smb enumeration results ###' >> /terminator/smb.txt")
   os.system("locate enum4linux > /terminator/wheresmb.txt")
   wheresmb = open("/terminator/wheresmb.txt")
   smbloc = wheresmb.readline()
   os.system("{} -a {} >> /terminator/smb.txt".format(smbloc.strip(),ip))
   os.system("{} -U {} | grep 'user' >> /terminator/smb_plus.txt".format(smbloc.strip(),ip))
   os.system("{} -S {} | grep 'Disk' >> /terminator/smb_plus.txt".format(smbloc.strip(),ip))
   os.system("cat smb_plus.txt >> /terminator/smb.txt")
   os.system("echo '' >> /terminator/smb.txt")
   os.system("nmap -vv -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse {} -oN /terminator/nmap_smb.txt".format(ip))
   os.system("echo '' >> /terminator/smb.txt")
   os.system("cat /terminator/nmap_smb.txt >> /terminator/smb.txt")

   es = open("/terminator/smb.txt")
   esr = es.read()
   enum_smb = re.sub(r"\\", "/", esr)

   os.system("touch /terminator/nsmb.txt")
   nsmb = open(r"/terminator/nsmb.txt", "w")
   nsmb.writelines(enum_smb)

   es.close()
   nsmb.close()
   wheresmb.close()

   os.system("cat /terminator/nsmb.txt >> /terminator/enum.txt")
   print("\n### smb enum output saved to /terminator/enum.txt ###")


# use nmap to try ftp anonymous login
def ftp(ip):
   print("\n### initiating ftp enumeration... ###")
   os.system("echo '### ftp enumeration results ###' >> /terminator/enum.txt")
   os.system("echo '-- ftp anonymous login:' >> /terminator/ftp_enum.txt")
   os.system("nmap -vv -p 21 --script=ftp-anon {} -oN /terminator/ftp_nmap.txt".format(ip))
   os.system("cat /terminator/ftp_nmap.txt >> /terminator/enum.txt")
   print("\n### ftp enum output saved to /terminator/enum.txt ###")


# use nmap to show NFS mounts
def nfs(ip):
   print("\n### initiating nfs enumeration... ###")
   os.system("echo '### nfs enumeration results ###' >> /terminator/enum.txt")
   os.system("nmap -vv -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount {} -oN /terminator/nfs_nmap.txt".format(ip))
   os.system("cat /terminator/nfs_nmap.txt >> /terminator/enum.txt")
   os.system("echo '' >> /terminator/enum.txt")
   os.system("echo '### NFS mounts ###' >> /terminator/enum.txt")
   os.system("/usr/sbin/showmount -e {} >> /terminator/enum.txt".format(ip))
   os.system("/usr/sbin/showmount -e {} >> /terminator/nfs.txt".format(ip))
   print("\n### nfs enum output saved to /terminator/enum.txt ###")


# save important findings to file and print to screen
def imp_enum(ip):
   os.system("touch /terminator/imp_enum_results.txt")
   os.system("echo ''")
   os.system("echo ''")
   os.system("echo ''")
   os.system("echo '***********************************************************'")
   os.system("echo ''")
   os.system("echo '### enumeration results saved to /terminator/ directory ###'")
   os.system("echo ''")
   os.system("echo '***********************************************************'")
   os.system("echo '<> open ports and services on {} <>' >> /terminator/imp_enum_results.txt".format(ip))
   os.system("cat /terminator/services.txt >> /terminator/imp_enum_results.txt")
   os.system("rm -f /terminator/services.txt")
   os.system("echo ''")
   os.system("echo '### important findings: ###' >> /terminator/imp_enum_results.txt")
   os.system("echo ''")

   # get important enum results
   with open("/terminator/enum.txt") as enum:
      e = enum.readlines()
      for line in e:
         smb_check = re.search("//{}/.".format(ip),line)
         if "interesting" in line:
            os.system("echo '{}' >> /terminator/web_enum.txt".format(line.strip()))
            os.system("echo '' >> /terminator/web_enum.txt")
         elif "robots" in line and "#" not in line:
            os.system("echo '{}' >> /terminator/web_enum.txt".format(line.strip()))
            os.system("echo '' >> /terminator/web_enum.txt")
         elif "Anonymous FTP" in line:
            os.system("echo '{}' >> /terminator/ftp_enum.txt".format(line.strip()))
            os.system("echo '' >> /terminator/ftp_enum.txt")
         elif "allows session" in line or "allow session" in line:
            os.system("echo '-- smb no-auth login:' >> /terminator/smb_enum.txt")
            os.system('echo "{}" >> /terminator/smb_enum.txt'.format(line.strip()))
            os.system("echo '' >> /terminator/smb_enum.txt")
         else:
            continue

   # save important enum results to /terminator/imp_enum_results.txt and print to screen
   os.system("cat /terminator/web_enum.txt >> /terminator/imp_enum_results.txt 2>/dev/null")
   os.system("echo '' >> /terminator/imp_enum_results.txt")
   os.system("echo 'robots.txt:' >> /terminator/imp_enum_results.txt")
   os.system("cat /terminator/robots_dir.txt >> /terminator/imp_enum_results.txt 2>/dev/null")
   os.system("echo '' >> /terminator/imp_enum_results.txt")
   os.system("cat /terminator/curl_find.txt >> /terminator/imp_enum_results.txt 2>/dev/null")
   os.system("echo '' >> /terminator/imp_enum_results.txt")
   os.system("cat /terminator/ftp_enum.txt >> /terminator/imp_enum_results.txt 2>/dev/null")
   os.system("echo '' >> /terminator/imp_enum_results.txt")
   os.system("echo '### smb users/shares: ###' >> /terminator/imp_enum_results.txt")
   os.system("cat /terminator/smb_plus.txt >> /terminator/imp_enum_results.txt 2>/dev/null")
   os.system("echo '' >> /terminator/imp_enum_results.txt")
   os.system("echo '-- nfs mounts:' >> /terminator/imp_enum_results.txt")
   os.system("cat /terminator/nfs.txt >> /terminator/imp_enum_results.txt 2>/dev/null")
   os.system("echo '' >> /terminator/imp_enum_results.txt")
   os.system("cat /terminator/imp_enum_results.txt")

   # delete temp enum files
   os.system("rm -f /terminator/robots_dir.txt 2>/dev/null")
   os.system("rm -f /terminator/web_enum.txt 2>/dev/null")
   os.system("rm -f /terminator/curl_find.txt 2>/dev/null")
   os.system("rm -f /terminator/ftp_enum.txt 2>/dev/null")
   os.system("rm -f /terminator/nsmb.txt 2>/dev/null")
   os.system("rm -f /terminator/smb_plus.txt 2>/dev/null")
   os.system("rm -f /terminator/nfs.txt 2>/dev/null")
   os.system("rm -f /terminator/wheresmb.txt 2>/dev/null")
   os.system("rm -f /terminator/smb_enum.txt 2>/dev/null")


# move important findings to results.html
def flask():
   pwd = os.getcwd()
   enum = open(r"/terminator/imp_enum_results.txt", "r")
   results = open(r"{}/results.html", "w+")
   r = results.read()
   e = enum.read()
   x = re.sub("FILL", e, r)
   results.write(x)

   enum.close()
   results.close()


# call enumeration functions
# prevent rerunning functions if more than one instance of service
webc = 0
smbc = 0
ftpc = 0
nfsc = 0
services = init_scan(ip)
for line in services:
  l = line.split(" ")
  for valueu in l:
     value = valueu.lower()
     if "http" in value:
        if webc == 0:
           web(ip,wordlist,services)
           webc = 1
        else:
           continue
     elif "smb" in value or "samba" in value:
        if smbc == 0:
           smb(ip)
           smbc = 1
        else:
           continue
     elif "ftp" in value:
        if ftpc == 0:
           ftp(ip)
           ftpc = 1
        else:
           continue
     elif "nfs" in value or "rpc" in value:
        if nfsc == 0:
           nfs(ip)
           nfsc = 1
        else:
           continue
     else:
       continue
imp_enum(ip)
flask()
os.system("echo '### end of enumeration ###' | tee -a /terminator/enum.txt")