# hello! welcome to the terminator's individual scripts
- you can use these to isolate an individual stage of the penetration test, instead of using terminator.py.

*terminator.py is the primary method for using the terminator since these individual scripts are not actively updated!*

the full, updated terminator tool can be found here: https://github.com/suffs811/the-terminator 

- feel free to leave a comment or suggestion for making the terminator better

- enum.py - script for automating common enumeration techniques (nmap,web,ftp,smb,nfs)
- priv.py - script to automate common privelege escalation techniques
- pers.py - script for establishing persistence on compromised target machine with root permissions.
- exfil.py - script for writing system data and /etc files to file, scp the file to local machine, and covers tracks by clearing logs.
- report.py - script to compile pentest data from the above scripts and create a report with it in both .txt and .docx formats named by -o input
- doc.py - script for creating a .docx file for the report from the terminator's findings

*report.py will likely not function properly if the individual scripts are used; so, to ensure proper report.py functionality, please use terminator.py*
