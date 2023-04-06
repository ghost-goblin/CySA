<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)


### 🖥️ Home Lab

</div>


- - -

#### Google Hacking
+ `"Jessica Hyde"`, exact match of the string
+ `@`, search for results in social media
+ `site:microsoft.com`
+ `intext:"CVE-2020-1472" site:microsoft.com`

#### Windows
+ IIS Web Server
   + `%SYSTEMDRIVE%\inetpub\wwwroot`
+ `secpol.msc` - Windows Local Security Policy
+ Add user to administrator group
   + `net user <name> <pass> /add`
   + `net localgroup "Administrators" <user> add`
+ Disable firewall
   + `netsh advfirewall set currentprofile state off`
   + `netsh advfirewall set allprofiles state off`
+ Uninstall patch to exploit a vulnerability
   + Display all patches:
   + `dir /a /b c:\windows\kb*`
+ Uninstall patch
   + `wusa.exe /uninstall /kb:<###>`

#### Kali Configs
  
```sh
# Returns useful information about the specific flavour of the OS and its kernel
uname -a

# Prints out a routing table
netstat -rn
ip route

# Add route to routing table
ip route add 192.168.222.52 via 10.175.30.1

# Install and enable rdp services
sudo apt install xrdp
sudo systemctl enable xrdp

# Set a static IP address on your Linux machine
sudo nano /etc/network/interfaces
## Add the following config: 
auto eth0
iface eth0 inet static
        address 192.168.1.215/24
        network 192.168.1.0
        netmask 255.255.255.0
        broadcast 192.168.1.255
        gateway 192.168.1.254
        dns-nameservers 192.168.1.254

# Configure DNS to resolve IPs to hostnames
systemd-resolve --interface lateralmovement --set-dns 10.200.78.101 --set-domain za.tryhackme.com
nslookup thmdc.za.tryhackme.com
```

#### Metasploit Framework

```sh
# Initialise the database
sudo msfdb init
msfconsole -q
```


#### 🔥 PfSense Firewall
+ Hyper-V / Virtualbox setup
   + `WAN` > bridged adapter to the external network
   + `LAN` > `Default Switch` adapter in Hyper-V
   + Attach both adapters to the virtual machine and access the admin portal on the `LAN` network on another machine: `http://192.168.1.1/`
+ **Blackholing** can be used to stop a DDoS attack at the routing layer by sending traffic to the `null0` interface

