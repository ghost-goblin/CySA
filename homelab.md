<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

</div>


- - -



- - - 


### 🖥️ Home Lab

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
```

#### Metasploit Framework

```sh
# Initialise the database
sudo msfdb init
msfconsole -q
```

#### 🚩 **Banner Grabbing**
```sh
echo " " | nc -v 10.10.226.5 80
```

#### 🔥 PfSense Firewall
+ Hyper-V / Virtualbox setup
   + `WAN` > bridged adapter to the external network
   + `LAN` > `Default Switch` adapter in Hyper-V
   + Attach both adapters to the virtual machine and access the admin portal on the `LAN` network on amother machine: `http://192.168.1.1/`
