# TMS6064-CS-Assignment1
TMS6064/TMV6064 Cyber Security Assignment 1 (10%) Due before 28 February, Saturday, 9:00 AM
# TMS6064/TMV6064 Cyber Security
## Assignment 1 – Reconnaissance Tools

Name: Aldrin Cedric bin Nicholas
Matric No: 25030712  

Name: Alven Allex
Matric No: 24030728  


Programme: Master in Information Technology Management  

---

## Task 1: Reconnaissance Tools in Kali Linux

Reconnaissance is the first phase of the penetration testing. The tester collects the information about the targeted system or network before attempting any kind of attack. The objective is to understand the structure, open ports, running services and possible weakness of the target. There are two types of reconnaissance: passive and active. The information collected helps the tester plan the next steps more effectively. In this task, tools such as Recon-ng, Nmap, Hping3, and DNSRecon are used to perform information gathering and network scanning. 


This assignment demonstrates the use of:
- Recon-ng
- Nmap
- Hping3
- DNSRecon


## Recon-ng
**What it is**: A Python-based tool for gathering public information (OSINT).

**The Interface**: Built to look and feel like Metasploit, making it easy for security pros to use.

**The Goal**: It automates the "busy work" of searching the web, APIs, and databases.

**The Benefit**:It centralizes all your findings into one searchable database, saving hours of manual research.


<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/c16f3d69-7e26-439a-aae4-02a485535570" />

**Launch**: Type recon-ng in the Kali Linux terminal to enter the interactive shell.

**Red Warnings**: These indicate missing API keys for specific services (like Shodan or Google).

**Functionality**: The tool is still fully usable; you just can't use the specific modules that require those missing credentials.

**Next Step**: You can usually start with "passive" modules that scrape public data without needing any keys at all.

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/e1b91d2b-c854-4667-9d9a-3557744f049d" />

**The Welcome**: When you launch, you'll see ASCII art and a summary of all available modules.

**Module Categories**: The tools are organized into three main types:

**Recon**: For gathering data.

**Reporting**: For exporting your findings.

**Discovery**: For interacting with the target directly.

**Customization**: The modular setup means you only load the specific scripts you need for your current target, keeping things clean and efficient.

___
**Feature 1: Workspace Management** 

**Storage**: Uses an embedded SQLite database to automatically save everything you find.

**Workspaces**: Acts like "folders" to keep different projects or clients completely separate.

**Isolation**: This structure prevents data contamination, ensuring info from "Target A" never accidentally mixes with "Target B."

**Efficiency**: Because it's a database, you can run complex queries to find specific patterns across all the data you've gathered.

<img width="476" height="44" alt="image" src="https://github.com/user-attachments/assets/708702b1-51a4-4d9d-8596-4482604c2f46" />

**The Command**: Running "workspaces create target1" sets up a fresh, isolated environment.

**Data Separation**: It creates a dedicated SQLite database specifically for "target1."

**Professionalism**: This prevents "data bleed," ensuring that IPs, emails, and hosts from one client never mix with another.

**Context**: Once created, your command prompt will change to show you are now working inside that specific workspace.

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/1887cb28-303c-4058-b94b-037d448ad1a4" />

**Switching Context**: The command "workspaces select target1" activates your specific project environment.

**Visual Feedback**: Your terminal prompt changes (e.g., from [default] to [target1]), so you always know exactly which target you are currently modifying.

**Inventory Management**: Running "workspaces list" displays a table of all your projects.

**Audit Trail**: The list includes last modification dates, helping you track when you last worked on a specific investigation.

___
**Feature 2: Marketplace and Modular Architecture**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/5eecb3b3-4065-45be-9dcd-2b3233716471" />


**The Command**: Running "marketplace install all" downloads the complete library of Recon-ng modules at once.

**Feature Access**: This unlocks the full suite of tools, including Discovery (finding sensitive files) and Exploitation (testing vulnerabilities like command injection).

**Efficiency**: Bulk installation ensures your environment is fully equipped for a deep-dive investigation without having to stop and download modules one by one.

**Preparation**: This is the standard "loadout" step to prepare Kali Linux for a comprehensive reconnaissance phase.

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/14d24210-c759-4eea-94f2-528b90b430b4" />


**Targeted Install**: The command "marketplace install recon/domains-hosts/hackertarget" downloads one specific tool instead of the entire library.

**Configuration Check**: After installation, the framework automatically audits the module to see if it’s ready to run.

**The "Red Text" Warning**: This is the API Key Check. it flags modules (like Shodan) that need external credentials to pull data.

**Critical Feedback**: These warnings prevent "silent failures," letting you know exactly which keys you need to add before the module can successfully gather intelligence.

___
**Feature 3: Automated Domain Enumeration**

<img width="476" height="299" alt="1" src="https://github.com/user-attachments/assets/db754b7b-b08a-494f-931f-c115e950d56c" />

**Module Activation**: Use modules load recon/domains-hosts/hackertarget to activate the specific script that queries the HackerTarget.com API for hostnames and IP addresses.

**Configuration Review**: The options list command reveals the module's settings, highlighting that the SOURCE variable is a required field that must be defined before execution.

**Target Selection**: Execute options set SOURCE example.com to assign the specific domain you wish to investigate to the module.

**Execution & Intelligence**: The run command executes the query, identifying hosts and IP addresses (e.g., www.example.com at 104.18.26.120) to automate preliminary intelligence gathering.

## Nmap

Nmap is the leading open-source tool for exploring networks, managing them, and checking security. It was created by Gordon "Fyodor" Lyon. Nmap works mainly at the transport and network layers of the OSI model. It uses raw IP packets in unique ways to check if hosts are available, map network layouts, find open ports, identify application versions, and determine the operating systems on target machines. It is very configurable and can perform stealthy SYN scans (-sS), full TCP connect scans, and UDP scans to meet different evasion needs

**Feature 1: Ping Scan**

<img width="940" height="339" alt="image" src="https://github.com/user-attachments/assets/3b7676c6-fe1e-4699-88c7-f5e1516c702a" />

**Host Verification**: Performs a Ping Scan to confirm if a target host is active and reachable on the network.

**Scan Optimization**: Utilizes the -sn flag to disable port scanning, focusing the tool's resources exclusively on host discovery.

**Operational Efficiency**: Provides quick confirmation of host status and latency (e.g., 45.33.32.156 is "up" with 0.27s latency) without generating the heavy traffic associated with full service scans.

**Footprint Analysis**: Identifies the target's IPv6 address, offering a more comprehensive view of the host's network presence.

**Stealth & Planning**: Serves as a light reconnaissance technique to check availability while maintaining a low profile before deploying more intensive scanning methods.

___
**Feature 2: Service and Detection**

<img width="950" height="334" alt="image" src="https://github.com/user-attachments/assets/b1598c41-c8bd-4664-b624-8be6d5654b97" />

**Service Identification**: Executes nmap -sV scanme.nmap.org to probe open ports and accurately determine active services and their specific version numbers.

**Detailed Scanning**: Successfully identifies critical open ports, such as Port 22 running OpenSSH 6.6.1p1 and Port 80 running Apache httpd 2.4.7.

**Environment Analysis**: Provides a deeper understanding of the target's software environment, moving beyond simple port status to granular application data.

**Vulnerability Mapping**: Enables the tester to research known exploits and vulnerabilities specific to the identified software builds, such as specific versions of SSH or Apache.

**OS Confirmation**: Includes a "Service Info" section that identifies the operating system (e.g., Linux), effectively narrowing the attack surface for strategic planning.

___
**Feature 3: OS Detection**

<img width="834" height="448" alt="image" src="https://github.com/user-attachments/assets/653ea109-95cd-41d2-96ba-920c4d4d1937" />


**OS Fingerprinting**: Executes sudo nmap -O -T4 -F scanme.nmap.org using the -O flag to perform remote operating system detection.

**Timing Optimization**: Incorporates the -T4 flag to accelerate the scanning process for faster results.

**Virtualized Environment Identification**: Analyzes network stack responses to provide an "Aggressive OS guess," identifying potential virtualized environments such as QEMU or Oracle VirtualBox.

**Port Status Analysis**: Displays the status of common ports, confirming that Port 22 (SSH) and Port 80 (HTTP) are open, while Port 53 (DNS) and Port 143 (IMAP) are closed.

**Strategic Strategy Shaping**: Provides essential environmental data that allows a penetration tester to tailor exploitation strategies toward the vulnerabilities of the specific identified OS.

___
## Hping3

Hping3 is a powerful command-line network tool and packet assembler. It gives security auditors detailed, byte-level control over creating TCP, UDP, ICMP, and RAW-IP packets. Unlike regular system ping tools that can only send basic ICMP Echo Requests, Hping3 allows for thorough network auditing, stateful firewall testing, Path MTU discovery, and manual protocol manipulation. It is commonly used to break through complex perimeter defenses that silently block standard scanning traffic.

<img width="817" height="364" alt="image" src="https://github.com/user-attachments/assets/dea24eae-bdc2-4c64-90ae-5ba8b06af913" />

___
**Feature 1:  ICMP Ping (Testing Basic Connectivity)**

<img width="817" height="364" alt="image" src="https://github.com/user-attachments/assets/af18bc29-cb3e-4ee0-b7ad-bf06a0a4d7ea" />

**Initial Discovery**: Uses hping3 to gather preliminary data on a target by testing for basic network connectivity.

**Packet Mode Selection**: Employs the -1 flag to enter ICMP mode, allowing the tool to perform a traditional ping function.

**Traffic Control**: Utilizes the -c 4 flag to limit the transmission to exactly four packets, keeping the probe concise.

**Status Confirmation**: Verifies that the target host is active by analyzing the Round Trip Time (rtt) and Time to Live (ttl) values returned in the terminal.

**Network Mapping**: Provides data that helps a penetration tester understand the responsiveness of the network and the likely path packets take to reach the destination.

___
**Feature 2: SYN Port Scanning**

<img width="892" height="178" alt="image" src="https://github.com/user-attachments/assets/fcab5759-4d36-4326-8018-505ca7e73206" />

**Targeted Packet Crafting**: Executes sudo hping3 -S -p 80 -c 1 scanme.nmap.org to send a single TCP SYN packet (-S) specifically to port 80 (-p 80).

**Response Analysis**: Receives a response containing the flags=SA (SYN-ACK) header, which serves as technical confirmation that the port is open.

**Connection Readiness**: Validates that the targeted service is active and ready to accept incoming network connections.

**Stealthy Identification**: Provides a method for identifying open ports that is less conspicuous than establishing a full TCP three-way handshake.

___
**Feature 3: Advanced Traceroute**

<img width="648" height="432" alt="image" src="https://github.com/user-attachments/assets/3291b632-0354-459a-8be8-7278c820e2e1" />

**Network Path Mapping**: Employs hping3 to conduct a traceroute, visualizing the specific route packets take to reach the target.

**Command Configuration**: Executes sudo hping3 --traceroute -V -1 -c 10 scanme.nmap.org, utilizing the --traceroute flag combined with ICMP mode (-1).

**Detailed Diagnostics**: Sends a sequence of 10 packets (-c 10) while enabling verbose output (-V) for granular data collection.

**Hop Analysis**: Enables the penetration tester to monitor the responsiveness of each individual hop along the network path.

**Infrastructure Detection**: Facilitates the identification of the network route, aiding in the discovery of intermediate devices or potential firewalls.


## DNSRecon

DNSRecon is a powerful script for active reconnaissance. It is designed to thoroughly query and explore the Domain Name System (DNS) infrastructure of a target organization. DNS acts as the main directory for the internet, and its records often disclose the internal setup of a corporate network. These records can outline the locations of mail servers, authentication points, and cloud infrastructure. Many organizations do not monitor DNS traffic for unusual patterns, giving attackers a subtle way to perform in-depth mapping.  

**Feature 1: Standard Record Enumeration and SRV Discovery**

<img width="700" height="464" alt="image" src="https://github.com/user-attachments/assets/745d167d-e1fa-47ed-ac3c-6599575a9341" />

**Infrastructure Querying**: Executes dnsrecon -d nmap.org to systematically query the domain's DNS servers for essential infrastructure details.

**IP Address Mapping**: Identifies A and AAAA records, which provide the direct mapping of the domain name to its specific IPv4 and IPv6 addresses.

**Service Provider Discovery**: Locates MX (Mail Exchange) records to identify mail servers and NS (Name Server) records to find the domain's authoritative servers.

**Security Configuration Audit**: Detects TXT records, which are often used for security protocols like the Sender Policy Framework (SPF) to prevent email spoofing.

**Digital Footprint Mapping**: Compiles gather data to map the target's external digital presence, allowing the tester to identify potential entry points or third-party service providers.

___
**Feature 2: Reverse IP Lookup**

<img width="806" height="219" alt="image" src="https://github.com/user-attachments/assets/a0c81b15-fa92-45d4-b846-c2f1982012de" />

**Infrastructure Mapping**: Uses DNSRecon to perform a Reverse IP Lookup, a critical technique for discovering the underlying infrastructure of a target.

**IP Range Scanning**: Executes the command dnsrecon -r 45.33.32.150-45.33.32.160 to scan a specific range of addresses for associated Pointer (PTR) records.

**PTR Record Identification**: Translates numerical IP addresses into human-readable domain names by identifying these PTR records.

**Asset Discovery**: Enables a penetration tester to find "neighboring" servers or hidden assets—such as scanme.nmap.org and web.discreet-logic.com—located on the same network block.

**Environment Analysis**: Identifies related records to provide a clearer view of the target’s hosting environment and discover potential lateral entry points for further testing.

___
**Feature 3: Zone Transfer (AXFR) Exploitation**

<img width="598" height="478" alt="image" src="https://github.com/user-attachments/assets/2d655646-ea74-4bd4-ac5b-580a29f83a48" />
<img width="610" height="510" alt="image" src="https://github.com/user-attachments/assets/28b0642e-a3ae-4063-9ea2-5d6edb47b154" />
<img width="714" height="580" alt="image" src="https://github.com/user-attachments/assets/04267cdb-27e4-4f37-a06b-627f46f4bdf1" />
<img width="717" height="473" alt="image" src="https://github.com/user-attachments/assets/57ddd8e5-50aa-4936-8ac9-cb24b7b2cba9" />

**Targeted AXFR Attempt**: Executes the command dnsrecon -d zonetransfer.me -t axfr to check if a domain's name servers are misconfigured to permit a full DNS database transfer.

**Vulnerability Confirmation**: Identifies a critical security flaw when the terminal displays a "Zone Transfer was successful!!" message.

**Infrastructure Mapping**: Reveals the complete internal and external DNS structure in a single request, including A records for subdomains like office, email, and vpn.

**Service and Environment Discovery**: Locates CNAME records pointing to staging environments and MX records for the domain's mail servers.

**Sensitive Metadata Exposure**: Uncovers administrative TXT records and HINFO records that reveal specific server operating systems, such as "Windows XP".

**Strategic Reconnaissance**: Allows an attacker to map out key targets and identify network weaknesses without the need for individual, time-consuming brute-force lookups.


## Task 2: Maintaining Access

Once a vulnerability is successfully exploited and access to a target system is gained, the main goal of the penetration test changes from breaking through the perimeter to maintaining access internally. Keeping access lets the security auditor maintain control over the compromised system, simulating an Advanced Persistent Threat (APT) that can survive system reboots, user logoffs, changing credentials, and regular security updates. Tools in this category must prioritize stealth, encryption, and disguising protocols to avoid egress filtering, stateful firewalls, and host-based intrusion detection systems that watch for unusual outbound network traffic.


This assignment demonstrates the use of:
• Powersploit
• Webshells
• Weevely
• Dns2tcp
• Cryptcat


## Powersploit

<img width="552" height="394" alt="image" src="https://github.com/user-attachments/assets/6cf4e00b-67ba-4f1f-94b5-a69c291ca5a2" />


This is the initial setup for using PowerSploit, a collection of Microsoft PowerShell modules used by penetration testers to maintain access and perform post-exploitation tasks on Windows systems. In this specific sequence, it is to navigate to the directory where the tool is stored and launch the PowerShell environment within Kali Linux to begin operation.

**Feature 1: Privilege Escalation (PowerUp)**

<img width="580" height="399" alt="image" src="https://github.com/user-attachments/assets/fc1f2671-42c7-4914-9d05-5900cdf107c8" />

**Security Assessment**: Uses the PowerSploit tool to systematically identify security weaknesses and potential escalation vectors within a target Windows system.

**Module Loading**: Executes Import-Module ./Privesc/PowerUp.ps1 to integrate the PowerUp module into the active PowerShell environment.

**Misconfiguration Detection**: Leverages specialized functions within the module to discover common system misconfigurations that could allow standard users to obtain higher privileges.

**Command Documentation**: Utilizes Get-Help Invoke-AllChecks to review the technical details, syntax, and usage instructions for the primary scanning function.

**Vulnerability Scanning**: Employs Invoke-AllChecks to audit the system for critical flaws, including weak service permissions, unquoted service paths, and writable registry keys.

**Access Elevation**: Targets vulnerabilities that can be exploited to secure administrator-level access, granting the tester full control over the compromised environment.

**Persistence Support**: Facilitates the "maintaining access" phase by ensuring the attacker can bypass restricted user environments to maintain long-term control.

___
**Feature 2: Persistence Mechanism**

<img width="605" height="248" alt="image" src="https://github.com/user-attachments/assets/87bddd8a-9de4-4ad7-9c97-559ff5e09bd5" />

**Long-Term Control**: Employs the Persistence feature of the PowerSploit framework to ensure sustained access to a compromised Windows environment.

**Module Integration**: Executes the command Import-Module ./Persistence/Persistence.psm1 to load specialized persistence tools into the active PowerShell session.

**Automated Execution**: Leverages functions designed to create triggers that automatically execute malicious code during system startups or user logins.

**Function Discovery**: Utilizes Get-Command -Module Persistence to list all available tools within the module, such as Add-Persistence and Install-SSP.

**Configuration Options:** Provides various methods for establishing a foothold through functions like New-ElevatedPersistenceOption and New-UserPersistenceOption.

**Operational Resilience**: Ensures that access is preserved even after system reboots or user logouts, eliminating the need to repeat the initial exploitation.

___
**Feature 3: Code Execution (Antivirus Bypass)**

<img width="578" height="489" alt="image" src="https://github.com/user-attachments/assets/472a237d-c946-469d-a0ee-32d175e3bac7" />

**Script Deployment:** Uses the command Import-Module ./CodeExecution/Invoke-Shellcode.ps1 to load a specialized script into the environment.

**Access Maintenance:** Employs shellcode injection as a primary technique to ensure sustained control over the compromised system.

**Technical Guidance:** Executes Get-Help Invoke-Shellcode -Examples to retrieve practical usage documentation for the function.

**Process Injection:** Provides the capability to inject malicious code into a specific Process ID (PID) or directly into the active PowerShell session.

**Execution Strategy:** Helps the penetration tester understand the correct parameters for successful code execution to avoid detection.


## Webshells

## Weevely

## Dns2tcp

## Cryptcat







All tools were tested in Kali Linux Virtual Machine.
Screenshots were taken during practical testing.

References are credited below.

















