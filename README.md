"This project is for educational purposes only. All testing was performed in a
controlled environment or on authorized targets."

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

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/3b7676c6-fe1e-4699-88c7-f5e1516c702a" />

**Host Verification**: Performs a Ping Scan to confirm if a target host is active and reachable on the network.

**Scan Optimization**: Utilizes the -sn flag to disable port scanning, focusing the tool's resources exclusively on host discovery.

**Operational Efficiency**: Provides quick confirmation of host status and latency (e.g., 45.33.32.156 is "up" with 0.27s latency) without generating the heavy traffic associated with full service scans.

**Footprint Analysis**: Identifies the target's IPv6 address, offering a more comprehensive view of the host's network presence.

**Stealth & Planning**: Serves as a light reconnaissance technique to check availability while maintaining a low profile before deploying more intensive scanning methods.

___
**Feature 2: Service and Detection**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/b1598c41-c8bd-4664-b624-8be6d5654b97" />

**Service Identification**: Executes nmap -sV scanme.nmap.org to probe open ports and accurately determine active services and their specific version numbers.

**Detailed Scanning**: Successfully identifies critical open ports, such as Port 22 running OpenSSH 6.6.1p1 and Port 80 running Apache httpd 2.4.7.

**Environment Analysis**: Provides a deeper understanding of the target's software environment, moving beyond simple port status to granular application data.

**Vulnerability Mapping**: Enables the tester to research known exploits and vulnerabilities specific to the identified software builds, such as specific versions of SSH or Apache.

**OS Confirmation**: Includes a "Service Info" section that identifies the operating system (e.g., Linux), effectively narrowing the attack surface for strategic planning.

___
**Feature 3: OS Detection**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/653ea109-95cd-41d2-96ba-920c4d4d1937" />


**OS Fingerprinting**: Executes sudo nmap -O -T4 -F scanme.nmap.org using the -O flag to perform remote operating system detection.

**Timing Optimization**: Incorporates the -T4 flag to accelerate the scanning process for faster results.

**Virtualized Environment Identification**: Analyzes network stack responses to provide an "Aggressive OS guess," identifying potential virtualized environments such as QEMU or Oracle VirtualBox.

**Port Status Analysis**: Displays the status of common ports, confirming that Port 22 (SSH) and Port 80 (HTTP) are open, while Port 53 (DNS) and Port 143 (IMAP) are closed.

**Strategic Strategy Shaping**: Provides essential environmental data that allows a penetration tester to tailor exploitation strategies toward the vulnerabilities of the specific identified OS.

___
## Hping3

Hping3 is a powerful command-line network tool and packet assembler. It gives security auditors detailed, byte-level control over creating TCP, UDP, ICMP, and RAW-IP packets. Unlike regular system ping tools that can only send basic ICMP Echo Requests, Hping3 allows for thorough network auditing, stateful firewall testing, Path MTU discovery, and manual protocol manipulation. It is commonly used to break through complex perimeter defenses that silently block standard scanning traffic.

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/dea24eae-bdc2-4c64-90ae-5ba8b06af913" />

___
**Feature 1:  ICMP Ping (Testing Basic Connectivity)**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/af18bc29-cb3e-4ee0-b7ad-bf06a0a4d7ea" />

**Initial Discovery**: Uses hping3 to gather preliminary data on a target by testing for basic network connectivity.

**Packet Mode Selection**: Employs the -1 flag to enter ICMP mode, allowing the tool to perform a traditional ping function.

**Traffic Control**: Utilizes the -c 4 flag to limit the transmission to exactly four packets, keeping the probe concise.

**Status Confirmation**: Verifies that the target host is active by analyzing the Round Trip Time (rtt) and Time to Live (ttl) values returned in the terminal.

**Network Mapping**: Provides data that helps a penetration tester understand the responsiveness of the network and the likely path packets take to reach the destination.

___
**Feature 2: SYN Port Scanning**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/fcab5759-4d36-4326-8018-505ca7e73206" />

**Targeted Packet Crafting**: Executes sudo hping3 -S -p 80 -c 1 scanme.nmap.org to send a single TCP SYN packet (-S) specifically to port 80 (-p 80).

**Response Analysis**: Receives a response containing the flags=SA (SYN-ACK) header, which serves as technical confirmation that the port is open.

**Connection Readiness**: Validates that the targeted service is active and ready to accept incoming network connections.

**Stealthy Identification**: Provides a method for identifying open ports that is less conspicuous than establishing a full TCP three-way handshake.

___
**Feature 3: Advanced Traceroute**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/3291b632-0354-459a-8be8-7278c820e2e1" />

**Network Path Mapping**: Employs hping3 to conduct a traceroute, visualizing the specific route packets take to reach the target.

**Command Configuration**: Executes sudo hping3 --traceroute -V -1 -c 10 scanme.nmap.org, utilizing the --traceroute flag combined with ICMP mode (-1).

**Detailed Diagnostics**: Sends a sequence of 10 packets (-c 10) while enabling verbose output (-V) for granular data collection.

**Hop Analysis**: Enables the penetration tester to monitor the responsiveness of each individual hop along the network path.

**Infrastructure Detection**: Facilitates the identification of the network route, aiding in the discovery of intermediate devices or potential firewalls.


## DNSRecon

DNSRecon is a powerful script for active reconnaissance. It is designed to thoroughly query and explore the Domain Name System (DNS) infrastructure of a target organization. DNS acts as the main directory for the internet, and its records often disclose the internal setup of a corporate network. These records can outline the locations of mail servers, authentication points, and cloud infrastructure. Many organizations do not monitor DNS traffic for unusual patterns, giving attackers a subtle way to perform in-depth mapping.  

**Feature 1: Standard Record Enumeration and SRV Discovery**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/745d167d-e1fa-47ed-ac3c-6599575a9341" />

**Infrastructure Querying**: Executes dnsrecon -d nmap.org to systematically query the domain's DNS servers for essential infrastructure details.

**IP Address Mapping**: Identifies A and AAAA records, which provide the direct mapping of the domain name to its specific IPv4 and IPv6 addresses.

**Service Provider Discovery**: Locates MX (Mail Exchange) records to identify mail servers and NS (Name Server) records to find the domain's authoritative servers.

**Security Configuration Audit**: Detects TXT records, which are often used for security protocols like the Sender Policy Framework (SPF) to prevent email spoofing.

**Digital Footprint Mapping**: Compiles gather data to map the target's external digital presence, allowing the tester to identify potential entry points or third-party service providers.

___
**Feature 2: Reverse IP Lookup**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/a0c81b15-fa92-45d4-b846-c2f1982012de" />

**Infrastructure Mapping**: Uses DNSRecon to perform a Reverse IP Lookup, a critical technique for discovering the underlying infrastructure of a target.

**IP Range Scanning**: Executes the command dnsrecon -r 45.33.32.150-45.33.32.160 to scan a specific range of addresses for associated Pointer (PTR) records.

**PTR Record Identification**: Translates numerical IP addresses into human-readable domain names by identifying these PTR records.

**Asset Discovery**: Enables a penetration tester to find "neighboring" servers or hidden assets—such as scanme.nmap.org and web.discreet-logic.com—located on the same network block.

**Environment Analysis**: Identifies related records to provide a clearer view of the target’s hosting environment and discover potential lateral entry points for further testing.

___
**Feature 3: Zone Transfer (AXFR) Exploitation**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/2d655646-ea74-4bd4-ac5b-580a29f83a48" />
<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/28b0642e-a3ae-4063-9ea2-5d6edb47b154" />
<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/04267cdb-27e4-4f37-a06b-627f46f4bdf1" />
<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/57ddd8e5-50aa-4936-8ac9-cb24b7b2cba9" />

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

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/6cf4e00b-67ba-4f1f-94b5-a69c291ca5a2" />


This is the initial setup for using PowerSploit, a collection of Microsoft PowerShell modules used by penetration testers to maintain access and perform post-exploitation tasks on Windows systems. In this specific sequence, it is to navigate to the directory where the tool is stored and launch the PowerShell environment within Kali Linux to begin operation.

**Feature 1: Privilege Escalation (PowerUp)**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/fc1f2671-42c7-4914-9d05-5900cdf107c8" />

**Security Assessment**: Uses the PowerSploit tool to systematically identify security weaknesses and potential escalation vectors within a target Windows system.

**Module Loading**: Executes Import-Module ./Privesc/PowerUp.ps1 to integrate the PowerUp module into the active PowerShell environment.

**Misconfiguration Detection**: Leverages specialized functions within the module to discover common system misconfigurations that could allow standard users to obtain higher privileges.

**Command Documentation**: Utilizes Get-Help Invoke-AllChecks to review the technical details, syntax, and usage instructions for the primary scanning function.

**Vulnerability Scanning**: Employs Invoke-AllChecks to audit the system for critical flaws, including weak service permissions, unquoted service paths, and writable registry keys.

**Access Elevation**: Targets vulnerabilities that can be exploited to secure administrator-level access, granting the tester full control over the compromised environment.

**Persistence Support**: Facilitates the "maintaining access" phase by ensuring the attacker can bypass restricted user environments to maintain long-term control.

___
**Feature 2: Persistence Mechanism**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/87bddd8a-9de4-4ad7-9c97-559ff5e09bd5" />

**Long-Term Control**: Employs the Persistence feature of the PowerSploit framework to ensure sustained access to a compromised Windows environment.

**Module Integration**: Executes the command Import-Module ./Persistence/Persistence.psm1 to load specialized persistence tools into the active PowerShell session.

**Automated Execution**: Leverages functions designed to create triggers that automatically execute malicious code during system startups or user logins.

**Function Discovery**: Utilizes Get-Command -Module Persistence to list all available tools within the module, such as Add-Persistence and Install-SSP.

**Configuration Options:** Provides various methods for establishing a foothold through functions like New-ElevatedPersistenceOption and New-UserPersistenceOption.

**Operational Resilience**: Ensures that access is preserved even after system reboots or user logouts, eliminating the need to repeat the initial exploitation.

___
**Feature 3: Code Execution (Antivirus Bypass)**

<img width="500" height="299" alt="image" src="https://github.com/user-attachments/assets/472a237d-c946-469d-a0ee-32d175e3bac7" />

**Script Deployment:** Uses the command Import-Module ./CodeExecution/Invoke-Shellcode.ps1 to load a specialized script into the environment.

**Access Maintenance:** Employs shellcode injection as a primary technique to ensure sustained control over the compromised system.

**Technical Guidance:** Executes Get-Help Invoke-Shellcode -Examples to retrieve practical usage documentation for the function.

**Process Injection:** Provides the capability to inject malicious code into a specific Process ID (PID) or directly into the active PowerShell session.

**Execution Strategy:** Helps the penetration tester understand the correct parameters for successful code execution to avoid detection.


## Webshells

A web shell is a malicious script and it is usually written in web programming languages like PHP, ASP, or JSP. It is also uploaded to a web server to allow an attacker remote administration and command execution over the internet. Web shells are a cornerstone of post-exploitation, used to establish a persistent backdoor on a compromised system without needing to re-exploit the initial vulnerability.

**Feature 1: Remote Command Execution (RCE)**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/13062e14-278a-45ff-bb34-c69aadeda22f" />

**Webshell Deployment**: Executes sudo cp /usr/share/webshells/php/simple-backdoor.php /var/www/html/shell.php to copy a pre-installed PHP script into the web server's root directory.

**Service Activation**: Uses the sudo systemctl start apache2 command to launch the Apache web server, making the shell accessible through a browser.

**Remote Interaction**: Navigates to the webshell's URL and appends the ?cmd=id parameter to pass system commands directly to the server.

**Context Verification**: Confirms the shell is functional when the browser displays server output, such as uid=33(www-data), showing the current user context.

**System Contro**l: Enables the attacker to remotely execute system commands, manage the file system, or dump databases from the compromised host.
___
**Feature 2: Stealthy Reverse Shell Connectivity**

<img width="500" height="299" alt="image" src="https://github.com/user-attachments/assets/c819cea6-dd90-4cf7-9a24-f6f39aecc2e7" />

**Payload Review**: Uses the command cat /usr/share/webshells/php/php-reverse-shell.php to inspect and configure the pre-installed reverse shell script.

**Firewall Evasion**: Employs a reverse shell strategy to maintain access even when the target system is protected by a restrictive inbound firewall.

**Outbound Connection**: Configures the webshell to initiate a connection from the target back to the Kali Linux machine.

**Security Bypass**: Successfully circumvents security rules that block incoming connections by utilizing a trusted outbound traffic path.

**Persistent Control**: Ensures the penetration tester can "continue dominating the target system" effectively, regardless of external network changes.
___
**Feature 3: File System Navigation & Data Exfiltration**

<img width="500" height="299" alt="image" src="https://github.com/user-attachments/assets/847719ff-a817-4771-883f-33096975de77" />

**Directory Access**: Executes http://127.0.0.1/shell.php?cmd=ls%20-l%20/etc/ to gain access to the /etc/ directory and list its contents.

**Sensitive Data Discovery:** Utilizes directory listing commands to locate critical information such as configuration files, passwords, or databases.

**System-Wide Navigation**: Enables the tester to navigate the entire file system to identify high-value targets for further exploitation.

**Stealthy Execution**: Blends malicious activity with standard web server file-reading processes, allowing the tester to remain hidden from basic monitoring tools.

**Destructive Potential**: Moves beyond simple access to "cause more destruction" by identifying and preparing sensitive data for exfiltration


## Weevely

Weevely is a sophisticated PHP web shell designed for post-exploitation tasks on compromised web application servers. Unlike basic, first-generation web shells, which simply execute system commands through easily tracked HTTP GET parameters that are logged by web servers and flagged by security tools, Weevely sets up a stealthy command and control (C2) channel that looks like normal web browsing traffic.

**Feature 1:  Payload Generation**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/702a10cb-bb0f-44e8-b55f-081daaf5e760" />

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/a7c46fc2-823d-428f-b02a-44b6379736c8" />

**Hidden Entry Point Creation**: Establishes a primary entry point for maintaining long-term access to a system.

**Stealthy Payload Construction:** Executes the command weevely generate mypassword backdoor.php to build a specialized, obfuscated PHP web shell.

**Access Security**: Incorporates a secure key ("mypassword") into the generation process to ensure only the authorized penetration tester can access the backdoor.

**Persistent Control**: Facilitates continued system dominance by uploading the file to a compromised server, eliminating the need for repeated exploitations.

**Victim Server Simulation**: Demonstrates functionality by launching a local server via php -S localhost:8080, representing a compromised host environment.

**Active Communication**: Displays a stream of POST requests in the terminal, confirming the backdoor is active, listening, and communicating with the attacker's machine.

___
**Feature 2: Remote Terminal / Session Management**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/9deb0260-6d01-4210-9013-df2534a0ef30" />

**Target Connection Establishment:** Initiates the connection once the backdoor is successfully hosted on the target server.

**Command Execution**: Runs the command weevely http://localhost:8080/backdoor.php mypassword to direct the tool to the specific URL containing the malicious file.

**Web Shell Authentication**: Unlocks the web shell interface by providing the correct pre-configured password.

**Access Maintenance:** Facilitates a hidden and persistent entry point, which is essential for maintaining control over the compromised machine.

___
**Feature 3: System Enumeration / Information Gathering**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/d2414e2c-62e2-466d-8fbe-2d16a1d27025" />

**Direct Command Access**: Establishes a command prompt link directly to the target system once the connection is secured.

**Automated Data Collection**: Executes the system_info command within the Weevely interface to gather critical environmental data.

**Environment Profiling**: Quietly retrieves details such as current user privileges, the operating system version, and specific file directory paths.

**Strategic Navigation**: Utilizes the collected information to help the tester navigate the file system and plan subsequent post-exploitation actions.

**Stealthy Maintenance**: Enables continued control over the target while minimizing the risk of detection by security monitors.



## Dns2tcp

Dns2tcp is a specialized network tunneling suite that encapsulates Transmission Control Protocol (TCP) communications within standard Domain Name System (DNS) requests and responses. It has two main parts: a server daemon (dns2tcpd) that operates on an external machine controlled by the attacker, and a client utility (dns2tcpc) that runs on the compromised internal host. This tool is designed specifically to bypass strict network compartmentalization.

**Feature 1: Resource Mapping Configuration**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/79865641-56d2-4f54-9988-86357d4163ff" />

**Traffic Routing Strategy**: Identifies the necessary paths to route hidden traffic as a prerequisite for maintaining covert access.

**Configuration Creation:** Employs the echo command to generate a dns2tcpd.conf file, which serves as the blueprint for mapping local services to the tunnel.

**Service Redirection:** Configures the tunnel to direct incoming traffic directly to the target machine's SSH service.

**Tunnel Preparation**: Prepares the compromised host to properly receive and handle disguised communications once the secret tunnel becomes operational.

**System Control Maintenance:** Establishes a technical setup that allows the penetration tester to maintain sustained control over the target system.

___
**Feature 2: FDNS Tunneling Server Daemon**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/9edffe2b-97ff-42b5-a990-d1b6eee3e7a2" />

**Service Activation:** Launches a dedicated server daemon on the compromised target system once routing rules are finalized.

**Background Monitoring:** Executes the dns2tcpd command to place the host in a listening state, quietly waiting for DNS queries that match the pre-defined domain.

**Payload Decapsulation:** Ensures the system is technically prepared to identify and unpack hidden TCP traffic embedded within DNS packets.

**Stealthy Persistence:** Enables the penetration tester to maintain persistent operations without triggering standard firewall alerts.

___
**Feature 3: Client Port Forwarding**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/dad547f8-8bb8-46fa-b0f5-25d7997c7413" />

**Hidden Connection Establishment**: Creates the final connection from the attacker’s machine to the target to secure long-term access.

**Traffic Encapsulation**: Uses the dns2tcpc command to wrap the penetration tester’s communication into packets that appear as regular, harmless DNS requests.

**Service Linking**: Routes traffic by linking the remote SSH service on the target system to a local port, such as 8888, on the attacker’s machine.

**System Connectivity**: Establishes a crucial, functional link between the two systems.

**Security Control Evasion**: Bypasses security restrictions to maintain control of the target system for as long as possible.


## Cryptcat

Cryptcat is a security-focused upgrade of the well-known Netcat utility. This tool is widely recognized in cybersecurity as the "TCP/IP Swiss Army Knife." While the standard Netcat binary is unmatched for reading and writing raw data over network connections, it has a major flaw in modern offensive operations. It sends all data in unencrypted plaintext. This leaves the operator vulnerable to packet sniffing, man-in-the-middle (MitM) attacks, and network forensics by defense teams. Cryptcat addresses this vital issue by integrating strong transport-layer encryption directly into the socket connections. 

**Feature 1:Encrypted Backdoor (Listener)**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/a4291f47-e619-46c3-994b-ec3c3a0f8dfe" />

**Command Execution:** Run the command cryptcat -l -p 4444 -k mysecretkey to establish a secure communication channel.

**Listen Mode Activation**: Utilizes the -l flag to place the target machine into "listen" mode, waiting for incoming connections on port 4444.

**Pre-shared Key Security**: Employs the -k flag to secure the connection with a specific secret key, ensuring that all transmitted data is encrypted.

**Persistent Entry Point:** Creates a critical foothold for maintaining access to the system.

**Access Control**: Restricts the backdoor to only the attacker, effectively locking out system administrators or other unauthorized third parties. 

___
**Feature 2:Secure Remote Shell (Persistence)**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/e0bc522e-8814-4d0b-912b-2c9893aef1ac" />

**Remote Connectivity:** Executes the command cryptcat 127.0.0.1 4444 -k mysecretkey to connect to a previously established listener.

**Command Execution**: Enables the attacker to remotely execute system commands on the target machine.

**Twofish Encryption:** Utilizes the Twofish encryption algorithm to secure all traffic between the attacker and the target.

**Total Traffic Protection**: Ensures that both sent shell commands and received system responses are fully encrypted.

**Evasion of Detection**: Hides offensive activity from Network Intrusion Detection Systems (NIDS) by preventing the detection of plain-text shell traffic.

**Subtle Operations:** Meets the "under-the-ground operations" requirement by maintaining a stealthy presence within the network

___
**Feature 3:  Encrypted Data Exfiltration**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/003e1d5e-4571-4412-840f-aa948a7dcbc7" />

**Command Execution:** Runs the command cryptcat -l -p 5555 -k mysecretkey > stolen_data.txt to prepare for secure data reception.

**Data Capture Mechanism:** Employs a redirection operator (>) to intercept any incoming encrypted data stream and save it directly into a designated local file.

**Destructive Objective: **Supports the goal to "cause more destruction" by facilitating the stealthy removal of sensitive information from the target network.

**Intercept Protection:** Utilizes encryption to ensure that even if the data transfer is monitored or intercepted, the file contents remain unreadable to unauthorized parties.

**Secret Key Security:** Protects the actual contents of the stolen files using a pre-shared secret key, maintaining confidentiality throughout the exfiltration process.


## Methodological Synthesis and Comparative Analysis

A thorough assessment of cybersecurity tools necessitates looking at their detectability profiles, ideal use cases, and structural paradigms. A crucial prerequisite for turning technical data into strategic intelligence is the ability to draw conclusions from comparative analysis. The comparative benefits, OSI model interactions, and operational constraints of the toolsets discussed in both the Reconnaissance and Maintaining Access phases are summarised in the following tables.

## Reconnaissance Tools Analysis and Comparison

<img width="350" height="500" alt="task1table" src="https://github.com/user-attachments/assets/47885145-0195-4493-a6b5-75f32edbc206" />

The use of these reconnaissance tools shows a shift from passive intelligence gathering to active network engagement. Recon-ng leads the early reconnaissance phase by creating a preliminary threat profile through the global OSINT ecosystem without directly contacting the target. After identifying external IP ranges and domains, DNSRecon converts these domains into usable IP addresses while revealing the underlying routing infrastructure. Nmap then serves as a detailed diagnostic tool, checking the identified hosts to classify running services and operating systems. Finally, when strong perimeter defenses block standard scans, Hping3 offers the precise packet manipulation needed to bypass filtering rules and effectively map internal state tables.


## Maintaining Access Tools Analysis

<img width="350" height="500" alt="task2table" src="https://github.com/user-attachments/assets/3ab3c6b8-79b9-4d55-ad68-38f7aa5a520b" />

Selecting the right persistence mechanism depends a lot on understanding the compromised environment's egress filtering and endpoint security. Weevely works best in situations where external web traffic is trusted. It effectively hides harmful commands in the large amount of standard HTTP traffic. On the other hand, if a network tightly controls outbound web traffic but allows DNS resolution, Dns2tcp takes advantage of this by turning the DNS protocol into a secret, two-way transport layer. Cryptcat offers complete point-to-point transport security. It needs open ports to work, and it is less able to deal with strict egress filtering compared to Dns2tcp. However, its use of Twofish encryption makes sure that extracted data is completely hidden from network monitoring and analysis.

## Conclusions

A successful penetration test requires a strong understanding of network protocols to simulate Advanced Persistent Threats (APTs) effectively. The Reconnaissance phase shapes the entire engagement. Tools like Recon-ng and DNSRecon collect open-source intelligence and map hidden infrastructure. Active scanners like Nmap and Hping3 find specific service vulnerabilities and bypass strict perimeter controls. Together, these tools provide the crucial information needed to identify key weaknesses.
Once perimeter defenses are breached, the focus shifts to Maintaining Access. Persistence tools such as Weevely, Dns2tcp, and Cryptcat evade detection by exploiting the built-in trust of networks. They do this by hiding harmful payloads within regular web traffic, tunneling through DNS queries, or encrypting data streams. In the end, mastering both information gathering and stealthy persistence gives the practical knowledge needed to strengthen organizational defenses and improve resilience against modern cyberattacks.


## Reference

Alex-sector. (2017). Dns2tcp: A tool for relaying TCP connections over DNS (Version 0.5.2) [Computer software]. GitHub. https://github.com/alex-sector/dns2tcp

CyberLabs007. (n.d.). Hping3: Firewall testing and traceroute mode [Video]. YouTube. https://www.youtube.com/watch?v=B4FwRo4a6Qg

Farm9. (2000). Cryptcat [Computer software]. SourceForge. https://cryptcat.sourceforge.io/

HackerTarget. (n.d.). Recon-ng tutorial. https://hackertarget.com/recon-ng-tutorial/

HackerSploit. (2019). Recon-ng - Commands, workspaces and data management [Video]. YouTube. https://www.youtube.com/watch?v=oSt6WdTaCV4

Infoblox. (n.d.). Analysis on popular DNS tunneling tools. Infoblox Community. https://www.infoblox.com/blog/community/analysis-on-popular-dns-tunneling-tools/

InfoSec Pat. (2025). How hackers chat in private (SECURELY!) | Cryptcat [Video]. YouTube. https://www.youtube.com/watch?v=fNc3W_bEpok

Lyon, G. F. (2009). Nmap network scanning: The official Nmap project guide to network discovery and security scanning. Nmap Project.

Perez, C. (n.d.). DNSRecon [Computer software]. GitHub. https://github.com/darkoperator/dnsrecon

Pinna, E. (n.d.). Weevely3 [Computer software]. GitHub. https://github.com/epinna/weevely3

Sanfilippo, S. (n.d.). Hping3 [Computer software]. FreeBSD Manual Pages. https://man.freebsd.org/cgi/man.cgi?query=hping3&sektion=8&format=html

Tomes, T. (n.d.). Recon-ng [Computer software]. GitHub. https://github.com/lanmaster53/recon-ng

Kali Linux. (n.d.). Kali Linux tools directory. Offensive Security. https://www.kali.org/tools/

Nmap.org. (n.d.). Nmap reference guide. Nmap Security Scanner. https://nmap.org/book/man.html

Tutonics. (n.d.). Encrypted data transfer using Cryptcat. https://tutonics.com/articles/encrypted-data-transfer-using-cryptcat/

U.S. Department of Defense. (2021). DoD cyber table top guide (v2). Chief Information Officer. https://www.cto.mil/wp-content/uploads/2023/06/DoD-Cyber-Table-Top-Guide-v2-2021.pdf



All tools were tested in Kali Linux Virtual Machine.
Screenshots were taken during practical testing.
















