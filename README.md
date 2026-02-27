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

This assignment demonstrates the use of:
- Recon-ng
- Nmap
- Hping3
- DNSRecon


**Recon-ng**

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

**The Command**: Running workspaces create target1 sets up a fresh, isolated environment.

**Data Separation**: It creates a dedicated SQLite database specifically for "target1."

**Professionalism**: This prevents "data bleed," ensuring that IPs, emails, and hosts from one client never mix with another.

**Context**: Once created, your command prompt will change to show you are now working inside that specific workspace.

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/fcca2079-1f81-4f26-ba8b-e660dd2c6461" />

**Switching Context**: The command "workspaces select target1" activates your specific project environment.

**Visual Feedback**: Your terminal prompt changes (e.g., from [default] to [target1]), so you always know exactly which target you are currently modifying.

**Inventory Management**: Running "workspaces list" displays a table of all your projects.

**Audit Trail**: The list includes last modification dates, helping you track when you last worked on a specific investigation.

___
**Feature 2: Marketplace and Modular Architecture**

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/3ce03f9e-1cdb-446d-a5bb-ae28bcc29645" />

**The Command**: Running "marketplace install all" downloads the complete library of Recon-ng modules at once.

**Feature Access**: This unlocks the full suite of tools, including Discovery (finding sensitive files) and Exploitation (testing vulnerabilities like command injection).

**Efficiency**: Bulk installation ensures your environment is fully equipped for a deep-dive investigation without having to stop and download modules one by one.

**Preparation**: This is the standard "loadout" step to prepare Kali Linux for a comprehensive reconnaissance phase.

<img width="476" height="299" alt="image" src="https://github.com/user-attachments/assets/e6700cf3-0643-497a-87a2-ce8301f579ad" />

**Targeted Install**: The command "marketplace install recon/domains-hosts/hackertarget" downloads one specific tool instead of the entire library.

**Configuration Check**: After installation, the framework automatically audits the module to see if it’s ready to run.

**The "Red Text" Warning**: This is the API Key Check. it flags modules (like Shodan) that need external credentials to pull data.

**Critical Feedback**: These warnings prevent "silent failures," letting you know exactly which keys you need to add before the module can successfully gather intelligence.

___
**Feature 3: Automated Domain Enumeration**

<img width="476" height="299" alt="1" src="https://github.com/user-attachments/assets/db754b7b-b08a-494f-931f-c115e950d56c" />









## Task 2: Maintaining Access

This assignment demonstrates the use of:
• Powersploit
• Webshells
• Weevely
• Dns2tcp
• Cryptcat


All tools were tested in Kali Linux Virtual Machine.
Screenshots were taken during practical testing.

References are credited below.

















