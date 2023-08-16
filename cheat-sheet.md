# Advanced Threat Hunting Cheat Sheet

| Query Purpose | Query Content | Notes |
|---|---|---|
| Find endpoints communicating to a specific domain. | let Domain = "http://domainxxx.com"; DeviceNetworkEvents | where Timestamp > ago(7d) and RemoteUrl contains Domain | project Timestamp, DeviceName, RemotePort, RemoteUrl / top 100 by Timestamp desc  | “let” is the command to introduce variables. Variable name: “Domain” with value: “http://domainxxx.com" | 
| Finds PowerShell execution events that could involve a download. |union DeviceProcessEvents, DeviceNetworkEvents | where Timestamp > ago(7d) | where FileName in~ ("powershell.exe", "powershell_ise.exe") | where ProcessCommandLine has_any("WebClient", "DownloadFile", "DownloadData", "DownloadString", "WebRequest", "Shellcode", "http", "https") | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType / top 100 by Timestamp | “union” is the command to combine multiple Device Query Tables |
| Find scheduled tasks created by a non-system account  | - | - |
| Find possible clear text passwords in Windows registry | - | - |
| Lookup process executed from binary hidden in Base64 encoded file | - | - |
| Search for applications who create or update an 7Zip or WinRAR archive when a password is specified. | - | - |
| Search Device Events by IP address  | - | - |
| SList Devices with Schedule Task created by Virus   | - | - |
| List Device contained Virus File Name   | - | - |
| List Devices with Phising File extension (double extension) as .pdf.exe, .docx.exe, .doc.exe, .mp3.exe | - | - |
| List Device blocked by Windows Defender ExploitGuard | - | - |
| List All Files Create during the last hour | - | - |
| List Device who has a specific File Hash   | - | - |
| List IP address blocked by FW rule  | - | - |
| Look for public the IP addresses of devices that failed to logon multiple times, using multiple accounts, and eventually succeeded. | - | - |
| Look for machines failing to log-on to multiple machines or using multiple accounts   | - | - |
| List all devices named start with prefix FC-   | - | - |
| List Windows Defender Scan Actions completed or Cancelled   | - | - |
| List Devices access to bad URL   | - | - |
| List All URL access by a Device named contained the word FC-DC   | - | - |
