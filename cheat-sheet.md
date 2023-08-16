# Advanced Threat Hunting Cheat Sheet

| Query Purpose | Query Content | Notes |
|---|---|---|
| Find endpoints communicating to a specific domain. | let Domain = "http://domainxxx.com"; DeviceNetworkEvents | where Timestamp > ago(7d) and RemoteUrl contains Domain | project Timestamp, DeviceName, RemotePort, RemoteUrl / top 100 by Timestamp desc  | “let” is the command to introduce variables. Variable name: “Domain” with value: “http://domainxxx.com" | 
| Finds PowerShell execution events that could involve a download. |union DeviceProcessEvents, DeviceNetworkEvents | where Timestamp > ago(7d) | where FileName in~ ("powershell.exe", "powershell_ise.exe") | where ProcessCommandLine has_any("WebClient", "DownloadFile", "DownloadData", "DownloadString", "WebRequest", "Shellcode", "http", "https") | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType / top 100 by Timestamp | “union” is the command to combine multiple Device Query Tables |
| Find scheduled tasks created by a non-system account  | - | - |
| Find possible clear text passwords in Windows registry | - | - |
| Lookup process executed from binary hidden in Base64 encoded file | - | - |
| Search for applications who create or update an 7Zip or WinRAR archive when a password is specified.   | - | - |
| Search Device Events by IP address  | - | - |
