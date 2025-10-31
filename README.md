# threat-hunting-scenario-tor
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/dmarrero98/threat-hunting-scenario-tor/blob/e6017c4bf0a7d9714342dadc5e9d55cc1635a344/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "dillan" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop. These events began at `Oct 30, 2025 4:05:51 PM`. The user also deleted tor related files at `Oct 30, 2025 4:28:11 PM` roughly 30 minutes after the initial installation.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "bossv2-win11"
| where FileName contains "tor"
```
<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunting-scenario-tor/blob/main/screenshots/tor2.png">

---

### 2. Pivoting to the `DeviceProcessEvents` Table

Searched the `ProcessCommandLine` to see what processes were created within 15 minutes of the initial install. Based on the query results, it appears the user initiated a silent install of the tor browser from the downloads folder at Oct 30, 2025 4:05:28 PM.

**Query used to locate event:**

```kql
let baseTime = datetime("2025-10-30T20:05:51.439259Z");
DeviceProcessEvents
| where Timestamp between ((baseTime - 15m) .. (baseTime + 15m))
| where DeviceName == "bossv2-win11"
| order by Timestamp desc
| project Timestamp, ActionType, FileName, Account = InitiatingProcessAccountName, FolderPath
```
<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunting-scenario-tor/blob/main/screenshots/tor3.png">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `Oct 30, 2025 4:06:22 PM`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
DeviceProcessEvents
| where DeviceName == "bossv2-win11"
| where FileName has_any ("tor.exe", "firefox.exe", "torbrowser.exe", "tbb-launcher.exe", "start-tor-browser.exe", "tor-gui.exe", "torservice.exe")
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunting-scenario-tor/blob/main/screenshots/tor4.png">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I then proceeded to check for any attempts to connect to known TOR ports over the internet in the DeviceNetworkEvents table. On October 30, 2025, at 4:08 PM, the Windows 11 workstation “bossv2-win11” successfully established a TCP connection to 178.194.102.194 (port 9001) originating from local IP 10.1.0.134. The connection was initiated by tor.exe, located in the user’s Tor Browser directory, launched at 4:06 PM by firefox.exe. The process ran under the dillan user account. Command-line details show standard Tor Browser configuration and GeoIP files, indicating that the Tor Browser was actively used to connect to the Tor network, likely for anonymized web access.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "bossv2-win11"
| where InitiatingProcessFileName has_any ("tor.exe", "firefox.exe", "torbrowser.exe", "tbb-launcher.exe", "start-tor-browser.exe", "tor-gui.exe", "torservice.exe")
| where RemotePort in ("9001","9030","9050","9150", "443", "80")
| sort by Timestamp desc
| project Timestamp, ActionType, RemoteIP, RemotePort, LocalIP, InitiatingProcessFileName

```
<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunting-scenario-tor/blob/main/screenshots/tor1.png">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `Oct 30, 2025 4:05:28 PM`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\dillan\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `Oct 30, 2025 4:05:51 PM`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\dillan\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `Oct 30, 2025 4:06:22 PM`
- **Event:** User "dillan" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\dillan\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-10-30T20:07:29.8664511Z`
- **Event:** A network connection to IP `178.194.102.194` on port `9001` by user "dillan" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\dillan\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `Oct 30, 2025 4:08:29 PM` - Connected to `89.58.34.53` on port `9001`.
  - `Oct 30, 2025 4:08:32 PM` - Local connection to `64.65.1.147` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `Oct 30, 2025 4:20:37 PM`
- **Event:** The user "employee" created a file named `grocery-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\dillan\Desktop\grocery-list.txt`

---

## Summary

The user "dillan" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `grocery-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "grocery shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `dillan`. The device was isolated, and the user's direct manager was notified.

---
