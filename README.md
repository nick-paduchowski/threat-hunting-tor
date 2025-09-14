# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/nick-paduchowski/threat-hunting-tor/blob/main/setup-threat-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Searched for any file that had the string "tor" in it and discovered what looks like the user "nicklabuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `illegal-items.lnk` on the desktop at `2025-09-14T14:45:49.6096146Z`. These events began at `2025-09-14T14:24:48.8426211Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "nick-test-vm-md" and InitiatingProcessAccountName == "nicklabuser"
| where FileName contains "tor"
| project TimeGenerated, ActionType, DeviceName, FileName, Account = InitiatingProcessAccountName
| sort by TimeGenerated desc
```
<img width="1212" alt="image" src="https://github.com/nick-paduchowski/threat-hunting-tor/blob/fa261ec0e8bc39f2d4c1aefd6a9135a819bb5efe/tor-threat-hunting-pic1.png">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser". Based on the logs returned, at `2025-09-14T14:24:48.8426211Z`, a user on the "nick-test-vm-md" device ran the file `tor-browser-windows-x86_64-portable-14.5.6.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "nick-test-vm-md"
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine contains "tor-browser"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| sort by TimeGenerated desc

```
<img width="1212" alt="image" src="https://github.com/nick-paduchowski/threat-hunting-tor/blob/05a19cd5c27da6856715fb42d3c9e00da5ca984d/tor-threat-hunting-pic2.png">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "nicklabuser" actually opened the TOR browser. There was evidence that they did open it at `2025-09-14T14:27:18.1670479Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "nick-test-vm-md"
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine has_any ("tor", "firefox")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| sort by TimeGenerated desc 
```
<img width="1212" alt="image" src="https://github.com/nick-paduchowski/threat-hunting-tor/blob/06b71f714ee6f2f852f342d9bde6d33281e54ec3/tor-threat-hunting-pic3.png">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-09-14T14:27:22.2530453Z`, a user on the "nick-test-vm-md" device successfully established a connection to the remote IP address `185.124.240.98` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\nicklabuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "nick-test-vm-md"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9150")
| project TimeGenerated, ActionType, DeviceName, Account = InitiatingProcessAccountName, FileName = InitiatingProcessFileName, RemoteIP, RemotePort
| sort by TimeGenerated desc
```
<img width="1212" alt="image" src="https://github.com/nick-paduchowski/threat-hunting-tor/blob/d7941a2df8dd049fc976a91258b5913fb8752aa6/tor-threat-hunting-pic4.png">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-14T14:24:48.8426211Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\nicklabuser\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-14T14:26:52.3895701Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.6.exe /S`
- **File Path:** `C:\Users\nicklabuser\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-14T14:27:18.1670479Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\nicklabuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-09-14T14:27:22.2530453Z`
- **Event:** A network connection to IP `185.124.240.98` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\nicklabuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-09-14T14:33:21.8766843Z` - Connected to `64.65.63.10` on port `443`.
  - `2025-09-14T14:33:42.3586392Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-09-14T14:45:49.6096146Z`
- **Event:** The user "employee" created a file named `illegal-items.lnk` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\nicklabuser\AppData\Roaming\Microsoft\Windows\Recent\illegal-items.lnk`

---

## Summary

The user "nicklabuser" on the "nick-test-vm-md" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `illegal-items.lnk`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "illegal items" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `nick-test-vm-md` by the user `nicklabuser`. The device was isolated, and the user's direct manager was notified.

---
