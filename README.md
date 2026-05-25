# Azure Honeypot SIEM Lab

## Overview

This project demonstrates the deployment of a vulnerable Windows honeypot in Microsoft Azure and the integration of centralized logging, SIEM monitoring, log enrichment, and geolocation attack visualization using Microsoft Sentinel.

The purpose of this lab was to gain hands-on experience with:
- Cloud infrastructure deployment
- Security monitoring
- SIEM operations
- KQL querying
- Threat detection
- Log analysis
- Attack visualization

The environment simulates a real-world SOC (Security Operations Center) workflow by collecting failed authentication attempts from the internet and visualizing attacker locations on a live attack map.

---

# Lab Architecture

## Components
- Azure Virtual Machine (Windows 10 Honeypot)
- Network Security Group (NSG)
- Azure Log Analytics Workspace (LAW)
- Microsoft Sentinel SIEM
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Sentinel Watchlists
- Attack Map Workbook

---

# Objectives

- Deploy a vulnerable Windows VM honeypot
- Capture failed login attempts from the internet
- Forward Windows Event Logs into Log Analytics
- Query logs using Kusto Query Language (KQL)
- Enrich attacker IP addresses with geographic data
- Visualize attack traffic on a live world map

---

# Technologies Used

| Technology | Purpose |
|---|---|
| Microsoft Azure | Cloud Platform |
| Windows 10 VM | Honeypot System |
| Network Security Groups | Traffic Control |
| Log Analytics Workspace | Centralized Logging |
| Microsoft Sentinel | SIEM & Threat Detection |
| Azure Monitor Agent | Log Forwarding |
| Kusto Query Language (KQL) | Log Querying |
| Sentinel Watchlists | GeoIP Enrichment |
| Sentinel Workbook | Attack Visualization |

---

# Part 1 — Azure Environment Setup

## Azure Subscription
Created a Microsoft Azure subscription and configured access to the Azure Portal.

### Azure Portal
https://portal.azure.com

---

# Part 2 — Honeypot Deployment

## Virtual Machine Configuration
Deployed a Windows 10 Virtual Machine in Azure configured as an internet-facing honeypot.

### VM Configuration
- Windows 10
- Public IP Address
- Open inbound NSG rule allowing all traffic
- Windows Firewall disabled

## Purpose
The VM was intentionally exposed to attract malicious authentication attempts from internet threat actors.

---

# Part 3 — Security Log Investigation

## Event Viewer Analysis
Generated failed login attempts using invalid credentials and inspected Windows Security Logs.

### Observed Event
- Event ID: 4625
- Description: Failed Login Attempt

## Example Findings
- Failed authentication attempts
- Invalid usernames
- Source IP addresses
- Login timestamps

---

# Part 4 — Centralized Logging & SIEM Integration

## Log Analytics Workspace
Created a centralized logging repository using Azure Log Analytics Workspace (LAW).

## Microsoft Sentinel
Configured Microsoft Sentinel and connected it to the Log Analytics Workspace.

## Log Collection
Configured:
- Windows Security Events via AMA Connector
- Data Collection Rules (DCR)

## Log Querying with KQL

Example query used to identify failed login attempts:

```kql
SecurityEvent
| where EventID == 4625
```

## Skills Demonstrated
- SIEM configuration
- Security event ingestion
- Log querying
- Security monitoring
- Threat investigation

---

# Part 5 — Log Enrichment & Geolocation

## GeoIP Watchlist Integration

Imported a GeoIP watchlist into Sentinel to enrich attacker IP addresses with:
- Country
- State
- City
- Latitude/Longitude

## Watchlist Configuration
- Alias: geoip
- Source Type: Local File
- Search Key: network

## GeoIP Enrichment Query

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

## Outcome
Successfully identified geographic origin locations of failed authentication attempts.

---

# Part 6 — Attack Map Visualization

## Sentinel Workbook
Created a custom Microsoft Sentinel Workbook to visualize attack traffic.

## Features
- Global attack map
- Attacker geolocation tracking
- Failed login visualization
- Real-time event analysis

## Visualization Benefits
- Improved threat visibility
- Faster threat investigation
- Geographic attack intelligence

---

# Security Concepts Demonstrated

- SIEM Operations
- Threat Detection
- Centralized Logging
- Log Correlation
- Network Exposure Risks
- Security Monitoring
- Security Event Analysis
- Threat Intelligence Enrichment
- Attack Surface Visibility

---

# KQL Queries Used

## Failed Login Attempts

```kql
SecurityEvent
| where EventID == 4625
```

## Filter by Source IP

```kql
SecurityEvent
| where IpAddress == "ATTACKER_IP"
```

## Recent Failed Logins

```kql
SecurityEvent
| where EventID == 4625
| order by TimeGenerated desc
```

---

# Key Takeaways

- Learned how attackers continuously scan public IP addresses
- Gained hands-on SIEM experience using Microsoft Sentinel
- Developed practical KQL querying skills
- Implemented centralized cloud logging
- Visualized real-world attack data using geographic enrichment

---





