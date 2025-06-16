# Win-Enum.ps1

## Overview

`Win-Enum.ps1` is a PowerShell-based enumertion tool designed for red teamers, penetration testers, and internal security audits. It gathers key system and network details for post-compromise enumeration or situational awareness during engagements.

## Features

- Collects host system information (e.g., OS, user context)
- Enumerates network adapters, routing table, DNS cache, ARP table
- Analyzes listening ports and active connections with process mapping
- Retrieves domain information (trusts, domain controllers, password policies)
- Checks firewall status, mapped drives, and shares
- Parses scheduled tasks running as SYSTEM/Admin
- Lists running services, local users, groups, and environment variables
- Optionally performs subnet ping sweep (first 10 IPs)
- Outputs results and error logs to timestamped text files

## Usage

### Syntax

```powershell
.\Win-Enum.ps1 [-Verbose] [-SkipSlow] [-OutputDir <path>]
