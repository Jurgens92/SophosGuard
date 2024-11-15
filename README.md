# SophosGuard

## Overview

**SophosGuard** is an open-source C# application currently in beta, designed to enhance network security by automatically retrieving malicious IP addresses from ipthreat.net. The application caches these IPs and applies them to a block firewall rule (WAN to LAN) on your Sophos XGS firewall, helping to protect your network from known threats.

## Features

- **Automatic IP Retrieval**: Regularly pulls bad IPs from ipthreat.net.
- **Caching**: Efficiently stores retrieved IPs for quick access.
- **Firewall Integration**: Applies cached IPs to a block rule on the Sophos XGS firewall.
- **Open Source**: Join the community and contribute to the project!

## Current Status

- **Early Version**: This application is currently working. Features may change, and feedback is welcome!

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/Jurgens92/SophosGuard.git
   cd sophosguard
