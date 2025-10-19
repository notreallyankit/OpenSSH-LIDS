# OpenSSH Login Intrusion Detection System (LIDS)

LIDS is a lightweight **Python-based Intrusion Detection System (IDS)** designed to monitor **OpenSSH login attempts** on Windows.  
It detects multiple failed login attempts, tracks the source IP, performs geolocation lookup, and alerts the user in real time.

---

## Features

- **User Registration & Login**  
  Secure registration with hashed passwords and OTP-based login verification.

- **SSH Log Scanning**  
  Automatically scans the **Windows Event Viewer** logs under  
  *Applications and Services Logs → OpenSSH → Operational*.

- **Intrusion Detection**  
  Detects multiple failed SSH login attempts within a defined timeframe.

- **Geolocation Tracking**  
  Uses the [ipstack API](https://ipstack.com/) to trace suspicious IPs and determine location, region, and ISP.

- **Real-Time Alerting**  
  Notifies users of potential intrusion attempts via console output or optional email integration.

---

## How It Works

1. **Fetch Logs**: Reads event logs using `win32evtlog`.  
2. **Parse Events**: Extracts timestamps, usernames, and IP addresses from failed login events.  
3. **Track Frequency**: Identifies repeated failed logins from the same IP.  
4. **Validate & Geolocate**: Uses the ipstack API to locate the IP and verify if it’s legitimate.  
5. **Trigger Alert**: Displays or logs a warning when thresholds are exceeded.

---

## Tech Stack

- **Language:** Python 3  
- **Libraries:**  
  - `win32evtlog` — Access Windows Event Viewer  
  - `requests` — API calls to ipstack  
  - `smtplib` — Optional email alerting  
  - `hashlib`, `random`, `json`, `time`, `os`

---

## Setup & Usage

1. **Clone the Repository**
   ```bash
   git clone https://github.com/notreallyankit/OpenSSH-LIDS.git
   cd OpenSSH-LIDS
