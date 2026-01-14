# 🛡️ Javascript-Code-Detected-in-Requested-URL 
 SOC Analyst Investigation Report


> Platform: LetsDefend.io  
> Role: SOC Analyst  
> Focus: Detection, Analysis, and Response  

---

## 📌 Alert Overview

- Alert Name: SOC166 - JavaScript Code Detected in Requested URL
- Alert Source: LetsDefend.io  
- Alert / Case ID: 	116
- Severity: Medium   
- Date & Time Detected: FEB, 26, 2022 06:56 PM
- Analyst: Jose Sanchez
	
Hostname: WebServer1002
Destination IP Address: 172.16.17.17
Source IP Address: 112.85.42.13
HTTP Request Method: GET
Requested URL: https://172.16.17.17/search/?q=<$script>javascript:$alert(1)<$/script>
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
Alert Trigger Reason: JavaScript code detected in URL
Device Action: Allowed
<img width="1888" height="616" alt="image" src="https://github.com/user-attachments/assets/6ef5e509-dfce-4d32-a415-103038b6cc3c" />

---

## 📝 Initial Alert Summary

  
 This alert was generated due to suspicious HTTP requests containing JavaScript-related keywords commonly associated with Cross-Site Scripting (XSS) attacks.
"<$script>javascript:$alert(1)</script>"
 
 
I went to the Log Management section and filtered the Destination Address Containing "172.16.17.17." 
 This log represents a web based attak attempt, XSS. 
 
 There were 8 attempts from the Source Address "112.85.42.13." 
 
 <img width="1600" height="558" alt="image" src="https://github.com/user-attachments/assets/76872d62-0a80-4b3f-bb7a-fc6f823bc3a3" />


 From the RAW Logs, I can see that 4 of the events involved the attacker trying to inject code. 

 <img width="560" height="342" alt="image" src="https://github.com/user-attachments/assets/b7ccae51-c0d3-42c3-9f85-96f4f355bebe" />

 <img width="554" height="322" alt="image" src="https://github.com/user-attachments/assets/3330822c-fee8-4d00-b4b3-8c30f905c782" />

 
<img width="558" height="348" alt="image" src="https://github.com/user-attachments/assets/cbaf3960-3d85-48c4-b2b0-98c704aa4de2" />

<img width="568" height="320" alt="image" src="https://github.com/user-attachments/assets/1e61bf5e-300d-427a-9af8-9c705fd37c67" />



I wondered what the Source port 49283 was; this appears as a destination port when a client connects to a server. Most likely TLS.SSL connection from a server to a client, but it can function as a source port when the server initiates a response back to the client. It falls within the dynamic/private port range (49152–65535), meaning it is used for temporary, ephemeral connections. 

 The attacker is targeting a search parameter"(q=)". 
 It is also using an old Browser version and was spoofed by scanners. 

I went to VirusTotal and searched for the source IP Address 112.85.42.13
In the Relations tab, I noticed that this IP Address sent a Communicating Files, and it was detected as a Malware Trojan. 
<img width="1586" height="892" alt="image" src="https://github.com/user-attachments/assets/a1f4f038-810b-4d0c-93ab-c7a26191269e" />


<img width="1440" height="890" alt="image" src="https://github.com/user-attachments/assets/6a064443-9022-4c31-b71b-40f7490f8390" />

I was able to find out more information about the Source IP Address using AlienVault, and found out that it had a history of Brute Force, Honeypot. 

<img width="1814" height="864" alt="image" src="https://github.com/user-attachments/assets/18be6b3b-395e-459d-b309-4ef7c5a2587b" />

---
There were no logs to see if the actions were successful. From the information I gathered, I know the URL request was redirected. 

<img width="1850" height="530" alt="image" src="https://github.com/user-attachments/assets/b0f36fb5-8e01-4a98-92fa-992ddb7771c6" />



## 🚩 Indicators of Compromise (IOCs)

### 🌐 Network Indicators
- **Source IP(s):**  
  - `112.85.42.13`
- **Destination IP(s):**  
  - `172.16.17.17`
- **Ports / Protocols:**  
  - Source Port: `49283`  
  - Destination Port: `443` (HTTPS)

---

### 🧪 Payload / Application Indicators
- **Suspicious Parameters:**  
  - `q` (search query parameter)
 **Observed Keywords:**  
  - `script`  
  - `javascript`  
  - `alert`  
  - `prompt`  
  - `eval`  
  - `svg`  
  - `img`  
  - `onerror`
- **Encoded / Special Characters:**  
  - `<` `>`  
  - URL-encoded characters (`%20`)  
  - JavaScript execution wrappers

---

## 🕵️Playbook 
**Supporting Evidence:**  

I will insert my artifacts into my SIEM report. 

<img width="1020" height="678" alt="image" src="https://github.com/user-attachments/assets/4c9225c2-ce3c-4791-b5de-51b784bf6105" />


## Notes
<img width="790" height="586" alt="image" src="https://github.com/user-attachments/assets/a8094985-d481-436a-bdf4-d34dcecfc9da" />


## Closing Remarks 

This alert represents a true positive, as the system correctly identified an XSS attempt. Based on the parameters and payloads observed, this was a legitimate attack attempt rather than normal user behavior. Given the repeated malicious patterns, the source IP should be flagged and blocked to prevent further exploitation attempts.

Editor Note :
We put the Requested URL into URL Decoding and find the payload sent by the attacker.
After URL Decoding, it has been confirmed that it is SQL Injection.
When we filtered by source address from the Log Management page, we saw other requests made. When the requests were examined, we saw that all of them were related to the SQL Injection vulnerability.
When the Response size of all requests is examined, it is seen that they are all the same, and the response status is 500.
The SQL Injection attack is unsuccessful, as there will be different response sizes and a 200 response status. It seems that the attack was not successful.


<img width="1584" height="532" alt="image" src="https://github.com/user-attachments/assets/350fbb62-e379-4266-a403-56fe9975e725" />

---
### Recommended Remediation Steps

1. Block and Monitor the Attacker Source

Recommend an immediate block of the identified source IP at the firewall or web application firewall (WAF).

Add the IP to a monitored watchlist to detect any future attempts using different payloads or patterns.
Why this matters: Prevents repeated probing and reduces noise from automated scanners.

2. Implement or Strengthen Web Application Firewall (WAF) Rules

Enable WAF rules specifically designed to detect and block XSS payloads, including:

<script> tags

Event handlers (e.g., onerror)

JavaScript keywords such as alert, eval, and prompt
Why this matters: Stops malicious requests before they reach the application, reducing exposure and risk.



---


## ✅ Final Determination

- **Verdict:** True Positive 
---

## 🔗 Resources

VirusTotal: https://www.virustotal.com/gui/file/c61df176fc90fd089ca36c316e4d29393f77c424c8455c69ef7fc4203427c8b0/behavior



AlienVault: https://otx.alienvault.com/indicator/ip/112.85.42.13



---


