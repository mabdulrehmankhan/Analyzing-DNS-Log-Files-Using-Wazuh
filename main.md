# Analyzing DNS Log Files Using Wazuh

## Introduction
DNS (Domain Name System) logs are essential for understanding network activity and identifying potential security threats. Wazuh, an open-source security monitoring solution, offers robust capabilities for analyzing DNS logs and detecting anomalies or malicious activities.

## Prerequisites
Before analyzing DNS logs in Wazuh, ensure the following:
- Wazuh server is installed and configured.
- Wazuh agents are deployed on the relevant systems.
- DNS log data sources are configured to forward logs to the Wazuh server.

## Steps to Upload Sample DNS Log Files to Wazuh

### 1. Prepare Sample DNS Log Files
- Obtain sample [DNS log files](https://www.secrepo.com/maccdc2012/dns.log.gz) in a suitable format (e.g., text files).
- Ensure the log files contain relevant DNS events, including source IP, destination IP, domain name, query type, response code, etc.
- Save the sample log files in a directory accessible by the Wazuh server.

### 2. Configure Log Collection on Wazuh Agent
- Edit the `ossec.conf` file on the Wazuh agent to include the DNS log file directory.
- Add the following configuration under the `<localfile>` tag:
  ```xml
  <localfile>
    <log_format>syslog</log_format>
    <location>/path/to/dns.log</location>
  </localfile>
  ```
- Save the configuration and restart the Wazuh agent:
  ```bash
  sudo systemctl restart wazuh-agent
  ```

### 3. Verify Log Forwarding
- Ensure the DNS log events are being forwarded to the Wazuh server by checking the Wazuh manager logs:
  ```bash
  sudo tail -f /var/ossec/logs/ossec.log
  ```

### 4. Configure Wazuh Manager to Parse DNS Logs
- Create a custom decoders and rules for DNS logs if not already available.
- Example decoder configuration in `local_decoder.xml`:
  ```xml
  <decoder name="dns_decoder">
    <type>syslog</type>
    <program_name>dns</program_name>
    <regex>^.*</regex>
    <order>dns</order>
  </decoder>
  ```
- Save the configuration and restart the Wazuh manager:
  ```bash
  sudo systemctl restart wazuh-manager
  ```

## Steps to Analyze DNS Log Files in Wazuh

### 1. Search for DNS Events
- Open the Wazuh dashboard and navigate to the **Discover** section.
- Enter the following search query to retrieve DNS events:
  ```elasticsearch
  agent.name:<agent_name> AND data.syslog.program: dns
  ```

### 2. Extract Relevant Fields
- Identify key fields in DNS logs such as source IP, destination IP, domain name, query type, response code, etc.
- Example query to extract relevant fields:
  ```elasticsearch
  agent.name:<agent_name> AND data.syslog.program: dns
  ```

### 3. Identify Anomalies
- Look for unusual patterns or anomalies in DNS activity.
- Example query to identify spikes:
  ```elasticsearch
  agent.name:<agent_name> AND data.syslog.program: dns | stats count by data.dns.query
  ```

### 4. Find the Top DNS Sources
- Use the following query to count the occurrences of each query type:
  ```elasticsearch
  agent.name:<agent_name> AND data.syslog.program: dns | top data.dns.query, data.src.ip
  ```

### 5. Investigate Suspicious Domains
- Search for domains associated with known malicious activity or suspicious behavior.
- Utilize threat intelligence feeds or reputation databases to identify malicious domains.
- Example search for known malicious domains:
  ```elasticsearch
  agent.name:<agent_name> AND data.syslog.program: dns AND data.dns.query: "maliciousdomain.com"
  ```

## Conclusion
Analyzing DNS log files using Wazuh enables security professionals to detect and respond to potential security incidents effectively. By understanding DNS activity and identifying anomalies, organizations can enhance their overall security posture and protect against various cyber threats.
