# Splunk-Boss-of-the-SOCv1 (RANSOMWARE)
![2025-02-28 09_59_52-Splunk Boss of the SOC](https://github.com/user-attachments/assets/5a916ce4-4b79-42af-940b-11d86dbbcdd8)
# Scenario from bots.splunk.com 

After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...

## Objective
The objective of this project is to investigate a ransomware incident using Splunk by analyzing security logs, correlating events, and identifying the attack vector. The investigation will focus on detecting malicious USB activity, process execution, and file modifications. The goal is to enhance threat detection, improve incident response, and implement preventive security measures.

### Skills Learned

- Analyzing security incidents using Splunk
- Writing Splunk SPL queries to analyze Windows logs
- Parsing Sysmon, Event Logs, and Security Logs for threat detection
- Identifying USB device activity, process execution, and file modifications

### Tools Used

- Splunk - Google - VirusTotal

## PREFACE
Before I begin my investigation, I want to check what kind of index I am working with first and see the sourcetypes within the index field.
![2025-02-28 10_07_08-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/92b8a2f6-8db7-4eda-a83b-d7963176af13)
![2025-02-28 10_07_55-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/c43b6b6d-6332-47e3-9dbd-61bb8818c302)



## Q1: What was the most likely IPv4 address of we8105desk on 24AUG2016?
Adjusting the Date Range of the Ransomware Incident

![2025-02-28 10_16_43-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/143222ac-12a0-4ffc-8a0c-268e796968f1)

I want to start with a broad search in Splunk first

![2025-02-28 10_21_03-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/89a419de-131a-47d5-8bde-8f9e730e38f0)

After reviewing the FIELDS section of the query, I checked the "src_ip" and suspect that 192.168.250.100 is the likely address of our infected endpoint

![2025-02-28 10_21_51-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/515ed288-abf7-4504-b3b8-828e4764283d)

I want to be completely certain, so I clicked on the 192.168.250.100 value to refine our query and examined one of the queried logs to verify that it matches

![2025-02-28 10_22_16-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/0510d8db-ad33-4935-a074-7b046170f846)

- IPv4 Address of we8105desk = 192.168.250.100

## Q2: Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.


## Q3: What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

## Q4: What was the first suspicious domain visited by we8105desk on 24AUG2016?

## Q5: During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

## Q6: What is the name of the USB key inserted by Bob Smith?

## Q7: Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

## Q8: How many distinct PDFs did the ransomware encrypt on the remote file server?

## Q9: The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

## Q10: The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

## Q11: The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

## Q12: Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?
