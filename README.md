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
Search in the "botsv1" index for the "suricata" sourcetype and look for the term "cerber" in quotation marks to begin the search broadly

![2025-03-05 09_08_22-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/37b77560-281d-446c-8708-82156fae731b)

Search within the FIELD values to identify "suricata_signature_id", then determine the most recent ID that triggered the fewest number of times, specifically with a count of 1

![2025-03-05 09_08_38-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/ba3c353c-c690-4406-8a75-170215d006cf)

- ID # = 2816763

## Q3: What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

Search within the "stream:dns" sourcetype and look for our user IP address in quotation marks to initiate the query.

![2025-03-05 09_12_15-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/c3eeffdb-e1e3-44ab-952d-134a5527b361)

Search within the FIELD values for query_type{} and filter for the "A" value, as we are focusing on IPv4 address records. After looking at the logs, we want to search for the query{} value to find the FQDN

![2025-03-05 09_12_27-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/61bc0f74-5288-4e81-9a26-b2be602ea287)
![2025-03-05 09_12_50-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/19b93a3f-c0da-48f8-980d-31f553865ff2)
![2025-03-05 09_15_47-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/4a5e9479-3e99-49ec-9362-8117c96da664)

After making a table with "query{}" "_time" field, we can find the suspicious FQDN that attempted to redirect the user at the END of its encryption phase

![2025-03-05 09_16_00-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/a3997a00-1e8c-40f9-a803-22d4a9541d4d)

- "cerberhhyed5frqa.xmfir0.win"

## Q4: What was the first suspicious domain visited by we8105desk on 24AUG2016?
Use the table that I created for question 3 to answer this question

![2025-03-05 09_16_28-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/f49e17a3-554e-4022-a484-038bdadc6de8)

- "solidaritedeproximite.org"

## Q5: During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

Search within the "sysmon" sourcetype to identify instances of VBS process execution. 

![2025-03-05 09_39_35-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/35d751a4-6feb-4ef6-bb3f-66ca672b1e0a)

Examine the FIELD values to locate "CommandLine" and assess the length of its value.

![2025-03-05 09_40_32-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/c12483eb-f4fd-4826-a96c-bc08cb1526ac)
![2025-03-05 09_42_01-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/a95e43d6-8326-4e04-83c9-70b491cfc2ec)
![2025-03-05 09_42_09-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/2e538a65-3570-4535-bc55-998639e405f0)

- Length = 4490

## Q6: What is the name of the USB key inserted by Bob Smith?

Before running this query, I will first Google the Windows Registry location for USB artifacts. After identifying different registry locations, I will search within the "winregistry" sourcetype. After reviewing various registry locations, I have finally found the correct one for this system.

![2025-03-05 09_45_02-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/e12eeaa6-208b-4932-a38f-42a40c4dafa7)
![2025-03-05 09_44_50-Digital Forensics_ Artifact Profile - USB Devices - Magnet Forensics](https://github.com/user-attachments/assets/19b3c86f-96c4-43b8-90b0-f982871c0da2)

There were only two logs for this query, so I focused on the log with the "modified" action value rather than "created", as "modified" indicates that the attacker has altered a value within the Windows Registry.

![2025-03-05 09_45_28-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/aecec89b-b25b-42b4-b945-e41a0a4d95ad)

- USB key inserted = MIRANDA_PRI

## Q7: Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

To identify the IP address of the file server, search within the "stream:smb" sourcetype and filter by the source IP address "192.168.250.100", as the infected endpoint was connected to a file server.

![2025-03-05 10_24_09-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/e515e4e1-af59-478b-bc41-493b4fede3cf)

Look at the FIELD value for "dest_ip" 

![2025-03-05 10_24_21-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/96edac99-cacd-4a0a-9c55-1d5b7a8c32fb)

- "192.168.250.20" is the file server as Bob's infected workstation made a lot of request to this address

## Q8: How many distinct PDFs did the ransomware encrypt on the remote file server?

To investigate PDF encryption, search within the "wineventlog" sourcetypes and filter for all PDF files. Also filter for "192.168.250.100" as our source address.

![2025-03-05 10_30_30-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/66799b87-d34f-476a-82ca-8402e23b1efb)
![2025-03-05 10_32_54-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/f975b40d-89ba-43b1-a327-d5417e4e9d4e)

Look into the FIELD value and find query for "Relative_Target_Name" since this field tells us all of the PDF file name. Also make it unique value by using the "dedup" command

![2025-03-05 10_31_01-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/5f88eb11-d376-499f-bc72-c96dd907ec60)
![2025-03-05 10_40_32-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/469b4038-b997-4112-b67c-60465a6e5675)
![2025-03-05 10_33_12-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/1ca8c68e-efa7-4369-a503-18f969b7777b)

- 257 distinct PDF file values

## Q9: The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

For process execution analysis, I examined the "sysmon" sourcetype and included filters for .tmp files and .vbs script extensions in the query. Got 1 result and looked at the parent prcess ID.

![2025-03-05 10_59_25-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/8cf0cb31-d933-44b6-aa15-743cb129fb39)
![2025-03-05 10_59_48-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/9b224de7-d37d-4279-8ecf-8ee52968fad0)

- PPID = 3968

## Q10: The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

For file encryption analysis, I searched within the "sysmon" sourcetype and filtered for .txt files.

![2025-03-05 11_03_48-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/798e43ae-63bb-4e88-8c92-894918bb9192)

Examine the FIELD values to locate "TargetFilename" and filter specifically for Bob Smith's Windows profile. Incorporate this into the query along with Event Code 2, which indicates a change in file creation time. Use dedup to eliminate duplicate files.

![2025-03-05 11_03_57-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/9bf45eb2-6754-49bf-b51a-f8971ca65a36)
![2025-03-05 11_05_22-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/8f4eb994-bb2f-4a16-a9dd-4a7ca5c88482)
![2025-03-05 11_06_48-Search _ Splunk 8 2 4](https://github.com/user-attachments/assets/74627858-0acc-46ae-9945-b2c559c520ca)

- 406 .txt files encrypted

## Q11: The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

## Q12: Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?
