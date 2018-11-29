# Code Analysis

## Code Review Strategy

Execute an automated scan using SonarQube and Cppcheck static analysis tools of the Samba open source project on Git Hub.
The attached graphics are from https://SonarCloud.io web site of the results.
The automated scan showed 2 security errors for 1,422,846 lines of source code in 3,952 files.
We found an addition 3 legitimate security errors which are described in the manual review section below.

## Manual Code Review Findings

### 1. Environmental Variable Passed To System Call

Source code: /source4/client/client.c<br/>
Line: 966 - 969<br/>
Reference: CWE-214<br/>
Risk: High (ENV02-J, STR07-C)<br/>

### 2. Missing Default Case in Switch Statement

Source code: /source4/client/client.c<br/> 
Line: 1678, 3356<br/> 
Reference: CWE-478<br/>
Risk: Medium (MSC01-C)<br/>

### 3. Configuration Parameter Is Used In a System Call

Source code: /ctdb/server/ctdb_monitor.c<br/> 
Line: 64 - 67<br/>
Reference: CWE-15<br/>
Risk: High (ENV33-C)<br/>

## Automated Code Review Findings

### 1. Insecure String 

Source code: /examples/libsmbclient/testbrowse.c<br/> 
Line: 243 - 244<br/>
Reference: CWE-676, CWE-120<br/>
Risk: High (STR07-C)<br/>

## SonarCloudio.io Analysis Images
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/SolarCloud1.jpg)
