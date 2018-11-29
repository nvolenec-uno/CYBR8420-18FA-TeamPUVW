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

## SonarCloud Analysis 

![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud1.png)  
Figure 1 - Sonarcloud.io Master screen showing Samba on Github<br/>  
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud2.png)
Figure 2 - Sonarcloud.io Master screen showing Samba on Github<br/>  
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud3.png)
Figure 3 - Sonarcloud.io Master screen showing Samba on Github<br/>   
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud4.png)
Figure 4 - Sonarcloud.io Master screen showing Samba on Github<br/>  
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud5.png)
Figure 5 - Sonarcloud.io Master screen showing Samba on Github<br/>  
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud6.png)
Figure 6 - Sonarcloud.io Master screen showing Samba on Github<br/>    
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud7.png)  
Figure 7 - Sonarcloud.io Master screen showing Samba on Github<br/>    
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud8.png)  
Figure 8 - Sonarcloud.io Master screen showing Samba on Github<br/>       
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud9.png)  
Figure 9 - Sonarcloud.io Master screen showing Samba on Github<br/>     
![Sonarcloud1](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/scloud10.png)  
Figure 10 - Sonarcloud.io Master screen showing Samba on Github<br/>     

