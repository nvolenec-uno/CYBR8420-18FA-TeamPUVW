# Code Analysis

## Code Review Strategy

## Manual Code Review Findings

### 1. Environmental Variable Passed To System Call

Source code: /source4/client/client.c
Line: 966 - 969
Reference: CWE-214
Risk: High (ENV02-J, STR07-C)

### 2. Missing Default Case in Switch Statement

Source code: /source4/client/client.c 
Line: 1678, 3356 
Reference: CWE-478
Risk: Medium (MSC01-C)

### 3. Configuration Parameter Is Used In a System Call

Source code: /ctdb/server/ctdb_monitor.c 
Line: 64 - 67
Reference: CWE-15
Risk: High (ENV33-C)

## Automated Code Review Findings

### 1. Insecure String 

Source code: /examples/libsmbclient/testbrowse.c 
Line: 243 - 244
Reference: CWE-676, CWE-120
Risk: High (STR07-C)
