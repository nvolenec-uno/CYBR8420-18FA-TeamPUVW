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

## Cppcheck Scan Results
```
nvolenec@mintleaf ~/samba $ cppcheck -f ./samba-4.9.2/ > /home/nvolenec/samba_cppchec_scan.txt
[samba-4.9.2/ctdb/common/ctdb_io.c:421]: (error) Boolean value assigned to pointer.
[samba-4.9.2/ctdb/common/ctdb_ltdb.c:60]: (error) Analysis failed. If the code is valid then please report this failure.
[samba-4.9.2/examples/auth/crackcheck/crackcheck.c:113]: (error) fflush() called on input stream 'stdin' results in undefined behaviour.
[samba-4.9.2/lib/ldb/common/ldb_modules.c:995]: (error) Analysis failed. If the code is valid then please report this failure.
[samba-4.9.2/lib/ldb/ldb_mdb/ldb_mdb.c:51]: (error) syntax error
[samba-4.9.2/lib/pthreadpool/tests.c:62]: (error) Memory leak: finished
[samba-4.9.2/lib/replace/snprintf.c:1462]: (error) sprintf format string has 5 parameters but only 4 are given.
[samba-4.9.2/lib/replace/snprintf.c:1472]: (error) sprintf format string has 5 parameters but only 4 are given.
[samba-4.9.2/lib/replace/test/os2_delete.c:110]: (error) Resource leak: d
[samba-4.9.2/lib/replace/test/snprintf.c:24]: (error) Null pointer dereference
[samba-4.9.2/lib/replace/test/testsuite.c:173]: (error) Memory leak: x
[samba-4.9.2/lib/replace/test/testsuite.c:267]: (error) Memory leak: x
[samba-4.9.2/lib/tdb/common/check.c:404]: (error) Uninitialized struct member: rec.rec_len
[samba-4.9.2/lib/tdb/common/summary.c:127]: (error) Uninitialized struct member: rec.rec_len
[samba-4.9.2/lib/tdb/common/tdb.c:347]: (error) Uninitialized struct member: lastrec.next
[samba-4.9.2/lib/tdb/test/run-mutex-openflags2.c:89]: (error) Memory leak: tdb
[samba-4.9.2/lib/tdb/test/run-mutex-openflags2.c:152]: (error) Memory leak: tdb
[samba-4.9.2/lib/tdb/tools/tdbtorture.c:490]: (error) Memory leak: done
[samba-4.9.2/lib/tevent/tevent_epoll.c:142]: (error) Boolean value assigned to pointer.
[samba-4.9.2/libcli/auth/pam_errors.c:114]: (error) syntax error
[samba-4.9.2/libcli/util/nterr.c:316]: (error) syntax error
[samba-4.9.2/nsswitch/krb5_plugin/winbind_krb5_localauth.c:216]: (error) Memory leak: name
[samba-4.9.2/nsswitch/libwbclient/wbc_sid.c:784]: (error) Common realloc mistake: 'extra_data' nulled but not freed upon failure
[samba-4.9.2/nsswitch/libwbclient/wbclient.c:217]: (error) Memory leak: result
[samba-4.9.2/nsswitch/nsstest.c:192]: (error) Common realloc mistake: 'buf' nulled but not freed upon failure
[samba-4.9.2/nsswitch/nsstest.c:230]: (error) Common realloc mistake: 'buf' nulled but not freed upon failure
[samba-4.9.2/nsswitch/nsstest.c:269]: (error) Common realloc mistake: 'buf' nulled but not freed upon failure
[samba-4.9.2/nsswitch/pam_winbind.c:126]: (error) syntax error
[samba-4.9.2/nsswitch/pam_winbind.c:130]: (error) syntax error
[samba-4.9.2/nsswitch/pam_winbind.c:134]: (error) syntax error
[samba-4.9.2/nsswitch/pam_winbind.c:122]: (error) syntax error
[samba-4.9.2/nsswitch/winbind_nss_linux.c:55]: (error) syntax error
[samba-4.9.2/source3/auth/pampass.c:684]: (error) syntax error
[samba-4.9.2/source3/auth/pass_check.c:258]: (error) syntax error
[samba-4.9.2/source3/client/smbspool.c:345]: (error) Resource leak: fp
[samba-4.9.2/source3/lib/messages_dgm.c:1141]: (error) Boolean value assigned to pointer.
[samba-4.9.2/source3/lib/util.c:1304]: (error) Uninitialized variable: ra_key
[samba-4.9.2/source3/lib/util.c:1347]: (error) Uninitialized variable: ra_key
[samba-4.9.2/source3/lib/util_sd.c:313]: (error) Uninitialized variable: sidstr
[samba-4.9.2/source3/lib/util_sd.c:626]: (error) Uninitialized variable: sidstr
[samba-4.9.2/source3/libads/krb5_errs.c:102]: (error) syntax error
[samba-4.9.2/source3/modules/vfs_commit.c:98]: (error) Uninitialized variable: result
[samba-4.9.2/source3/nmbd/nmbd_workgroupdb.c:167]: (error) Uninitialized variable: un_name
[samba-4.9.2/source3/smbd/dosmode.c:805]: (error) Analysis failed. If the code is valid then please report this failure.
[samba-4.9.2/source3/smbd/open.c:1220]: (error) Analysis failed. If the code is valid then please report this failure.
[samba-4.9.2/source3/smbd/open.c:3223]: (error) Analysis failed. If the code is valid then please report this failure.
[samba-4.9.2/source3/smbd/reply.c:671]: (error) Uninitialized variable: name1
[samba-4.9.2/source3/smbd/reply.c:671]: (error) Uninitialized variable: name2
[samba-4.9.2/source3/torture/torture.c:3972]: (error) Boolean value assigned to pointer.
[samba-4.9.2/source3/utils/nmblookup.c:249]: (error) Uninitialized variable: lookup
[samba-4.9.2/source3/utils/ntlm_auth.c:413]: (error) Uninitialized variable: domain
[samba-4.9.2/source3/utils/ntlm_auth.c:413]: (error) Uninitialized variable: name
[samba-4.9.2/source3/utils/ntlm_auth.c:1719]: (error) Uninitialized variable: fstr_user
[samba-4.9.2/source3/utils/ntlm_auth.c:1719]: (error) Uninitialized variable: fstr_domain
[samba-4.9.2/source3/utils/ntlm_auth.c:1999]: (error) Uninitialized variable: fstr_user
[samba-4.9.2/source3/utils/ntlm_auth.c:2000]: (error) Uninitialized variable: fstr_domain
[samba-4.9.2/source3/winbindd/idmap_ad_nss.c:360]: (error) Possible null pointer dereference: ctx
[samba-4.9.2/source3/winbindd/idmap_autorid_tdb.c:121]: (error) Uninitialized variable: keystr
[samba-4.9.2/source3/winbindd/idmap_autorid_tdb.c:341]: (error) Uninitialized variable: keystr
[samba-4.9.2/source3/winbindd/winbindd_cm.c:1538]: (error) Uninitialized variable: dcname
[samba-4.9.2/source4/auth/kerberos/kerberos_util.c:532]: (error) syntax error
[samba-4.9.2/source4/client/client.c:3429]: (error) Memory leak: base_directory
[samba-4.9.2/source4/client/client.c:3429]: (error) Memory leak: desthost
[samba-4.9.2/source4/dsdb/common/util.c:548]: (error) Address of local auto-variable assigned to a function parameter.
[samba-4.9.2/source4/dsdb/common/util.c:561]: (error) Address of local auto-variable assigned to a function parameter.
[samba-4.9.2/source4/dsdb/samdb/ldb_modules/operational.c:1429]: (error) Invalid number of character (() when these macros are defined: ''.
[samba-4.9.2/source4/heimdal/lib/gssapi/krb5/set_sec_context_option.c:155]: (error) Memory leak: str
[samba-4.9.2/source4/heimdal/lib/gssapi/krb5/set_sec_context_option.c:167]: (error) Memory leak: str
[samba-4.9.2/source4/heimdal/lib/gssapi/krb5/set_sec_context_option.c:203]: (error) Memory leak: str
[samba-4.9.2/source4/heimdal/lib/hcrypto/libtommath/mtest/mpi.c:3600]: (error) Uninitialized variable: jx
[samba-4.9.2/source4/heimdal/lib/hdb/mkey.c:601]: (error) Memory leak: set_time
[samba-4.9.2/source4/heimdal/lib/hdb/mkey.c:583]: (error) Uninitialized variable: set_time
[samba-4.9.2/source4/heimdal/lib/hx509/name.c:242]: (error) Memory leak: oidname
[samba-4.9.2/source4/heimdal/lib/hx509/name.c:419]: (error) Memory leak: ds1lp
[samba-4.9.2/source4/heimdal/lib/hx509/name.c:423]: (error) Memory leak: ds2lp
[samba-4.9.2/source4/heimdal/lib/krb5/crypto.c:1929]: (error) Common realloc mistake: 'd' nulled but not freed upon failure
[samba-4.9.2/source4/heimdal/lib/krb5/eai_to_heim_errno.c:54]: (error) syntax error
[samba-4.9.2/source4/heimdal/lib/krb5/eai_to_heim_errno.c:78]: (error) syntax error
[samba-4.9.2/source4/heimdal/lib/krb5/fcache.c:334]: (error) Memory leak: f
[samba-4.9.2/source4/heimdal/lib/krb5/get_cred.c:726]: (error) Common realloc mistake: 'tmp' nulled but not freed upon failure
[samba-4.9.2/source4/heimdal/lib/krb5/get_cred.c:1504]: (error) Memory leak: out
[samba-4.9.2/source4/heimdal/lib/krb5/init_creds_pw.c:1221]: (error) Memory leak: paid
[samba-4.9.2/source4/heimdal/lib/krb5/krbhst.c:447]: (error) Memory leak: res
[samba-4.9.2/source4/heimdal/lib/krb5/pkinit.c:1219]: (error) Memory leak: ptr
[samba-4.9.2/source4/heimdal/lib/krb5/principal.c] -> [samba-4.9.2/source4/heimdal/lib/krb5/principal.c:819]: (error) Internal error. Token::Match called with varid 0. Please report this to Cppcheck developers
[samba-4.9.2/source4/heimdal/lib/krb5/transited.c:284]: (error) Memory leak: tmp
[samba-4.9.2/source4/lib/wmi/wmi_wrap.c:184]: (error) Invalid number of character ({) when these macros are defined: 'METH_O'.
[samba-4.9.2/source4/libcli/resolve/dns_ex.c:402]: (error) syntax error
[samba-4.9.2/source4/param/pyparam.c:322]: (error) Resource leak: f
[samba-4.9.2/source4/smb_server/smb/reply.c:818]: (error) Uninitialized variable: req
[samba-4.9.2/source4/torture/local/nss_tests.c:774]: (error) Possible null pointer dereference: user_groups
[samba-4.9.2/testprogs/win32/npecho/npecho_client.c:21]: (error) Memory leak: outbuffer
[samba-4.9.2/testprogs/win32/npecho/npecho_client2.c:116]: (error) Memory leak: outbuffer
[samba-4.9.2/testprogs/win32/npecho/npecho_server2.c:70]: (error) Memory leak: outbuffer
[samba-4.9.2/testprogs/win32/prepare_dcpromo/prepare_dcpromo.c:246]: (error) Memory leak: old_Dacl
[samba-4.9.2/testprogs/win32/prepare_dcpromo/prepare_dcpromo.c:241]: (error) Memory leak: AbsoluteSD
[samba-4.9.2/testprogs/win32/prepare_dcpromo/prepare_dcpromo.c:251]: (error) Memory leak: Sacl
[samba-4.9.2/testprogs/win32/prepare_dcpromo/prepare_dcpromo.c:256]: (error) Memory leak: Owner
[samba-4.9.2/testprogs/win32/prepare_dcpromo/prepare_dcpromo.c:813]: (error) Memory leak: newDomainSid
[samba-4.9.2/testprogs/win32/prepare_dcpromo/prepare_dcpromo.c:228]: (error) Uninitialized variable: status
[samba-4.9.2/testprogs/win32/spoolss/error.c:105]: (error) syntax error
[samba-4.9.2/testprogs/win32/spoolss/error.c:51]: (error) syntax error
[samba-4.9.2/testprogs/win32/spoolss/error.c:109]: (error) syntax error
[samba-4.9.2/testprogs/win32/spoolss/error.c:101]: (error) syntax error
[samba-4.9.2/testprogs/win32/spoolss/error.c:113]: (error) syntax error
[samba-4.9.2/third_party/aesni-intel/inst-intel.h:179]: (error) syntax error
[samba-4.9.2/third_party/nss_wrapper/nss_wrapper.c:5214]: (error) Invalid number of character ({) when these macros are defined: 'HAVE_NSS_COMMON_H'.
[samba-4.9.2/third_party/nss_wrapper/nss_wrapper.c:5214]: (error) Invalid number of character ({) when these macros are defined: 'HAVE_NSS_H'.
[samba-4.9.2/third_party/popt/popt.c:718]: (error) Common realloc mistake: 't' nulled but not freed upon failure
[samba-4.9.2/third_party/popt/popt.c:1673]: (error) Common realloc mistake: 'items' nulled but not freed upon failure
[samba-4.9.2/third_party/popt/poptconfig.c:324]: (error) Common realloc mistake: 'b' nulled but not freed upon failure
[samba-4.9.2/third_party/popt/poptint.c:169]: (error) Common realloc mistake: 'b' nulled but not freed upon failure
[samba-4.9.2/third_party/popt/poptparse.c:91]: (error) Common realloc mistake: 'argv' nulled but not freed upon failure
[samba-4.9.2/third_party/popt/poptparse.c:189]: (error) Common realloc mistake: 'argstr' nulled but not freed upon failure
[samba-4.9.2/third_party/popt/poptparse.c:218]: (error) Common realloc mistake: 'argstr' nulled but not freed upon failure
[samba-4.9.2/third_party/socket_wrapper/socket_wrapper.c:2816]: (error) syntax error
[samba-4.9.2/third_party/socket_wrapper/socket_wrapper.c:2819]: (error) syntax error
[samba-4.9.2/third_party/socket_wrapper/socket_wrapper.c:4391]: (error) syntax error
[samba-4.9.2/third_party/socket_wrapper/socket_wrapper.c:4384]: (error) syntax error
[samba-4.9.2/third_party/socket_wrapper/socket_wrapper.c:3904]: (error) syntax error
[samba-4.9.2/third_party/socket_wrapper/socket_wrapper.c:3919]: (error) syntax error
[samba-4.9.2/third_party/socket_wrapper/socket_wrapper.c:3955]: (error) syntax error
[samba-4.9.2/third_party/zlib/contrib/minizip/zip.c:613]: (error) Memory leak: zi
[samba-4.9.2/third_party/zlib/contrib/minizip/zip.c:956]: (error) Uninitialized variable: t
[samba-4.9.2/third_party/zlib/examples/zran.c:224]: (error) Common realloc mistake: 'index' nulled but not freed upon failure
```
