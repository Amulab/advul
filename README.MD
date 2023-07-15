# AD高危漏洞扫描/利用工具


&emsp;&emsp;AD高危漏洞扫描/利用工具, 对AD高危漏洞进行快速批量检测。
1. #### 单机扫描
   &emsp;&emsp;未指定批量扫描相关参数时, 默认使用该模式。
2. #### 批量扫描
    &emsp;&emsp;当指定相关参数时(-all-dc/-tf), 启用批量扫描模式, 在该模式下, 未指定目标ip文件时, 将通过dns解析域名获取所有域控ip, 并进行批量探测, 若指定ip列表文件, 则只对指定的ip列表进行扫描。

## 导航

- [CVE-2020-1472](#cve-2020-1472)
- [CVE-2021-42287](#cve-2021-42287)
- [CVE-2022-26923](#cve-2022-26923)
- [CVE-2022-33679](#cve-2022-33679)

## 使用
```text
PS C:\> python.exe advul/main.py 
usage: main.py [-h] [-ts] [-debug] [-dc-ip ip address] [-target-ip ip address]
               [-target dns/ip address] [-ns nameserver] [-dns-tcp]
               [-timeout seconds] [-u username@domain] [-p password]
               [-hashes [LMHASH:]NTHASH] [-k] [-sspi] [-aes hex key]
               [-no-pass] [-all-dc] [-tf target file] [--threads threads]
               [-ntlm-method {rpc,smb}] [-ldap-scheme {ldap,ldaps}]
               {33679,26923,42287,zerologon}

Active Directory Vulnerability Scanner

positional arguments:
  {33679,26923,42287,zerologon}
                        modules

options:
  -h, --help            Show this help message and exit
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON

connection options:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
  -target dns/ip address
                        DNS Name or IP Address of the target machine. Required
                        for Kerberos or SSPI authentication
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -u username@domain, -username username@domain
                        Username. Format: username@domain
  -p password, -password password
                        Password
  -hashes [LMHASH:]NTHASH
                        NTLM hash, format is [LMHASH:]NTHASH
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -sspi                 Use Windows Integrated Authentication (SSPI)
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -no-pass              Don't ask for password (useful for -k and -sspi)

multi targets options:
  -all-dc               attack all dcs
  -tf target file       path to targets file
  --threads threads     number of worker threads

ntlm info options:
  -ntlm-method {rpc,smb}
                        method for ntlm info detection

ldap connection options:
  -ldap-scheme {ldap,ldaps}
                        method for ntlm info detection
```
## CVE-2020-1472
   &emsp;&emsp;理论上检测zerologon只需要知道目标ip即可，工具在仅有目标ip时，利用ntlminfo获取目标主机名，再通过常规手段进行zerologon漏洞探测。
### 使用示例

#### 扫描单个目标
   ```text
   PS C:\> python.exe advul/main.py -ts -dc-ip 192.168.31.110 zerologon 
   
   [2023-07-16 03:58:15] [-] Username is not specified
   [2023-07-16 03:58:15] [*] checking target 192.168.31.110...
   [2023-07-16 03:58:17] [*] [192.168.31.110] is vulnerable to zero logon!!!
   ```
#### 扫描单个目标(指定参数)
   ```text
PS C:\> python.exe advul/main.py -ts -dc-ip 192.168.31.110 -auth-method 2 -target-name DC01 zerologon 

[2023-07-16 04:01:16] [-] Username is not specified
[2023-07-16 04:01:16] [*] checking target 192.168.31.110...
[2023-07-16 04:01:16] [*] [192.168.31.110] is vulnerable to zero logon!!!
```

#### 批量扫
   ```text
PS C:\> python.exe advul/main.py -ts -all-dc -dc-ip 192.168.31.110 zerologon 

[2023-07-16 04:02:59] [-] Username is not specified
[2023-07-16 04:02:59] [*] checking target 192.168.31.111...
[2023-07-16 04:02:59] [*] checking target 192.168.31.110...
[2023-07-16 04:03:02] [*] [192.168.31.111] might not vulnerable:<
[2023-07-16 04:03:03] [*] [192.168.31.110] is vulnerable to zero logon!!!


```

## CVE-2021-42287
   &emsp;&emsp;使用域内任意用户凭据进行Kerberos认证, 向目标域控申请S4U2Self票据并遍历Pac属性, 通过ulType=0x10类型Pac的存在可以判断目标域控是否安装更新补丁。
### 使用示例

#### 扫描单个目标
   ```text
PS C:\> python.exe advul/main.py -u JDCA$@jd.local -hashes 48f925772624af82147e750a45b912a8 -dc-ip 192.168.31.110 42287 
    
    [*] [192.168.31.110] is vulnerable to 42287!!!!
```

#### 批量扫描
   ```text
   PS C:\> python.exe advul/main.py -ts -all-dc -u JDCA$@jd.local -hashes 48f925772624af82147e750a45b912a8 -dc-ip 192.168.31.110 42287 
   
   [2023-07-15 02:52:28] [*] [192.168.31.111] is patched :<
   [2023-07-15 02:52:28] [*] [192.168.31.110] is vulnerable to 42287!!!!
   ```

## CVE-2022-26923
   &emsp;&emsp;利用域内机器用户凭据登录目标域控Ldap服务, 对该域控Ldap数据库中自身的dnsHostName属性进行修改, 若修改成功, 说明未安装补丁, 若提示约束冲突说明已安装补丁。
### 使用示例

#### 扫描单个目标
   ```text
   PS C:\> python.exe advul/main.py -u JDCA$ -hashes 48f925772624af82147e750a45b912a8 -dc-ip 192.168.31.110 26923 
   
   [*] [192.168.31.110] success, target is vulnerable!!!
   ```
#### 批量扫描
   ```text
   PS C:\> python.exe advul/main.py -ts -all-dc -u JDCA$@jd.local -hashes 48f925772624af82147e750a45b912a8 -dc-ip 192.168.31.110 26923 

   [2023-07-15 02:59:48] [*] [192.168.31.110] success, target is vulnerable!!!
   [2023-07-15 02:59:48] [*] [192.168.31.111] constraintViolation, target is not vulnerable :<
   ```

## CVE-2022-33679
   &emsp;&emsp;向目标域控发起Kerberos预认证, 将加密方式设置为RC4-MD4(-128), 若返回KDC_ERR_ETYPE_NOSUPP(14)说明已安装更新补丁, 若返回KDC_ERR_PREAUTH_REQUIRED(25), 说明存在漏洞。
   
### 使用示例

#### 扫描单个目标
   ```text
   PS C:\> python.exe advul/main.py -ts -dc-ip 192.168.31.110 -u mayun@jd.local 33679 

   [2023-07-15 03:05:49] [*] [192.168.31.110] has 33679
   ```

#### 批量扫描
   ```text
   PS C:\> python.exe advul/main.py -ts -tf dcs.txt -dc-ip 192.168.31.110 -u mayun@jd.local 33679 

   [2023-07-15 03:04:24] [*] [192.168.31.110] has 33679
   [2023-07-15 03:04:24] [*] [192.168.31.111] is not vuln
   ```
