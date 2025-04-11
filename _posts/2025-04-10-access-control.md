---
layout: post
title: Access Control
date: 2025-04-10 17:13 +0300
categories: [Web Security, Server-side]
tags: [dac, mac, privilege escalation, user role]
---

## Introduction

Access control is the process of granting or denying specific requests to obtain and use information and related information processing services. It is a fundamental component of security that ensures users can only perform actions they are authorized to perform and access data they are authorized to access.

Access control vulnerabilities are among the most critical security issues in web applications and APIs. In fact, Broken Access Control topped the OWASP Top 10 Web Application Security Risks in 2021, highlighting its significance in the security landscape.

## Access Control Models

### Discretionary Access Control (DAC)

Access decisions are based on the identity of the requester and access rules stating what requesters are allowed to do.

```
# Example: File permissions in Unix systems
-rw-r--r--  1 owner group  4096 Apr 10 09:30 file.txt
```

### Mandatory Access Control (MAC)

Access is controlled by the operating system based on security levels and clearances.

```
# Example: SELinux policy
type=AVC msg=audit(1364481363.243:24): avc:  denied  { read } for  pid=138 comm="httpd" path="/var/www/html/file" dev=dm-0 ino=938721 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:samba_share_t:s0 tclass=file
```

### Role-Based Access Control (RBAC)

Access decisions are based on the roles that users have within the system.

```json
// Example: User roles
{
  "user": "alice",
  "roles": ["editor", "contributor"],
  "permissions": ["create_post", "edit_post", "delete_post"]
}
```

### Attribute-Based Access Control (ABAC)

Access decisions are based on attributes associated with users, resources, actions, and environment.

```javascript
// ABAC decision example
function canAccessResource(user, resource, action, environment) {
  if (user.department === resource.department && 
      user.clearanceLevel >= resource.requiredClearance && 
      environment.time > "9:00" && environment.time < "17:00" &&
      action === "read") {
    return true;
  }
  return false;
}
```

## Common Access Control Vulnerabilities

### Vertical Privilege Escalation

When a user can access functionality intended for higher-privileged users.

```
# Regular user URL
https://example.com/user/profile

# Admin functionality accessed by regular user
https://example.com/admin/users/delete/123
```

### Horizontal Privilege Escalation

When a user can access resources belonging to another user of the same privilege level.

```
# User accessing their own resource
https://example.com/user/profile?id=1337

# User accessing someone else's resource
https://example.com/user/profile?id=1338
```

### Missing Function Level Access Control

When sensitive functionality is unprotected and accessible to unauthorized users.

```
# Protected function implemented only with frontend hiding
<!-- Admin panel link hidden by CSS for non-admin users -->
<div class="admin-section" style="display: none;">
  <a href="/admin/dashboard">Admin Dashboard</a>
</div>
```

### Improper Access Control in REST APIs

```
# API missing authorization checks
GET /api/v1/users/1338/payment_info
```

### Parameter-Based Access Control Issues

```
# URL with insecure parameter controlling access
https://example.com/view_document?id=123&admin=false

# Attacker modified URL
https://example.com/view_document?id=123&admin=true
```

### Direct Object Reference Vulnerabilities

```
# Accessing file by direct reference
https://example.com/download?file=report_123.pdf

# Path traversal combined with direct reference
https://example.com/download?file=../../../etc/passwd
```

## Access Control Testing Methodology

### 1. Identify Access Control Mechanisms

- Authentication systems (login, MFA)
- Authorization systems (permissions, roles)
- Session management
- Token validation
- IP-based restrictions
- Time-based restrictions

### 2. Map User Roles & Permissions

```
# Example permission matrix
+-----------------+------------+--------+----------+
| Function        | Anonymous  | User   | Admin    |
+-----------------+------------+--------+----------+
| View public     | ✓          | ✓      | ✓        |
| Edit own        | ✗          | ✓      | ✓        |
| Edit others     | ✗          | ✗      | ✓        |
| Delete          | ✗          | ✗      | ✓        |
| Admin panel     | ✗          | ✗      | ✓        |
+-----------------+------------+--------+----------+
```

### 3. Test Vertical Access Controls

```bash
# 1. Identify admin functionality
GET /admin/dashboard

# 2. Attempt to access as lower privileged user
curl -H "Cookie: session=user_session_cookie" https://example.com/admin/dashboard

# 3. Check for client-side only restrictions
# Look for code like:
if (user.isAdmin) {
  showAdminFeatures();
}
```

### 4. Test Horizontal Access Controls

```bash
# 1. Access your own resource
curl -H "Cookie: session=user_session_cookie" https://example.com/api/users/1337/data

# 2. Change the identifier to another user's
curl -H "Cookie: session=user_session_cookie" https://example.com/api/users/1338/data
```

### 5. Test Context-Dependent Access Controls

```bash
# Test if you can access objects in incorrect order
# E.g., accessing confirmation page without going through payment

# 1. Normal flow
GET /cart
POST /checkout
GET /payment
POST /confirm

# 2. Try to skip steps
GET /cart
GET /confirm  # Should be denied
```

## Advanced Access Control Exploitation Techniques

### Parameter Manipulation

```
# Original request
POST /api/update_settings
{
  "user_id": 1337,
  "is_admin": false
}

# Modified request
POST /api/update_settings
{
  "user_id": 1337,
  "is_admin": true
}
```

### HTTP Method Tampering

```
# If GET is blocked but POST is not checked
GET /admin/create_user    # Returns 403 Forbidden
POST /admin/create_user   # Might succeed
```

### Forced Browsing

```bash
# Using tools like DIRB, Gobuster, or ffuf to discover endpoints
dirb https://example.com /usr/share/wordlists/dirb/big.txt

# Forced browsing to common admin paths
curl https://example.com/admin
curl https://example.com/administrator
curl https://example.com/console
curl https://example.com/management
curl https://example.com/control
curl https://example.com/dashboard
```

### Request Forgery to Bypass Access Controls

```html
<!-- CSRF to exploit poorly protected admin function -->
<form id="csrf-form" action="https://example.com/admin/add_user" method="POST">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="role" value="admin">
</form>
<script>document.getElementById("csrf-form").submit();</script>
```

### JWT Token Manipulation

```javascript
// Decode JWT token
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMzM3LCJyb2xlIjoidXNlciJ9.y65Uyt-tJFyfToi4k3GtJ7bXrGNtfMyxpzT8L_q52D4';

// Decoded payload
{
  "user_id": 1337,
  "role": "user"
}

// Manipulated payload (change role to admin)
{
  "user_id": 1337,
  "role": "admin"
}

// If signature verification is poorly implemented, create new token with manipulated payload
```

### Race Conditions in Access Control

```javascript
// Example: Two simultaneous requests to bypass limit
async function exploitRaceCondition() {
  const promises = [];
  for (let i = 0; i < 10; i++) {
    promises.push(
      fetch('https://example.com/api/premium_feature', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token },
        body: JSON.stringify({ action: 'use_feature' })
      })
    );
  }
  const results = await Promise.all(promises);
  return results;
}
```

## Access Control Analysis Tools

### Automated Tools

1. **Burp Suite Professional**
   - Autorize extension for testing access controls
   - Active Scanner for detecting vulnerabilities

2. **OWASP ZAP**
   - Access Control Testing addon
   - Forced Browse feature

3. **AuthMatrix (Burp Extension)**
   - Creates matrix of roles/endpoints to test

4. **JWT Tool**
   - For testing JWT-based access controls
   - `jwt_tool.py <token> -T`

### Manual Analysis Scripts

```python
# Python script to test multiple endpoints with different user roles
import requests
import concurrent.futures

base_url = "https://example.com/api"
endpoints = ["/users", "/admin", "/reports", "/settings", "/logs"]
roles = {
    "admin": "admin_session_token",
    "user": "user_session_token",
    "guest": ""
}

results = {}

def test_endpoint(role, token, endpoint):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = requests.get(f"{base_url}{endpoint}", headers=headers)
    return role, endpoint, response.status_code, len(response.text)

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = []
    for role, token in roles.items():
        for endpoint in endpoints:
            futures.append(executor.submit(test_endpoint, role, token, endpoint))
    
    for future in concurrent.futures.as_completed(futures):
        role, endpoint, status, length = future.result()
        if role not in results:
            results[role] = {}
        results[role][endpoint] = {"status": status, "length": length}

# Analyze for access control issues
for endpoint in endpoints:
    statuses = [results[role][endpoint]["status"] for role in roles]
    if len(set(statuses)) == 1:
        print(f"Potential issue: {endpoint} returns {statuses[0]} for all roles")
```

## Prevention Strategies and Best Practices

### Implementation Patterns

#### 1. Centralized Access Control Logic

```javascript
// Centralized authorization service
class AuthorizationService {
  static checkAccess(user, resource, action) {
    // Check if user has role-based access
    if (this.hasRole(user, 'admin')) return true;
    
    // Check if user owns the resource
    if (action === 'read' || action === 'update') {
      return this.isResourceOwner(user, resource);
    }
    
    // Deny by default
    return false;
  }
  
  static hasRole(user, role) {
    return user.roles.includes(role);
  }
  
  static isResourceOwner(user, resource) {
    return resource.ownerId === user.id;
  }
}

// Using the service in an API endpoint
app.get('/api/documents/:id', (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).send('Not found');
  
  if (!AuthorizationService.checkAccess(req.user, document, 'read')) {
    return res.status(403).send('Forbidden');
  }
  
  return res.json(document);
});
```

#### 2. Policy-Based Authorization

```javascript
// Using a policy-based library like CASL
const { defineAbility } = require('@casl/ability');

function defineAbilityFor(user) {
  return defineAbility((can, cannot) => {
    if (user.role === 'admin') {
      can('manage', 'all');
    } else {
      can('read', 'Article');
      can(['update', 'delete'], 'Article', { authorId: user.id });
      can('read', 'Comment');
      can(['update', 'delete'], 'Comment', { authorId: user.id });
    }
    
    cannot('delete', 'Article', { published: true });
  });
}

// Using in an API endpoint
app.delete('/api/articles/:id', async (req, res) => {
  const article = await Article.findById(req.params.id);
  if (!article) return res.status(404).send('Not found');
  
  const ability = defineAbilityFor(req.user);
  if (ability.cannot('delete', article)) {
    return res.status(403).send('Forbidden');
  }
  
  await article.delete();
  return res.status(204).send();
});
```

#### 3. Attribute-Based Access Control

```java
// Java example using Spring Security and ABAC
@PreAuthorize("hasRole('ADMIN') or " +
              "(hasRole('USER') and #document.ownerId == authentication.principal.id) and " +
              "T(java.time.LocalTime).now().isAfter(T(java.time.LocalTime).of(9, 0)) and " +
              "T(java.time.LocalTime).now().isBefore(T(java.time.LocalTime).of(17, 0))")
public Document accessDocument(Document document) {
    return documentRepository.findById(document.getId());
}
```

### Design Principles for Secure Access Control

1. **Deny by Default**
   ```javascript
   // Start with denying all access
   function checkAccess(user, resource, action) {
     // Specific allow rules here
     if (isAllowed(user, resource, action)) {
       return true;
     }
     
     // Default deny
     return false;
   }
   ```

2. **Defense in Depth**
   ```javascript
   // Multiple layers of authorization
   
   // Layer 1: API Gateway / Front Controller
   app.use(authMiddleware);
   
   // Layer 2: Route-specific middleware
   app.get('/admin/*', adminMiddleware);
   
   // Layer 3: Business logic validation
   function updateUser(requestingUser, targetUserId, data) {
     // Check again inside the business logic
     if (!isAuthorized(requestingUser, targetUserId)) {
       throw new Error('Unauthorized');
     }
     // Proceed with update
   }
   ```

3. **Server-Side Enforcement**
   ```javascript
   // Never rely on client-side restrictions
   
   // BAD (client-side only)
   if (isAdmin) {
     showAdminButton();
   }
   
   // GOOD (server enforces restrictions regardless of UI)
   app.post('/api/admin/action', (req, res) => {
     if (!req.user.isAdmin) {
       return res.status(403).send('Forbidden');
     }
     // Process admin action
   });
   ```

4. **Least Privilege**
   ```javascript
   // Assign the minimum necessary permissions
   
   // Instead of one admin role with full access:
   const roles = {
     'user': ['read:own_data', 'update:own_data'],
     'support': ['read:user_data', 'update:user_data'],
     'reports_admin': ['read:all_data', 'generate:reports'],
     'system_admin': ['create:users', 'delete:users', 'update:system'],
   };
   ```

5. **Secure Session Management**
   ```javascript
   // Ensure access control is tied to secure sessions
   
   // Set secure cookies
   app.use(session({
     secret: 'strong_secret',
     name: 'sessionId',
     cookie: {
       secure: true,
       httpOnly: true,
       sameSite: 'strict',
       maxAge: 3600000 // 1 hour
     },
     resave: false,
     saveUninitialized: false
   }));
   ```

## Common Access Control Bypasses & Solutions

### URL Bypasses

#### Issue
```
# Access denied
https://example.com/admin/users

# But these might work
https://example.com/ADMIN/users
https://example.com/admin/users/
https://example.com/adm1n/users
https://example.com/%61%64%6d%69%6e/users  # URL encoded
https://example.com/./admin/users
```

#### Solution
```javascript
// Normalize paths before access control checks
const normalizedPath = path.normalize(req.path).toLowerCase();
if (normalizedPath.startsWith('/admin/') && !req.user.isAdmin) {
  return res.status(403).send('Forbidden');
}
```

### Method Bypasses

#### Issue
```
# POST denied
POST /admin/delete_user HTTP/1.1

# But these might work
GET /admin/delete_user HTTP/1.1
PUT /admin/delete_user HTTP/1.1
DELETE /admin/delete_user HTTP/1.1
```

#### Solution
```javascript
// Check authorization regardless of HTTP method
app.all('/admin/*', (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).send('Forbidden');
  }
  next();
});
```

### Insecure Direct Object References

#### Issue
```
# User accessing their own data
GET /api/users/1337/profile

# Simply changing the ID to access another user's data
GET /api/users/1338/profile
```

#### Solution
```javascript
app.get('/api/users/:id/profile', (req, res) => {
  // Check if the requested ID matches the authenticated user
  // or if the user has appropriate permissions
  if (req.params.id != req.user.id && !hasAdminPermission(req.user)) {
    return res.status(403).send('Forbidden');
  }
  
  // Proceed with the request
  const profile = getUserProfile(req.params.id);
  res.json(profile);
});
```

### Referrer/Origin Validation Bypass

#### Issue
```
# Server checks HTTP Referer/Origin header
server {
  location /admin/ {
    if ($http_referer !~ "^https://example.com/admin/") {
      return 403;
    }
    # Process request
  }
}
```

#### Solution
```javascript
// Don't rely only on Referer/Origin headers
// Instead, use proper session-based authentication and authorization
app.use('/admin/*', (req, res, next) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.status(403).send('Forbidden');
  }
  next();
});
```

### JWT Token Manipulation

#### Issue
```javascript
// JWT with algorithm set to "none"
const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxMzM3LCJyb2xlIjoiYWRtaW4ifQ.';
```

#### Solution
```javascript
// Always validate JWT signatures with a specific algorithm
const jwt = require('jsonwebtoken');

app.use((req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Unauthorized');
  
  try {
    // Explicitly specify the expected algorithm
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'] // Only accept this algorithm
    });
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send('Invalid token');
  }
});
```

## Role-Based Access Control Implementation

### Example: RBAC with Express.js

```javascript
// Define roles and permissions
const roles = {
  guest: [],
  user: ['read:own_profile', 'update:own_profile', 'create:posts'],
  moderator: ['read:own_profile', 'update:own_profile', 'create:posts', 
              'update:posts', 'delete:posts', 'read:user_profiles'],
  admin: ['read:own_profile', 'update:own_profile', 'create:posts', 
          'update:posts', 'delete:posts', 'read:user_profiles',
          'update:user_profiles', 'delete:users', 'create:users']
};

// Middleware to check permissions
function checkPermission(permission) {
  return (req, res, next) => {
    const userRole = req.user?.role || 'guest';
    const userPermissions = roles[userRole] || [];
    
    if (userPermissions.includes(permission)) {
      next();
    } else {
      res.status(403).send('Forbidden');
    }
  };
}

// Using the middleware in routes
app.get('/api/users/:id/profile', checkPermission('read:user_profiles'), (req, res) => {
  // Handler code
});

app.put('/api/users/:id/profile', (req, res) => {
  const userId = req.params.id;
  const currentUser = req.user;
  
  // If updating own profile or has admin permission
  if (userId === currentUser.id) {
    checkPermission('update:own_profile')(req, res, () => {
      // Update profile
    });
  } else {
    checkPermission('update:user_profiles')(req, res, () => {
      // Update other user's profile
    });
  }
});
```

### Example: RBAC with Spring Security (Java)

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/moderator/**").hasRole("MODERATOR")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
            .and()
                .logout()
                .permitAll();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        // Create users with roles
        UserDetails user =
             User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
                
        UserDetails moderator =
             User.withDefaultPasswordEncoder()
                .username("moderator")
                .password("password")
                .roles("USER", "MODERATOR")
                .build();
                
        UserDetails admin =
             User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("USER", "MODERATOR", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, moderator, admin);
    }
}
```

## Real-World Access Control Vulnerabilities

### Facebook Access Control Bypass (2021)

A vulnerability allowed users to view private information on private profiles because access controls were not properly enforced on certain API endpoints.

**Root Cause**: Inconsistent enforcement of access controls across different API versions and endpoints.

### Zoom Meeting Security Issues (2020)

Zoom meetings lacked proper access controls, allowing unauthorized users to join private meetings through "meeting ID" guessing.

**Root Cause**: Reliance on obfuscation (meeting IDs) rather than proper authentication and authorization.

### HackerOne Private Program Access (2019)

A vulnerability allowed hackers to view private bug bounty programs they weren't invited to.

**Root Cause**: Missing access control check for the handler that fetched program details.

### CVE-2021-26084: Confluence Server

An OGNL injection vulnerability in Confluence Server allowed unauthenticated attackers to execute arbitrary code on vulnerable installations.

**Root Cause**: Missing authentication check combined with OGNL injection vulnerability.

## Security Headers for Access Control

```
# X-Frame-Options
# Prevents clickjacking by controlling if a page can be embedded in frames
X-Frame-Options: DENY

# Content-Security-Policy
# Restricts which resources can be loaded, reducing XSS risks
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none';

# X-Content-Type-Options
# Prevents MIME type sniffing
X-Content-Type-Options: nosniff

# Permissions-Policy (formerly Feature-Policy)
# Controls which browser features are available
Permissions-Policy: camera=(), microphone=(), geolocation=()

# Cross-Origin Resource Sharing headers
# Controls cross-origin requests
Access-Control-Allow-Origin: https://trusted-site.com
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type, Authorization
```

## Access Control Testing Checklist

1. **User Role Enumeration**
   - [ ] Identify all user roles in the application
   - [ ] Create accounts for each role
   - [ ] Document intended permissions for each role

2. **Identification of Protected Functionality**
   - [ ] Map all application functionality and endpoints
   - [ ] Note which roles should have access to each function
   - [ ] Check for hidden functionality in client-side code

3. **Vertical Privilege Escalation Testing**
   - [ ] Access higher-level functions as lower-privilege user
   - [ ] Check admin functions with non-admin account
   - [ ] Test direct access to admin endpoints
   - [ ] Modify role/privilege claims in tokens/cookies

4. **Horizontal Privilege Escalation Testing**
   - [ ] Access other users' resources of same privilege
   - [ ] Modify identifiers in URLs, request bodies, headers
   - [ ] Try UUID/GUID manipulation for less obvious IDs
   - [ ] Test API endpoints with other users' identifiers

5. **Context-Dependent Access Control Testing**
   - [ ] Test business flow bypass (e.g., skip payment step)
   - [ ] Test time-dependent access controls
   - [ ] Check for conditions that might change access (e.g., holidays)

6. **HTTP Method Testing**
   - [ ] Try different HTTP methods on protected endpoints
   - [ ] Test with OPTIONS, HEAD, PUT, DELETE, etc.
   - [ ] Try method override techniques (X-HTTP-Method-Override)

7. **Parameter Pollution and Manipulation**
   - [ ] Duplicate parameters with different values
   - [ ] Add unexpected parameters that might affect access control
   - [ ] Test parameter arrays/objects for logic issues

8. **Token and Cookie Manipulation**
   - [ ] Analyze tokens for encoded privileges (JWT, etc.)
   - [ ] Attempt to modify token claims
   - [ ] Test token signature bypass techniques
   - [ ] Check cookie-based access controls

## References

1. [OWASP Top 10 2021 - A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
2. [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
3. [PortSwigger Web Academy: Access Control](https://portswigger.net/web-security/access-control)
4. [NIST SP 800-53 Access Control](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
5. [HackTricks: Access Control Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/broken-authentication)
6. [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)

