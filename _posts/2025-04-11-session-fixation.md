---
layout: post
title: Session Fixation Attack
date: 2025-04-11 17:30 +0300
categories: [Web Security, Server-side]
tags: [session, session fixation, session hijacking, session security, cookie]
---

## Introduction

Session fixation is a web security vulnerability that allows an attacker to force a user to use a specific session identifier (session ID). The attack exploits applications that do not generate new session identifiers when users authenticate, allowing attackers to hijack authenticated sessions and impersonate legitimate users.

## How Session Fixation Works

### Attack Flow

1. **Attacker obtains a valid session ID** from the target website
2. **Attacker tricks the victim** into using this predetermined session ID
3. **Victim authenticates** using the fixed session ID
4. **Attacker uses the now-authenticated session ID** to access the victim's account

### Key Concepts

- **Session ID**: A unique identifier used to track a user's session
- **Session Management**: How web applications assign, track, and validate session IDs
- **Authentication**: The process of verifying a user's identity
- **Session Fixation**: Forcing a user to use a specific session ID before authentication

## Attack Vectors

### URL Parameter Method

An attacker sends a link with a session ID in the URL:

```
https://vulnerable-site.com/login.php?SESSIONID=1234567890
```

When the victim clicks this link and logs in, the attacker can use the same session ID to access the authenticated session.

### Cookie-based Method

The attacker sets a cookie on the victim's browser:

```html
<img src="https://vulnerable-site.com/setcookie.php?SESSIONID=1234567890" style="display:none">
```

### Hidden Form Field Method

```html
<form action="https://vulnerable-site.com/login.php" method="POST">
  <input type="hidden" name="SESSIONID" value="1234567890">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
```

### Cross-subdomain Cookie Injection

If the application accepts session IDs from subdomains:

```html
<img src="https://sub.vulnerable-site.com/setcookie.php?SESSIONID=1234567890" style="display:none">
```

### Meta Tag Refresh

```html
<meta http-equiv="refresh" content="0;url=https://vulnerable-site.com/login.php?SESSIONID=1234567890">
```

## Technical Example

### PHP Example - Vulnerable Code

```php
<?php
// Vulnerable code - doesn't regenerate session ID on login
session_start();

if(isset($_POST['username']) && isset($_POST['password'])) {
    // Authenticate user
    if($_POST['username'] == 'admin' && $_POST['password'] == 'password123') {
        // Set session variable to indicate authenticated user
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $_POST['username'];
        header('Location: dashboard.php');
        exit;
    }
}
?>

<form method="post" action="login.php">
    Username: <input type="text" name="username"><br>
    Password: <input type="password" name="password"><br>
    <input type="submit" value="Login">
</form>
```

### PHP Example - Secure Code

```php
<?php
// Secure code - regenerates session ID on login
session_start();

if(isset($_POST['username']) && isset($_POST['password'])) {
    // Authenticate user
    if($_POST['username'] == 'admin' && $_POST['password'] == 'password123') {
        // Regenerate session ID to prevent fixation
        session_regenerate_id(true);
        
        // Set session variable to indicate authenticated user
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $_POST['username'];
        header('Location: dashboard.php');
        exit;
    }
}
?>

<form method="post" action="login.php">
    Username: <input type="text" name="username"><br>
    Password: <input type="password" name="password"><br>
    <input type="submit" value="Login">
</form>
```

## Real-World Attack Scenario

1. **Reconnaissance**: Attacker identifies a vulnerable web application that doesn't regenerate session IDs after authentication
2. **Preparation**: Attacker obtains a valid session ID by visiting the site
3. **Social Engineering**: Attacker sends an email to the victim with a link containing the fixed session ID
4. **Victim Action**: Victim clicks the link and logs into their account
5. **Session Hijacking**: Attacker uses the now-authenticated session ID to access the victim's account
6. **Unauthorized Access**: Attacker performs actions as the authenticated victim

## Prevention Measures

### Server-side Prevention

1. **Regenerate Session IDs**: Always create a new session ID after authentication
   ```php
   session_regenerate_id(true);
   ```

2. **Validate Session Changes**: Implement checks for suspicious session changes
3. **Session Timeouts**: Implement appropriate session expiration
4. **Accept Only Server-Generated IDs**: Reject session IDs provided by users
5. **Secure Session Cookie Attributes**:
   ```
   Set-Cookie: SESSIONID=abc123; HttpOnly; Secure; SameSite=Strict
   ```

6. **IP Binding**: Optionally bind sessions to IP addresses (with caution due to mobile networks)

### Framework-specific Implementation

#### Java (Spring Security)

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                .sessionFixation().newSession()  // Prevent session fixation
                .maximumSessions(1);             // Prevent multiple sessions
    }
}
```

#### ASP.NET

```csharp
// In Global.asax.cs
protected void Application_BeginRequest(object sender, EventArgs e)
{
    // Check if user just authenticated
    if (Request.IsAuthenticated && Session["PreviouslyAuthenticated"] == null)
    {
        // Regenerate session ID
        Session.Regenerate();
        Session["PreviouslyAuthenticated"] = true;
    }
}
```

#### Express.js (Node.js)

```javascript
const session = require('express-session');

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// On login route
app.post('/login', (req, res) => {
  // Authenticate user
  if (validCredentials(req.body.username, req.body.password)) {
    // Regenerate session to prevent fixation
    req.session.regenerate((err) => {
      if (err) next(err);
      
      // Store user information
      req.session.userId = userID;
      req.session.save((err) => {
        if (err) next(err);
        res.redirect('/dashboard');
      });
    });
  }
});
```

## Detection and Testing

### Manual Testing Steps

1. **Access the application** and note the assigned session ID
2. **Manipulate the session ID** by using a fixed value in the URL, cookie, or form
3. **Authenticate** to the application without closing the browser
4. **Verify if the session ID changes** after authentication
5. If the session ID remains the same, the application is vulnerable to session fixation

### Automated Testing

Use security tools like:
- OWASP ZAP Session Fixation scanner
- Burp Suite Professional's session handling scanner
- Custom scripts to detect if session IDs change after authentication

### Burp Suite Test Example

1. Intercept the initial request to get a session ID
2. Send that session ID in a modified login request 
3. Observe if the application generates a new session ID after authentication

## Impact of Session Fixation

### Security Risks

- **Account Hijacking**: Complete access to victim's account
- **Identity Theft**: Impersonation of the victim
- **Data Theft**: Access to sensitive information
- **Financial Loss**: Unauthorized transactions
- **Privacy Violations**: Access to personal information

### Notable Incidents

- In 2010, several banking applications were found vulnerable to session fixation
- Social media platforms have experienced session fixation vulnerabilities, leading to account compromises
- E-commerce sites have had vulnerabilities allowing attackers to access user accounts and payment information

## OWASP Classification

Session fixation is listed in the OWASP Top Ten under the category of **Broken Authentication**. It's specifically mentioned as a subcategory of session management flaws that can lead to authentication bypasses.

## Best Practices Summary

1. **Always regenerate session IDs after:**
   - Authentication
   - Privilege level changes
   - Switching from HTTP to HTTPS

2. **Implement proper session management:**
   - Short session timeouts
   - Secure cookie attributes
   - Multi-factor authentication for sensitive operations

3. **Validate session data:**
   - Check for anomalous changes
   - Implement session monitoring
   - Use additional context validation

4. **User education:**
   - Warn users about clicking suspicious links
   - Encourage use of bookmarks for sensitive sites
   - Promote awareness of phishing techniques


## References
- [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#Secure_and_HttpOnly_cookies)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
