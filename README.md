# Burp AES Crypto Bridge
Thib Burp extension let's you decrypt requests from a known crypto aes key. 

A Burp Suite Jython extension that transparently decrypts and re-encrypts
AES-encrypted HTTP request and response bodies in real time.

This extension is intended for **authorized security testing** of mobile
applications and APIs that implement client-side encryption using static
keys embedded in the application.

## Features

- AES/CBC/PKCS5Padding support
- Real-time request and response decryption
- Automatic re-encryption after modification
- Works seamlessly with Burp Proxy
- Enables automated testing tools (e.g. sqlmap) against encrypted APIs
- URL and payload logging for analysis

## Use Cases

- Mobile application penetration testing
- Analysis of client-side encryption schemes
- Validation of backend authorization controls
- Testing encrypted APIs for IDOR, business logic flaws, and injection issues

## Requirements

- Burp Suite Professional
- Jython Standalone 2.7.x
- Java (JRE/JDK)

## Installation

1. Download `jython-standalone-2.7.3.jar`
2. In Burp:
   - Extensions → Settings → Python Environment
   - Select the Jython standalone JAR
3. Restart Burp
4. Load the extension:
   - Extensions → Add
   - Type: Python
   - Select `burp_crypto_bridge.py`

## Configuration

Edit the following values in `burp_crypto_bridge.py`:

```python
SECRET_KEY = "CHANGE_ME_SECRET_KEY"
IV = "CHANGE_ME_IV_16_BYTES"

