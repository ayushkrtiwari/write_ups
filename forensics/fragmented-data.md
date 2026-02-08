# Forensics Nightmare - CTF Writeup

## Challenge Information

- **Name:** Forensics Nightmare
- **Category:** Digital Forensics / DFIR
- **Difficulty:** Hard
- **Points:** 300
- **Flag:** `CTF{f0r3ns1c_4n4lys1s_m4st3r_2026}`

## Challenge Description

You're a SOC analyst investigating a security breach. Forensic artifacts have been collected including security logs, network packets, disk images, memory dumps, and file metadata. The flag is hidden across multiple evidence types using various encoding techniques.

**Access:** `https://ctf.hackelite.app/challenges/5/39`

## Solution Overview

The flag is split into 5 parts across different forensic evidence:
1. **Security Logs** - Hex encoded in timestamp anomalies
2. **Network Packets** - Hex encoded in packet payloads
3. **Disk Artifacts** - Base64 encoded in file comments
4. **Memory Dumps** - ROT13 encoded strings
5. **File Metadata** - Base64 encoded in EXIF/XMP data

### Credentials Discovery

Login credentials follow common default patterns:
- **Username:** `analyst` 
- **Password:** `soc2026`

## Step-by-Step Solution

### Step 1: Security Logs - Hex in Timestamps

Navigate to **Security Logs** and examine timestamp fields. Notice anomalies:

```json
"timestamp": "2026-02-09T10:23:433054"  // Extra digits after milliseconds!
```

Extract characters beyond position 19 from all timestamps, concatenate, and decode from hex:

```python
hex_data = "3054665f30573054395f703031..."  # Extracted from timestamps
decoded = bytes.fromhex(hex_data).decode('utf-8')
# Result: "CTF{f0r3"
```

### Step 2: Network Packets - Hex in Payloads

Check **Network Traffic** packet payloads for hex-encoded data in unusual fields or appended to legitimate traffic.

```python
# Look for hex patterns in packet data
# Decode hex sequences to find: "ns1c_4n4"
```

### Step 3: Disk Artifacts - Base64 in Comments

Examine **Disk Artifacts** file contents for Base64 strings in comments:

```ini
# config.ini
# Internal comment: Zm9yM25zMWNfNG40bHlz
```

```python
import base64
decoded = base64.b64decode("Zm9yM25zMWNfNG40bHlz").decode()
# Result: "lys1s_m4"
```

### Step 4: Memory Dumps - ROT13 Encoding

Search **Memory Dumps** for strings starting with `PSG{`:

```python
import codecs
rot13_text = "PSG{...z4fg3e_2026}"
decoded = codecs.decode(rot13_text, 'rot_13')
# Result: "CTF{...m4st3r_2026}"  (ROT13: C→P, T→G, F→S)
```

### Step 5: File Metadata - Base64 in EXIF/XMP

Check **File Metadata** for Base64 in XMP Description fields:

```python
xmp_data = "Q1RGe2YwcjNuczFjXzRuNGx5czFzX200c3QzeV8yMDI2fQ=="
decoded = base64.b64decode(xmp_data).decode()
# Result: Full flag as confirmation
```

### Final Flag Assembly

```
Stage 1 (Logs hex):     CTF{f0r3
Stage 2 (Packets hex):  ns1c_4n4
Stage 3 (Disk base64):  lys1s_m4
Stage 4 (Memory rot13): st3r_2026}

Complete Flag: CTF{f0r3ns1c_4n4lys1s_m4st3r_2026}
```

## Encoding Techniques Used

```python
# Hexadecimal
bytes.fromhex("4354467b").decode()  # "CTF{"

# Base64
import base64
base64.b64decode("Q1RGew==").decode()  # "CTF{"

# ROT13 (shift by 13)
import codecs
codecs.decode("PSG{", 'rot_13')  # "CTF{"  (C→P, T→G, F→S)
```

## Key Takeaways

**DFIR Skills Demonstrated:**
- Timeline analysis and timestamp anomaly detection
- Network forensics and packet payload inspection
- Disk forensics and metadata analysis
- Memory forensics and string extraction
- Multi-encoding layer recognition (hex, base64, ROT13)
- Cross-artifact pattern correlation

**Security Lessons:**
- Default credentials remain a critical vulnerability
- Data can be hidden in metadata across multiple sources
- Encoding layers obscure but don't secure data
- Forensic analysis requires systematic methodology

**Tools:** Browser DevTools, Python (requests, base64, codecs), text editors, built-in decoders

## References

- [SANS Digital Forensics](https://www.sans.org/cyber-security-courses/advanced-digital-forensics-incident-response/)
- [NIST SP 800-86: Guide to Integrating Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [Volatility Framework](https://www.volatilityfoundation.org/)

---

**Author:** CTF Challenge Team | **Date:** February 2026 | **Difficulty:** ⭐⭐⭐⭐⭐
