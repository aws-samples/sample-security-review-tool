export const BanditFixes: Record<string, string> = {
  // B1xx: General security issues
  "B101": "Replace `assert` statements with proper exception handling using `raise ValueError()` or `raise AssertionError()` with descriptive error messages, as assert statements are removed in optimized Python bytecode.",

  "B102": "Replace `exec()` calls with safer alternatives. Use specific function calls, imports, or data structures instead of dynamic code execution. If dynamic execution is necessary, validate and sanitize all inputs thoroughly.",

  "B103": "Set file permissions explicitly and securely. Use specific octal values (e.g., 0o644, 0o600) instead of overly permissive settings like 0o777. Consider the principle of least privilege.",

  "B104": "Replace hardcoded '0.0.0.0' bind addresses with specific interface addresses or configurable host settings. Use environment variables or configuration files for host binding.",

  "B105": "Remove hardcoded password strings from source code. Create a .env file named after the Python file (e.g., for script.py create script.env in the same directory) containing the ACTUAL secret values extracted from the code. Update the Python code to: 1) add 'from dotenv import load_dotenv' import if not present, 2) call load_dotenv('script.env') near the top of the file to load the environment file, 3) use os.environ.get() to read the values. Add *.env to the project root .gitignore.",

  "B106": "Remove hardcoded passwords from function arguments. Create a .env file named after the Python file (e.g., for script.py create script.env) containing the ACTUAL secret values. Update the Python code to: 1) add 'from dotenv import load_dotenv' import, 2) call load_dotenv('script.env'), 3) use os.environ.get(). Add *.env to .gitignore.",

  "B107": "Remove hardcoded password defaults from function parameters. Create a .env file named after the Python file (e.g., for script.py create script.env) containing the ACTUAL secret values. Update the Python code to: 1) add 'from dotenv import load_dotenv' import, 2) call load_dotenv('script.env'), 3) use os.environ.get() with None as default. Add *.env to .gitignore.",

  "B108": "Replace hardcoded temporary directory paths with `tempfile.mkdtemp()` or `tempfile.gettempdir()` to use system-appropriate temporary directories.",

  "B109": "Mark password configuration options as secret in configuration schemas to prevent them from being logged or displayed in plaintext.",

  "B110": "Replace bare `except: pass` blocks with specific exception handling. Either handle specific exceptions appropriately or use logging to record the exception details.",

  "B111": "Remove `run_as_root=True` settings or ensure proper privilege escalation controls are in place. Use least-privilege principles and validate the necessity of root access.",

  "B112": "Replace `except: continue` blocks with specific exception handling. Log exceptions appropriately and ensure the continue statement is intentional and safe.",

  "B113": "Add timeout parameters to HTTP requests. Use `timeout=(connection_timeout, read_timeout)` to prevent indefinite blocking and potential denial of service.",

  // B2xx: Framework-specific issues
  "B201": "Set Flask's debug mode to False in production. Use `app.debug = False` or set the `FLASK_ENV` environment variable to 'production'.",

  "B202": "Use `tarfile.extractall()` with member filtering or `tarfile.extract()` with path validation to prevent directory traversal attacks. Validate member paths before extraction.",

  // B3xx: Crypto and encoding issues
  "B301": "Replace pickle with safer serialization formats like JSON for untrusted data. If pickle is necessary, validate data sources and consider using `hmac` for integrity verification.",

  "B302": "Replace marshal with safer serialization formats like JSON. Marshal is intended for internal Python use and can execute arbitrary code when loading.",

  "B303": "Replace MD5 hash usage with stronger algorithms like SHA-256 or SHA-3. MD5 is cryptographically broken and vulnerable to collision attacks.",

  "B304": "Replace weak ciphers (DES, RC4, Blowfish) with strong algorithms like AES-256. Use well-vetted cryptographic libraries and current best practices.",

  "B305": "Use secure cipher modes like GCM, CTR, or CBC with proper IV/nonce generation. Avoid ECB mode and ensure proper authentication for encryption.",

  "B306": "Replace `tempfile.mktemp()` with `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()` to avoid race conditions and ensure secure temporary file creation.",

  "B307": "Remove or replace `eval()` calls with safer alternatives. Use `ast.literal_eval()` for simple expressions, or implement specific parsing logic for your use case.",

  "B308": "Ensure data passed to `mark_safe()` is properly sanitized. Validate and escape user input before marking it as safe to prevent XSS vulnerabilities.",

  "B309": "Use HTTPS connections instead of unverified HTTPS. Set proper SSL context with certificate verification for `HTTPSConnection`.",

  "B310": "Replace `urllib.urlopen()` with `urllib.request.urlopen()` and implement proper URL validation. Validate URLs against allowed protocols and domains.",

  "B311": "Replace `random` module with `secrets` module for cryptographic purposes. Use `secrets.randbelow()`, `secrets.token_bytes()`, or `secrets.token_hex()` for security-sensitive random values.",

  "B312": "Replace `telnetlib` with encrypted alternatives like SSH (`paramiko`) or HTTPS APIs. Telnet transmits data in plaintext and is inherently insecure.",

  "B313": "Replace `xml.etree.cElementTree` with `defusedxml.cElementTree` to prevent XML attacks. Configure parser to disable external entity processing.",

  "B314": "Replace `xml.etree.ElementTree` with `defusedxml.ElementTree` to prevent XXE attacks. Disable DTD processing and external entity resolution.",

  "B315": "Replace `xml.sax.expatreader` with `defusedxml.expatreader` to prevent XML vulnerabilities. Configure parser to reject malicious XML constructs.",

  "B316": "Replace `xml.dom.expatbuilder` with `defusedxml.expatbuilder` to prevent XXE attacks. Disable external entity processing and DTD handling.",

  "B317": "Replace `xml.sax` with `defusedxml.sax` to prevent XML attacks. Configure parser to disable dangerous XML features like external entities.",

  "B318": "Replace `xml.dom.minidom` with `defusedxml.minidom` to prevent XXE vulnerabilities. Disable external entity resolution and DTD processing.",

  "B319": "Replace `xml.dom.pulldom` with `defusedxml.pulldom` to prevent XML attacks. Configure parser to reject external entities and DTDs.",

  "B320": "Replace `lxml.etree` with `defusedxml.lxml` or configure XMLParser with `resolve_entities=False` and `no_network=True` to prevent XXE attacks.",

  "B321": "Replace FTP with SFTP or HTTPS for secure file transfer. FTP transmits credentials and data in plaintext. Use `paramiko` for SFTP or secure HTTP APIs.",

  "B322": "Replace `input()` in Python 2 with `raw_input()` or upgrade to Python 3. Python 2's `input()` evaluates user input as Python code, creating code injection risks.",

  "B323": "Set `ssl_context` parameter or use `ssl.create_default_context()` instead of unverified SSL contexts. Ensure certificate verification is enabled.",

  "B324": "Replace insecure hash functions (MD4, MD5, SHA1) with secure alternatives like SHA-256, SHA-3, or BLAKE2. Use `hashlib.sha256()` or stronger algorithms.",

  "B325": "Replace `os.tempnam()` and `os.tmpnam()` with `tempfile` module functions like `tempfile.mkstemp()` to avoid race conditions and security vulnerabilities.",

  // B4xx: Import-related issues
  "B401": "Remove `import telnetlib` and use encrypted alternatives like SSH with `paramiko` library for secure remote connections.",

  "B402": "Replace `import ftplib` with secure alternatives like SFTP using `paramiko` or HTTPS-based file transfer APIs.",

  "B403": "Use `import pickle` with caution. Consider safer serialization formats like JSON for untrusted data, and validate pickle sources thoroughly.",

  "B404": "Use `import subprocess` with secure practices. Always validate inputs, avoid shell=True, and use absolute paths for executables.",

  "B405": "Replace `import xml.etree` with `import defusedxml.ElementTree` to prevent XXE and XML bomb attacks.",

  "B406": "Replace `import xml.sax` with `import defusedxml.sax` to prevent XML-based vulnerabilities.",

  "B407": "Replace `import xml.dom.expatbuilder` with `import defusedxml.expatbuilder` for safe XML parsing.",

  "B408": "Replace `import xml.dom.minidom` with `import defusedxml.minidom` to prevent XML attacks.",

  "B409": "Replace `import xml.dom.pulldom` with `import defusedxml.pulldom` for secure XML processing.",

  "B410": "Use `import lxml` with secure configuration. Set `resolve_entities=False` and `no_network=True` in XMLParser, or use `defusedxml.lxml`.",

  "B411": "Replace `import xmlrpclib` with more secure RPC mechanisms like gRPC with TLS, or implement proper input validation and use HTTPS.",

  "B412": "Avoid importing httpoxy-vulnerable libraries. Ensure proper environment variable handling and use updated libraries that address CVE-2016-1000111.",

  "B413": "Replace `import pycrypto` with `import pycryptodome` (Cryptodome) as PyCrypto is no longer maintained and has known vulnerabilities.",

  "B415": "Use `import pyghmi` with proper security configurations. Implement authentication and ensure secure IPMI communication channels.",

  // B5xx: Network and crypto issues
  "B501": "Enable SSL certificate verification in HTTP requests. Use `verify=True` parameter or provide a CA bundle path instead of `verify=False`.",

  "B502": "Use secure SSL/TLS versions. Replace SSLv2, SSLv3, and TLSv1.0 with TLSv1.2 or TLSv1.3. Set `ssl_version=ssl.PROTOCOL_TLS` or use `ssl.create_default_context()`.",

  "B503": "Configure SSL context securely. Enable certificate verification, use strong ciphers, and disable insecure protocols. Use `ssl.create_default_context()`.",

  "B504": "Specify SSL/TLS version explicitly. Use `ssl_version=ssl.PROTOCOL_TLSv1_2` or `ssl.create_default_context()` instead of protocol auto-negotiation.",

  "B505": "Use strong cryptographic key sizes. Use at least 2048 bits for RSA, 256 bits for ECC, and follow current cryptographic standards for key generation.",

  "B506": "Replace `yaml.load()` with `yaml.safe_load()` to prevent arbitrary code execution. Use `yaml.safe_load()` for untrusted YAML data.",

  "B507": "Enable SSH host key verification. Set `AutoAddPolicy` only for testing. Use `client.set_missing_host_key_policy(paramiko.RejectPolicy())` in production.",

  "B508": "Use secure SNMP versions. Replace SNMPv1 and SNMPv2c with SNMPv3 which provides authentication and encryption capabilities.",

  "B509": "Use strong SNMP cryptography. Configure SNMPv3 with AES encryption and SHA authentication instead of DES and MD5.",

  // B6xx: Process and command injection
  "B601": "Use Paramiko securely. Validate hostnames, enable host key checking, and use strong authentication methods. Avoid hardcoded credentials.",

  "B602": "Avoid `shell=True` in subprocess calls. Use `shell=False` and pass command arguments as a list to prevent shell injection attacks.",

  "B603": "Set `shell=False` explicitly in subprocess calls for clarity. Ensure command arguments are properly validated and use absolute paths.",

  "B604": "Avoid shell=True in process execution functions. Use `shell=False` and validate all arguments to prevent command injection vulnerabilities.",

  "B605": "Avoid starting processes with shell=True. Use `subprocess.run()` or `subprocess.Popen()` with `shell=False` and argument lists.",

  "B606": "Validate executable paths when using shell=False. Use absolute paths and validate executables exist and are safe to run.",

  "B607": "Use absolute paths for executables. Avoid relying on PATH resolution which could lead to execution of unintended programs.",

  "B608": "Use parameterized queries instead of string formatting for SQL. Use database-specific parameter placeholders (?, %s) to prevent SQL injection.",

  "B609": "Replace Linux commands with Python equivalents where possible. If shell commands are necessary, validate all inputs and use `shlex.quote()` for arguments.",

  // B7xx: Django-specific (if they exist)
  "B701": "Enable Django's CSRF protection. Use `@csrf_protect` decorator and include `{% csrf_token %}` in forms. Don't use `@csrf_exempt` unnecessarily.",

  "B702": "Use Django's secure cookie settings. Set `SESSION_COOKIE_SECURE=True` and `CSRF_COOKIE_SECURE=True` for HTTPS-only cookie transmission.",

  "B703": "Configure Django security settings. Set `DEBUG=False`, use `ALLOWED_HOSTS`, enable security middleware, and follow Django security best practices.",
};
