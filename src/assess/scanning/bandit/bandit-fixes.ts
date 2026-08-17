import type { Remediation } from '../remediation/types.js';

export const BanditFixes: Record<string, Omit<Remediation, 'id'>> = {
  // B1xx: General security issues
  "B101": {
    description: "assert_used",
    priority: "LOW",
    remediation: "Replace `assert` statements with proper exception handling using `raise ValueError()` or `raise AssertionError()` with descriptive error messages, as assert statements are removed in optimized Python bytecode."
  },
  "B102": {
    description: "exec_used",
    priority: "MEDIUM",
    remediation: "Replace `exec()` calls with safer alternatives. Use specific function calls, imports, or data structures instead of dynamic code execution. If dynamic execution is necessary, validate and sanitize all inputs thoroughly."
  },
  "B103": {
    description: "set_bad_file_permissions",
    priority: "MEDIUM",
    remediation: "Set file permissions explicitly and securely. Use specific octal values (e.g., 0o644, 0o600) instead of overly permissive settings like 0o777. Consider the principle of least privilege."
  },
  "B104": {
    description: "hardcoded_bind_all_interfaces",
    priority: "MEDIUM",
    remediation: "Replace hardcoded '0.0.0.0' bind addresses with specific interface addresses or configurable host settings. Use environment variables or configuration files for host binding."
  },
  "B105": {
    description: "hardcoded_password_string",
    priority: "HIGH",
    remediation: "Remove hardcoded password strings from source code. Create a .env file named after the Python file (e.g., for script.py create script.env in the same directory) containing the ACTUAL secret values extracted from the code. Update the Python code to: 1) add 'from dotenv import load_dotenv' import if not present, 2) call load_dotenv('script.env') near the top of the file to load the environment file, 3) use os.environ.get() to read the values. Add *.env to the project root .gitignore."
  },
  "B106": {
    description: "hardcoded_password_funcarg",
    priority: "HIGH",
    remediation: "Remove hardcoded passwords from function arguments. Create a .env file named after the Python file (e.g., for script.py create script.env) containing the ACTUAL secret values. Update the Python code to: 1) add 'from dotenv import load_dotenv' import, 2) call load_dotenv('script.env'), 3) use os.environ.get(). Add *.env to .gitignore."
  },
  "B107": {
    description: "hardcoded_password_default",
    priority: "LOW",
    remediation: "Remove hardcoded password defaults from function parameters. Create a .env file named after the Python file (e.g., for script.py create script.env) containing the ACTUAL secret values. Update the Python code to: 1) add 'from dotenv import load_dotenv' import, 2) call load_dotenv('script.env'), 3) use os.environ.get() with None as default. Add *.env to .gitignore."
  },
  "B108": {
    description: "hardcoded_tmp_directory",
    priority: "MEDIUM",
    remediation: "Replace hardcoded temporary directory paths with `tempfile.mkdtemp()` or `tempfile.gettempdir()` to use system-appropriate temporary directories."
  },
  "B110": {
    description: "try_except_pass",
    priority: "LOW",
    remediation: "Replace bare `except: pass` blocks with specific exception handling. Either handle specific exceptions appropriately or use logging to record the exception details."
  },
  "B112": {
    description: "try_except_continue",
    priority: "LOW",
    remediation: "Replace `except: continue` blocks with specific exception handling. Log exceptions appropriately and ensure the continue statement is intentional and safe."
  },
  "B113": {
    description: "request_without_timeout",
    priority: "MEDIUM",
    remediation: "Add timeout parameters to HTTP requests. Use `timeout=(connection_timeout, read_timeout)` to prevent indefinite blocking and potential denial of service."
  },

  // B2xx: Application and framework misuse
  "B201": {
    description: "flask_debug_true",
    priority: "HIGH",
    remediation: "Set Flask's debug mode to False in production. Use `app.debug = False` or set the `FLASK_ENV` environment variable to 'production'."
  },
  "B202": {
    description: "tarfile_unsafe_members",
    priority: "HIGH",
    remediation: "Use `tarfile.extractall()` with member filtering or `tarfile.extract()` with path validation to prevent directory traversal attacks. Validate member paths before extraction."
  },

  // B3xx: Blacklisted calls
  "B301": {
    description: "pickle",
    priority: "MEDIUM",
    remediation: "Replace pickle with safer serialization formats like JSON for untrusted data. If pickle is necessary, validate data sources and consider using `hmac` for integrity verification."
  },
  "B302": {
    description: "marshal",
    priority: "MEDIUM",
    remediation: "Replace marshal with safer serialization formats like JSON. Marshal is intended for internal Python use and can execute arbitrary code when loading."
  },
  "B303": {
    description: "md5",
    priority: "MEDIUM",
    remediation: "Replace MD5 hash usage with stronger algorithms like SHA-256 or SHA-3. MD5 is cryptographically broken and vulnerable to collision attacks."
  },
  "B304": {
    description: "ciphers",
    priority: "HIGH",
    remediation: "Replace weak ciphers (DES, RC4, Blowfish) with strong algorithms like AES-256. Use well-vetted cryptographic libraries and current best practices."
  },
  "B305": {
    description: "cipher_modes",
    priority: "MEDIUM",
    remediation: "Use secure cipher modes like GCM, CTR, or CBC with proper IV/nonce generation. Avoid ECB mode and ensure proper authentication for encryption."
  },
  "B306": {
    description: "mktemp_q",
    priority: "MEDIUM",
    remediation: "Replace `tempfile.mktemp()` with `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()` to avoid race conditions and ensure secure temporary file creation."
  },
  "B307": {
    description: "eval",
    priority: "MEDIUM",
    remediation: "Remove or replace `eval()` calls with safer alternatives. Use `ast.literal_eval()` for simple expressions, or implement specific parsing logic for your use case."
  },
  "B308": {
    description: "mark_safe",
    priority: "MEDIUM",
    remediation: "Ensure data passed to `mark_safe()` is properly sanitized. Validate and escape user input before marking it as safe to prevent XSS vulnerabilities."
  },
  "B310": {
    description: "urllib_urlopen",
    priority: "MEDIUM",
    remediation: "Replace `urllib.urlopen()` with `urllib.request.urlopen()` and implement proper URL validation. Validate URLs against allowed protocols and domains."
  },
  "B311": {
    description: "random",
    priority: "LOW",
    remediation: "Replace `random` module with `secrets` module for cryptographic purposes. Use `secrets.randbelow()`, `secrets.token_bytes()`, or `secrets.token_hex()` for security-sensitive random values."
  },
  "B312": {
    description: "telnetlib",
    priority: "HIGH",
    remediation: "Replace `telnetlib` with encrypted alternatives like SSH (`paramiko`) or HTTPS APIs. Telnet transmits data in plaintext and is inherently insecure."
  },
  "B313": {
    description: "xml_bad_cElementTree",
    priority: "MEDIUM",
    remediation: "Replace `xml.etree.cElementTree` with `defusedxml.cElementTree` to prevent XML attacks. Configure parser to disable external entity processing."
  },
  "B314": {
    description: "xml_bad_ElementTree",
    priority: "MEDIUM",
    remediation: "Replace `xml.etree.ElementTree` with `defusedxml.ElementTree` to prevent XXE attacks. Disable DTD processing and external entity resolution."
  },
  "B315": {
    description: "xml_bad_expatreader",
    priority: "MEDIUM",
    remediation: "Replace `xml.sax.expatreader` with `defusedxml.expatreader` to prevent XML vulnerabilities. Configure parser to reject malicious XML constructs."
  },
  "B316": {
    description: "xml_bad_expatbuilder",
    priority: "MEDIUM",
    remediation: "Replace `xml.dom.expatbuilder` with `defusedxml.expatbuilder` to prevent XXE attacks. Disable external entity processing and DTD handling."
  },
  "B317": {
    description: "xml_bad_sax",
    priority: "MEDIUM",
    remediation: "Replace `xml.sax` with `defusedxml.sax` to prevent XML attacks. Configure parser to disable dangerous XML features like external entities."
  },
  "B318": {
    description: "xml_bad_minidom",
    priority: "MEDIUM",
    remediation: "Replace `xml.dom.minidom` with `defusedxml.minidom` to prevent XXE vulnerabilities. Disable external entity resolution and DTD processing."
  },
  "B319": {
    description: "xml_bad_pulldom",
    priority: "MEDIUM",
    remediation: "Replace `xml.dom.pulldom` with `defusedxml.pulldom` to prevent XML attacks. Configure parser to reject external entities and DTDs."
  },
  "B321": {
    description: "ftplib",
    priority: "HIGH",
    remediation: "Replace FTP with SFTP or HTTPS for secure file transfer. FTP transmits credentials and data in plaintext. Use `paramiko` for SFTP or secure HTTP APIs."
  },
  "B323": {
    description: "unverified_context",
    priority: "MEDIUM",
    remediation: "Set `ssl_context` parameter or use `ssl.create_default_context()` instead of unverified SSL contexts. Ensure certificate verification is enabled."
  },
  "B324": {
    description: "hashlib_insecure_functions",
    priority: "HIGH",
    remediation: "Replace insecure hash functions (MD4, MD5, SHA1) with secure alternatives like SHA-256, SHA-3, or BLAKE2. Use `hashlib.sha256()` or stronger algorithms."
  },

  // B4xx: Blacklisted imports
  "B401": {
    description: "import_telnetlib",
    priority: "HIGH",
    remediation: "Remove `import telnetlib` and use encrypted alternatives like SSH with `paramiko` library for secure remote connections."
  },
  "B402": {
    description: "import_ftplib",
    priority: "HIGH",
    remediation: "Replace `import ftplib` with secure alternatives like SFTP using `paramiko` or HTTPS-based file transfer APIs."
  },
  "B403": {
    description: "import_pickle",
    priority: "LOW",
    remediation: "Use `import pickle` with caution. Consider safer serialization formats like JSON for untrusted data, and validate pickle sources thoroughly."
  },
  "B404": {
    description: "import_subprocess",
    priority: "LOW",
    remediation: "Use `import subprocess` with secure practices. Always validate inputs, avoid shell=True, and use absolute paths for executables."
  },
  "B405": {
    description: "import_xml_etree",
    priority: "LOW",
    remediation: "Replace `import xml.etree` with `import defusedxml.ElementTree` to prevent XXE and XML bomb attacks."
  },
  "B406": {
    description: "import_xml_sax",
    priority: "LOW",
    remediation: "Replace `import xml.sax` with `import defusedxml.sax` to prevent XML-based vulnerabilities."
  },
  "B407": {
    description: "import_xml_expat",
    priority: "LOW",
    remediation: "Replace `import xml.dom.expatbuilder` with `import defusedxml.expatbuilder` for safe XML parsing."
  },
  "B408": {
    description: "import_xml_minidom",
    priority: "LOW",
    remediation: "Replace `import xml.dom.minidom` with `import defusedxml.minidom` to prevent XML attacks."
  },
  "B409": {
    description: "import_xml_pulldom",
    priority: "LOW",
    remediation: "Replace `import xml.dom.pulldom` with `import defusedxml.pulldom` for secure XML processing."
  },
  "B411": {
    description: "import_xmlrpclib",
    priority: "HIGH",
    remediation: "Replace `import xmlrpclib` with more secure RPC mechanisms like gRPC with TLS, or implement proper input validation and use HTTPS."
  },
  "B412": {
    description: "import_httpoxy",
    priority: "HIGH",
    remediation: "Avoid importing httpoxy-vulnerable libraries. Ensure proper environment variable handling and use updated libraries that address CVE-2016-1000111."
  },
  "B413": {
    description: "import_pycrypto",
    priority: "HIGH",
    remediation: "Replace `import pycrypto` with `import pycryptodome` (Cryptodome) as PyCrypto is no longer maintained and has known vulnerabilities."
  },
  "B415": {
    description: "import_pyghmi",
    priority: "HIGH",
    remediation: "Use `import pyghmi` with proper security configurations. Implement authentication and ensure secure IPMI communication channels."
  },

  // B5xx: Cryptography and certificate handling
  "B501": {
    description: "request_with_no_cert_validation",
    priority: "HIGH",
    remediation: "Enable SSL certificate verification in HTTP requests. Use `verify=True` parameter or provide a CA bundle path instead of `verify=False`."
  },
  "B502": {
    description: "ssl_with_bad_version",
    priority: "HIGH",
    remediation: "Use secure SSL/TLS versions. Replace SSLv2, SSLv3, and TLSv1.0 with TLSv1.2 or TLSv1.3. Set `ssl_version=ssl.PROTOCOL_TLS` or use `ssl.create_default_context()`."
  },
  "B503": {
    description: "ssl_with_bad_defaults",
    priority: "MEDIUM",
    remediation: "Configure SSL context securely. Enable certificate verification, use strong ciphers, and disable insecure protocols. Use `ssl.create_default_context()`."
  },
  "B504": {
    description: "ssl_with_no_version",
    priority: "LOW",
    remediation: "Specify SSL/TLS version explicitly. Use `ssl_version=ssl.PROTOCOL_TLSv1_2` or `ssl.create_default_context()` instead of protocol auto-negotiation."
  },
  "B505": {
    description: "weak_cryptographic_key",
    priority: "MEDIUM",
    remediation: "Use strong cryptographic key sizes. Use at least 2048 bits for RSA, 256 bits for ECC, and follow current cryptographic standards for key generation."
  },
  "B506": {
    description: "yaml_load",
    priority: "MEDIUM",
    remediation: "Replace `yaml.load()` with `yaml.safe_load()` to prevent arbitrary code execution. Use `yaml.safe_load()` for untrusted YAML data."
  },
  "B507": {
    description: "ssh_no_host_key_verification",
    priority: "HIGH",
    remediation: "Enable SSH host key verification. Set `AutoAddPolicy` only for testing. Use `client.set_missing_host_key_policy(paramiko.RejectPolicy())` in production."
  },
  "B508": {
    description: "snmp_insecure_version",
    priority: "MEDIUM",
    remediation: "Use secure SNMP versions. Replace SNMPv1 and SNMPv2c with SNMPv3 which provides authentication and encryption capabilities."
  },
  "B509": {
    description: "snmp_weak_cryptography",
    priority: "MEDIUM",
    remediation: "Use strong SNMP cryptography. Configure SNMPv3 with AES encryption and SHA authentication instead of DES and MD5."
  },

  // B6xx: Injection
  "B601": {
    description: "paramiko_calls",
    priority: "MEDIUM",
    remediation: "Use Paramiko securely. Validate hostnames, enable host key checking, and use strong authentication methods. Avoid hardcoded credentials."
  },
  "B602": {
    description: "subprocess_popen_with_shell_equals_true",
    priority: "HIGH",
    remediation: "Avoid `shell=True` in subprocess calls. Use `shell=False` and pass command arguments as a list to prevent shell injection attacks."
  },
  "B603": {
    description: "subprocess_without_shell_equals_true",
    priority: "LOW",
    remediation: "Set `shell=False` explicitly in subprocess calls for clarity. Ensure command arguments are properly validated and use absolute paths."
  },
  "B604": {
    description: "any_other_function_with_shell_equals_true",
    priority: "MEDIUM",
    remediation: "Avoid shell=True in process execution functions. Use `shell=False` and validate all arguments to prevent command injection vulnerabilities."
  },
  "B605": {
    description: "start_process_with_a_shell",
    priority: "LOW",
    remediation: "Avoid starting processes with shell=True. Use `subprocess.run()` or `subprocess.Popen()` with `shell=False` and argument lists."
  },
  "B606": {
    description: "start_process_with_no_shell",
    priority: "LOW",
    remediation: "Validate executable paths when using shell=False. Use absolute paths and validate executables exist and are safe to run."
  },
  "B607": {
    description: "start_process_with_partial_path",
    priority: "LOW",
    remediation: "Use absolute paths for executables. Avoid relying on PATH resolution which could lead to execution of unintended programs."
  },
  "B608": {
    description: "hardcoded_sql_expressions",
    priority: "MEDIUM",
    remediation: "Use parameterized queries instead of string formatting for SQL. Use database-specific parameter placeholders (?, %s) to prevent SQL injection."
  },
  "B609": {
    description: "linux_commands_wildcard_injection",
    priority: "HIGH",
    remediation: "Replace Linux commands with Python equivalents where possible. If shell commands are necessary, validate all inputs and use `shlex.quote()` for arguments."
  },
  "B610": {
    description: "django_extra_used",
    priority: "MEDIUM",
    remediation: "Replace Django's `.extra()` queryset method with parameterised alternatives such as `.filter()`, `.annotate()` or `RawSQL` with bound parameters. `.extra()` interpolates raw SQL fragments and is a SQL injection risk; it is also deprecated in modern Django."
  },
  "B611": {
    description: "django_rawsql_used",
    priority: "MEDIUM",
    remediation: "Replace `RawSQL` and `.raw()` queries built by string formatting with parameterised queries. Pass values via the `params` argument so Django escapes them, or use the ORM query API instead of raw SQL."
  },
  "B612": {
    description: "logging_config_insecure_listen",
    priority: "MEDIUM",
    remediation: "Do not call `logging.config.listen()` on an open port. It accepts and executes logging configuration from the network, which allows remote code execution. Load logging configuration from a trusted local file with `logging.config.fileConfig()` or `dictConfig()` instead."
  },
  "B613": {
    description: "trojansource",
    priority: "HIGH",
    remediation: "Remove Unicode bidirectional control characters from the source file. These characters reorder how code is displayed without changing how it executes, so reviewed code can differ from executed code (the 'Trojan Source' attack, CVE-2021-42574). Delete the control characters, or escape them so their presence is visible in review."
  },
  "B614": {
    description: "pytorch_load",
    priority: "MEDIUM",
    remediation: "Do not call `torch.load()` on untrusted checkpoint files; it unpickles arbitrary Python objects and can execute code. Pass `weights_only=True` so only tensors are deserialised, and load checkpoints only from sources you control and have integrity-checked."
  },
  "B615": {
    description: "huggingface_unsafe_download",
    priority: "MEDIUM",
    remediation: "Pin Hugging Face model and dataset downloads to an immutable revision. Pass an explicit commit hash via the `revision` argument rather than a branch or tag name, so the artefact cannot be replaced after review."
  },

  // B7xx: Template and framework XSS
  "B701": {
    description: "jinja2_autoescape_false",
    priority: "HIGH",
    remediation: "Enable Django's CSRF protection. Use `@csrf_protect` decorator and include `{% csrf_token %}` in forms. Don't use `@csrf_exempt` unnecessarily."
  },
  "B702": {
    description: "use_of_mako_templates",
    priority: "MEDIUM",
    remediation: "Use Django's secure cookie settings. Set `SESSION_COOKIE_SECURE=True` and `CSRF_COOKIE_SECURE=True` for HTTPS-only cookie transmission."
  },
  "B703": {
    description: "django_mark_safe",
    priority: "MEDIUM",
    remediation: "Configure Django security settings. Set `DEBUG=False`, use `ALLOWED_HOSTS`, enable security middleware, and follow Django security best practices."
  },
  "B704": {
    description: "markupsafe_markup_xss",
    priority: "MEDIUM",
    remediation: "Do not wrap untrusted or dynamically built strings in `markupsafe.Markup()`, which marks them as safe and disables escaping, causing XSS. Let the template engine escape the value, or sanitise it before marking it safe."
  },
};
