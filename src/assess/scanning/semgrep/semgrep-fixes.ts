export const SemgrepFixes: Record<string, string> = {
  // ============================================================================
  // YAML - GitHub Actions Security
  // ============================================================================

  "yaml.github-actions.security.run-shell-injection.run-shell-injection": "Avoid using variable interpolation `${{...}}` with `github` context data directly in `run:` steps. Instead, use an intermediate environment variable with `env:` to store the data, then reference the environment variable in the script using double quotes: \"$ENVVAR\".",

  "yaml.github-actions.security.pull-request-target-code-checkout.pull-request-target-code-checkout": "When using `pull_request_target`, avoid checking out code from the incoming pull request as it runs with access to repository secrets. Either use `pull_request` trigger instead, or ensure no code from the incoming PR is executed (no build scripts, no dependency installation). See https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",

  "yaml.github-actions.security.allowed-unsecure-commands.allowed-unsecure-commands": "Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` from your workflow. This enables deprecated commands that can be exploited for command injection. Use environment files instead.",

  "yaml.github-actions.security.artifact-poisoning.artifact-poisoning": "Validate artifacts downloaded from other workflow runs. Artifacts can be poisoned by malicious PRs. Use artifact attestation or checksums to verify integrity.",

  // ============================================================================
  // Python Lang Security - General
  // ============================================================================

  "python.lang.security.dangerous-code-run.dangerous-code-run": "Replace `code.run()` with safer alternatives. Validate and sanitize all inputs if dynamic code execution is necessary. Consider using specific function calls or imports instead of dynamic execution.",

  "python.lang.security.dangerous-globals-use": "Avoid using `globals()` for dynamic variable access. Use explicit dictionaries or classes to manage dynamic data. If globals access is necessary, validate and sanitize all keys.",

  "python.lang.security.dangerous-os-exec": "Replace `os.exec*()` calls with `subprocess.run()` with `shell=False`. Pass arguments as a list and validate all inputs. Use absolute paths for executables.",

  "python.lang.security.dangerous-spawn-process": "Replace `os.spawn*()` calls with `subprocess.run()` with `shell=False`. Pass arguments as a list, validate inputs, and use absolute paths for executables.",

  "python.lang.security.dangerous-subinterpreters-run-string": "Avoid running arbitrary strings in subinterpreters. Validate and sanitize all code strings. Consider using pre-compiled modules or safe APIs instead.",

  "python.lang.security.dangerous-subprocess-use": "Use `subprocess.run()` with `shell=False` and pass arguments as a list. Validate all inputs and use absolute paths for executables. Avoid shell=True unless absolutely necessary.",

  "python.lang.security.dangerous-system-call": "Replace `os.system()` with `subprocess.run()` with `shell=False`. Pass arguments as a list, validate all inputs, and use `shlex.quote()` if shell usage is unavoidable.",

  "python.lang.security.dangerous-testcapi-run-in-subinterp": "Avoid using `_testcapi.run_in_subinterp()` in production code. This is intended for testing purposes only and can execute arbitrary code.",

  "python.lang.security.insecure-hash-algorithms-md5": "Replace MD5 with a secure hash algorithm like SHA-256 or SHA-3. Use `hashlib.sha256()` or `hashlib.sha3_256()` for cryptographic purposes.",

  "python.lang.security.insecure-hash-algorithms": "Replace weak hash algorithms (MD5, SHA1) with secure alternatives like SHA-256 or SHA-3. Use `hashlib.sha256()` for cryptographic hashing.",

  "python.lang.security.insecure-hash-function": "Replace insecure hash functions with cryptographically secure alternatives. Use `hashlib.sha256()` or stronger algorithms for security-sensitive operations.",

  "python.lang.security.insecure-uuid-version": "Use `uuid.uuid4()` for generating random UUIDs. Avoid `uuid1()` which exposes MAC address information. For security tokens, consider `secrets.token_hex()` instead.",

  "python.lang.security.unverified-ssl-context": "Create SSL contexts with proper certificate verification. Use `ssl.create_default_context()` which enables certificate verification by default. Never use `ssl._create_unverified_context()` in production.",

  "python.lang.security.use-defused-xml-parse": "Replace standard XML parsing with `defusedxml` to prevent XXE attacks. Use `defusedxml.ElementTree.parse()` instead of `xml.etree.ElementTree.parse()`.",

  "python.lang.security.use-defused-xml": "Replace `xml.etree` with `defusedxml.ElementTree` to prevent XML External Entity (XXE) attacks. Install defusedxml: `pip install defusedxml`.",

  "python.lang.security.use-defused-xmlrpc": "Replace `xmlrpc` with `defusedxml.xmlrpc` to prevent XXE attacks. Configure XML-RPC clients and servers to use safe parsing.",

  "python.lang.security.use-defusedcsv": "Use `defusedcsv` for parsing untrusted CSV files to prevent formula injection attacks. Install with `pip install defusedcsv`.",

  // ============================================================================
  // Python Lang Security - Audit
  // ============================================================================

  "python.lang.security.audit.conn_recv": "Validate data received from network connections. Deserialize with safe methods and validate the structure before use. Consider using message authentication.",

  "python.lang.security.audit.dangerous-annotations-usage": "Avoid using dangerous type annotations that could execute code during runtime. Use string annotations with `from __future__ import annotations`.",

  "python.lang.security.audit.dangerous-asyncio-create-exec-audit": "Use `asyncio.create_subprocess_exec()` with validated arguments. Pass arguments as separate parameters, not as a shell command string.",

  "python.lang.security.audit.dangerous-asyncio-create-exec-tainted-env-args": "Sanitize environment variables and arguments before passing to asyncio subprocess. Validate all user-controlled inputs.",

  "python.lang.security.audit.dangerous-asyncio-exec-audit": "Replace asyncio exec calls with safer subprocess methods. Validate all inputs and avoid shell execution.",

  "python.lang.security.audit.dangerous-asyncio-exec-tainted-env-args": "Sanitize tainted environment variables before passing to asyncio processes. Use allowlists for permitted values.",

  "python.lang.security.audit.dangerous-asyncio-shell-audit": "Avoid `asyncio.create_subprocess_shell()`. Use `asyncio.create_subprocess_exec()` with arguments as a list instead.",

  "python.lang.security.audit.dangerous-asyncio-shell-tainted-env-args": "Never pass user-controlled data to shell commands. Use `create_subprocess_exec()` with validated arguments.",

  "python.lang.security.audit.dangerous-code-run-audit": "Audit all uses of dynamic code execution. Ensure inputs are validated and consider safer alternatives.",

  "python.lang.security.audit.dangerous-code-run-tainted-env-args": "Never execute code with tainted environment variables or arguments. Validate and sanitize all inputs.",

  "python.lang.security.audit.dangerous-os-exec-audit": "Audit `os.exec*()` usage. Replace with `subprocess.run()` where possible and validate all arguments.",

  "python.lang.security.audit.dangerous-os-exec-tainted-env-args": "Sanitize environment variables before passing to os.exec functions. Use allowlists for permitted values.",

  "python.lang.security.audit.dangerous-spawn-process-audit": "Audit `os.spawn*()` usage. Consider using `subprocess.run()` with validated arguments instead.",

  "python.lang.security.audit.dangerous-spawn-process-tainted-env-args": "Sanitize tainted inputs before spawning processes. Validate environment variables and arguments.",

  "python.lang.security.audit.dangerous-subinterpreters-run-string-audit": "Audit subinterpreter string execution. Validate code strings and consider pre-compiled alternatives.",

  "python.lang.security.audit.dangerous-subinterpreters-run-string-tainted-env-args": "Never run tainted strings in subinterpreters. Validate all inputs thoroughly.",

  "python.lang.security.audit.dangerous-subprocess-use-audit": "Audit subprocess usage. Use `shell=False` and pass arguments as a list. Validate all inputs.",

  "python.lang.security.audit.dangerous-subprocess-use-tainted-env-args": "Sanitize tainted environment variables before subprocess calls. Never pass unsanitized user input to subprocesses.",

  "python.lang.security.audit.dangerous-system-call-audit": "Audit `os.system()` calls. Replace with `subprocess.run()` with `shell=False` and validated arguments.",

  "python.lang.security.audit.dangerous-system-call-tainted-env-args": "Never pass tainted data to system calls. Use subprocess with shell=False and validate all inputs.",

  "python.lang.security.audit.dangerous-testcapi-run-in-subinterp-audit": "Remove `_testcapi` usage from production code. This module is for CPython internal testing only.",

  "python.lang.security.audit.dangerous-testcapi-run-in-subinterp-tainted-env-args": "Never use `_testcapi` with tainted inputs. Remove from production code entirely.",

  "python.lang.security.audit.dynamic-urllib-use-detected": "Validate URLs before passing to urllib. Use allowlists for permitted domains and protocols. Consider using the `requests` library with proper validation.",

  "python.lang.security.audit.eval-detected": "Replace `eval()` with safer alternatives. Use `ast.literal_eval()` for parsing simple Python literals, or implement specific parsing logic for your use case.",

  "python.lang.security.audit.exec-detected": "Replace `exec()` with safer alternatives. Use specific function calls, imports, or data structures instead of dynamic code execution. Validate inputs if exec is unavoidable.",

  "python.lang.security.audit.formatted-sql-query": "Use parameterized queries instead of string formatting for SQL. Use database-specific parameter placeholders (`?`, `%s`, `:name`) to prevent SQL injection.",

  "python.lang.security.audit.hardcoded-password-default-argument": "Remove hardcoded password defaults from function parameters. Load passwords from environment variables using `os.environ.get()` or a secrets manager.",

  "python.lang.security.audit.httpsconnection-detected": "Ensure HTTPS connections verify SSL certificates. Use `ssl.create_default_context()` for proper certificate validation.",

  "python.lang.security.audit.insecure-file-permissions": "Set secure file permissions. Use specific octal values (e.g., `0o644` for files, `0o755` for directories) instead of overly permissive `0o777`.",

  "python.lang.security.audit.mako-templates-detected": "Sanitize all user inputs before rendering in Mako templates. Use `| h` filter for HTML escaping: `${user_input | h}`.",

  "python.lang.security.audit.marshal": "Replace `marshal` with safer serialization formats like JSON. Marshal can execute arbitrary code when loading untrusted data.",

  "python.lang.security.audit.md5-used-as-password": "Never use MD5 for password hashing. Use `bcrypt`, `argon2`, or `scrypt` via the `passlib` library for secure password storage.",

  "python.lang.security.audit.non-literal-import": "Avoid dynamic imports with user-controlled module names. Use allowlists for permitted modules or static imports.",

  "python.lang.security.audit.paramiko-implicit-trust-host-key": "Set explicit host key policy for Paramiko. Use `client.set_missing_host_key_policy(paramiko.RejectPolicy())` in production instead of `AutoAddPolicy`.",

  "python.lang.security.audit.python-reverse-shell": "Remove reverse shell code. This pattern is commonly used in malware. If this is for legitimate penetration testing, ensure proper authorization.",

  "python.lang.security.audit.regex-dos": "Avoid regex patterns vulnerable to ReDoS attacks. Use atomic groups, possessive quantifiers, or set timeouts. Consider using `google-re2` for untrusted patterns.",

  "python.lang.security.audit.sha224-hash": "Use SHA-256 or stronger instead of SHA-224 for security-sensitive applications. SHA-224 provides less security margin.",

  "python.lang.security.audit.ssl-wrap-socket-is-deprecated": "Replace `ssl.wrap_socket()` with `ssl.SSLContext.wrap_socket()`. Use `ssl.create_default_context()` for secure defaults.",

  "python.lang.security.audit.subprocess-list-passed-as-string": "Pass subprocess arguments as a list, not a string. Change `subprocess.run('cmd arg1 arg2')` to `subprocess.run(['cmd', 'arg1', 'arg2'])`.",

  "python.lang.security.audit.subprocess-shell-true": "Use `shell=False` in subprocess calls. Pass arguments as a list: `subprocess.run(['cmd', 'arg'], shell=False)` to prevent shell injection.",

  "python.lang.security.audit.system-wildcard-detected": "Avoid shell wildcards in system commands. Enumerate files explicitly using `glob.glob()` or `os.listdir()` and pass as a list to subprocess.",

  "python.lang.security.audit.telnetlib": "Replace `telnetlib` with encrypted alternatives. Use SSH via `paramiko` or secure APIs for remote connections.",

  "python.lang.security.audit.weak-ssl-version": "Use TLS 1.2 or higher. Set `ssl.PROTOCOL_TLS_CLIENT` or use `ssl.create_default_context()` which disables weak protocols by default.",

  // ============================================================================
  // Python Lang Security - Deserialization
  // ============================================================================

  "python.lang.security.deserialization.avoid-jsonpickle.avoid-jsonpickle": "Replace `jsonpickle` with standard `json` module for untrusted data. jsonpickle can execute arbitrary code during deserialization.",

  "python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load": "Replace `yaml.load()` with `yaml.safe_load()` to prevent arbitrary code execution. Use `yaml.safe_load()` for all untrusted YAML data.",

  "python.lang.security.deserialization.avoid-unsafe-ruamel.avoid-unsafe-ruamel": "Use `ruamel.yaml.YAML(typ='safe')` for loading untrusted YAML. The default loader can execute arbitrary code.",

  "python.lang.security.deserialization.pickle.avoid-pickle": "Replace `pickle` with safer serialization like JSON for untrusted data. If pickle is required, validate data sources and consider using `hmac` for integrity verification.",

  // ============================================================================
  // Python Cryptography Security
  // ============================================================================

  "python.cryptography.security.empty-aes-key": "Generate proper AES keys using `os.urandom(32)` for AES-256 or use `cryptography.fernet.Fernet.generate_key()`. Never use empty or hardcoded keys.",

  "python.cryptography.security.insecure-cipher-algorithms-arc4": "Replace RC4/ARC4 with AES-GCM. RC4 has known vulnerabilities and should not be used. Use `cryptography.hazmat.primitives.ciphers.algorithms.AES` with GCM mode.",

  "python.cryptography.security.insecure-cipher-algorithms-blowfish": "Replace Blowfish with AES-256. Blowfish has a small block size vulnerable to birthday attacks. Use AES with GCM mode for authenticated encryption.",

  "python.cryptography.security.insecure-cipher-algorithms": "Replace weak ciphers (DES, 3DES, RC4, Blowfish) with AES-256-GCM. Use the `cryptography` library with modern cipher suites.",

  "python.cryptography.security.insecure-cipher-mode-ecb": "Replace ECB mode with GCM, CTR, or CBC with proper IV. ECB mode reveals patterns in encrypted data. Use `modes.GCM()` for authenticated encryption.",

  "python.cryptography.security.insecure-hash-algorithms-md5": "Replace MD5 with SHA-256 or SHA-3 for cryptographic purposes. Use `hashlib.sha256()` or `hashlib.sha3_256()`.",

  "python.cryptography.security.insecure-hash-algorithms": "Replace weak hash algorithms (MD5, SHA1) with SHA-256 or SHA-3. Use `hashlib.sha256()` for security-sensitive hashing.",

  "python.cryptography.security.insufficient-dsa-key-size": "Use DSA keys of at least 2048 bits. Consider migrating to ECDSA or EdDSA for better performance and security.",

  "python.cryptography.security.insufficient-ec-key-size": "Use EC curves with at least 256 bits (P-256 or higher). Recommended: `SECP384R1` or `SECP521R1` for high-security applications.",

  "python.cryptography.security.insufficient-rsa-key-size": "Use RSA keys of at least 2048 bits, preferably 4096 bits for long-term security. Generate with `rsa.generate_private_key(public_exponent=65537, key_size=4096)`.",

  "python.cryptography.security.mode-without-authentication": "Use authenticated encryption modes like GCM or ChaCha20-Poly1305. Add authentication with `modes.GCM()` or use `cryptography.fernet.Fernet`.",

  // ============================================================================
  // Python Django Security
  // ============================================================================

  "python.django.security.django-no-csrf-token": "Add `{% csrf_token %}` to all POST forms. Ensure `django.middleware.csrf.CsrfViewMiddleware` is enabled in settings.",

  "python.django.security.django-using-request-post-after-is-valid": "Access form data through the cleaned form object after validation. Use `form.cleaned_data['field']` instead of `request.POST['field']`.",

  "python.django.security.globals-as-template-context": "Never pass `globals()` to template context. Create explicit context dictionaries with only required variables.",

  "python.django.security.hashids-with-django-secret": "Use a separate secret for Hashids, not `settings.SECRET_KEY`. Generate a dedicated secret: `hashids.Hashids(salt=settings.HASHIDS_SALT)`.",

  "python.django.security.locals-as-template-context": "Avoid passing `locals()` to templates. Create explicit context dictionaries to prevent exposing sensitive variables.",

  "python.django.security.nan-injection": "Validate numeric inputs before database queries. Check for NaN and Infinity values: `if math.isnan(value) or math.isinf(value): raise ValidationError()`.",

  "python.django.security.injection.sql.sql-injection-extra": "Use parameterized queries with Django ORM. Avoid `extra()` with raw SQL. Use `RawSQL()` with params or ORM query methods.",

  "python.django.security.injection.sql.sql-injection-rawsql": "Pass parameters separately to `RawSQL()`. Use: `RawSQL('SELECT * FROM t WHERE id=%s', [user_id])` instead of string formatting.",

  "python.django.security.injection.code.code-injection-os-system": "Replace `os.system()` with Django management commands or `subprocess.run()` with `shell=False`. Validate all inputs.",

  "python.django.security.injection.code.code-injection-subprocess": "Use `subprocess.run()` with `shell=False` and pass arguments as a list. Validate all user inputs before subprocess calls.",

  "python.django.security.injection.email.email-injection": "Sanitize email headers to prevent injection. Validate email addresses and strip newlines from subject and recipient fields.",

  "python.django.security.injection.path-traversal.path-traversal-open": "Validate file paths against a base directory. Use `os.path.realpath()` and verify the resolved path starts with the allowed directory.",

  "python.django.security.injection.ssrf.ssrf-injection-urllib": "Validate URLs against an allowlist of domains and protocols. Never pass user input directly to URL fetching functions.",

  "python.django.security.injection.ssrf.ssrf-injection-requests": "Validate URLs before making requests. Use domain allowlists and validate protocols. Consider using a URL validation library.",

  "python.django.security.audit.csrf-exempt": "Remove `@csrf_exempt` decorator unless absolutely necessary. Implement proper CSRF handling with tokens for all state-changing operations.",

  "python.django.security.audit.xss-send-mail-html-message": "Escape user input in HTML emails. Use `django.utils.html.escape()` or template autoescaping for user-provided content.",

  "python.django.security.audit.xss-template-response": "Enable template autoescaping. Use `{% autoescape on %}` or ensure user input is escaped with `{{ variable|escape }}`.",

  "python.django.security.audit.secure-cookies": "Set secure cookie flags. Configure `SESSION_COOKIE_SECURE=True`, `CSRF_COOKIE_SECURE=True`, and `SESSION_COOKIE_HTTPONLY=True` in production.",

  "python.django.security.passwords.password-empty-string": "Never use empty passwords. Implement proper password validation using Django's password validators and enforce minimum complexity requirements.",

  // ============================================================================
  // Python Flask Security
  // ============================================================================

  "python.flask.security.dangerous-template-string": "Use `render_template()` with separate template files instead of `render_template_string()`. If using string templates, never include user input in the template source.",

  "python.flask.security.flask-api-method-string-format": "Avoid string formatting in API responses. Use proper JSON serialization with `jsonify()` and validate all user inputs.",

  "python.flask.security.hashids-with-flask-secret": "Use a separate secret for Hashids. Generate a dedicated key: `hashids = Hashids(salt=app.config['HASHIDS_SALT'])` instead of using `app.secret_key`.",

  "python.flask.security.insecure-deserialization": "Replace insecure deserialization with JSON. Use `request.get_json()` for JSON data. Never unpickle user-provided data.",

  "python.flask.security.open-redirect": "Validate redirect URLs against an allowlist. Use `url_for()` for internal redirects. Check that redirect targets are within your domain.",

  "python.flask.security.secure-static-file-serve": "Use `send_from_directory()` with a fixed directory instead of `send_file()` with user input. Validate file paths to prevent directory traversal.",

  "python.flask.security.unescaped-template-extension": "Use `.html` extension for Jinja2 templates to enable autoescaping. Avoid `.txt`, `.xml`, or custom extensions without explicit escaping.",

  "python.flask.security.unsanitized-input": "Sanitize all user inputs before use. Use `markupsafe.escape()` for HTML output, and validate inputs against expected patterns.",

  "python.flask.security.audit.debug-enabled": "Disable debug mode in production. Set `app.debug = False` and use environment variables: `app.debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'`.",

  "python.flask.security.audit.hardcoded-config": "Move secrets to environment variables. Use `app.config.from_envvar()` or `os.environ.get()` for sensitive configuration values.",

  "python.flask.security.audit.secure-set-cookie": "Set secure cookie flags. Use `response.set_cookie(key, value, secure=True, httponly=True, samesite='Strict')` for sensitive cookies.",

  // ============================================================================
  // Python JWT Security
  // ============================================================================

  "python.jwt.security.jwt-exposed-credentials": "Never expose JWT secrets in code or responses. Store secrets in environment variables and use `os.environ.get('JWT_SECRET')`.",

  "python.jwt.security.jwt-hardcode": "Remove hardcoded JWT secrets. Use environment variables: `secret = os.environ.get('JWT_SECRET_KEY')`. Rotate secrets regularly.",

  "python.jwt.security.jwt-none-alg": "Never allow 'none' algorithm in JWT. Explicitly specify allowed algorithms: `jwt.decode(token, secret, algorithms=['HS256'])`.",

  "python.jwt.security.unverified-jwt-decode": "Always verify JWT signatures. Use `jwt.decode(token, secret, algorithms=['HS256'])` instead of `jwt.decode(token, options={'verify_signature': False})`.",

  // ============================================================================
  // Python SQLAlchemy Security
  // ============================================================================

  "python.sqlalchemy.security.sqlalchemy-execute-raw-query": "Use SQLAlchemy ORM methods or parameterized queries. Replace `execute('SELECT * FROM t WHERE id=' + user_id)` with `execute(text('SELECT * FROM t WHERE id=:id'), {'id': user_id})`.",

  "python.sqlalchemy.security.sqlalchemy-sql-injection": "Use parameterized queries with SQLAlchemy. Pass parameters separately: `session.execute(text('SELECT * FROM users WHERE id=:id'), {'id': user_id})`.",

  // ============================================================================
  // Python Requests Security
  // ============================================================================

  "python.requests.security.disabled-cert-validation": "Enable SSL certificate verification. Remove `verify=False` from requests calls. Use `verify=True` or specify a CA bundle path.",

  "python.requests.security.no-auth-over-http": "Use HTTPS for authenticated requests. Change `http://` to `https://` and ensure certificates are verified.",

  // ============================================================================
  // Python Boto3/AWS Security
  // ============================================================================

  "python.boto3.security.hardcoded-access-token": "Remove hardcoded AWS credentials. Use IAM roles, environment variables, or AWS credentials file. Never commit credentials to source control.",

  "python.aws-lambda.security.dangerous-spawn-process": "Avoid spawning processes in Lambda. Use Lambda layers or SDK calls instead. If subprocess is required, validate all inputs.",

  "python.aws-lambda.security.dangerous-subprocess-shell": "Use `shell=False` in Lambda subprocess calls. Pass arguments as a list and validate all inputs.",

  // ============================================================================
  // JavaScript/TypeScript Security
  // ============================================================================

  "javascript.lang.security.detect-buffer-noassert": "Remove `noAssert` parameter from Buffer methods. Use explicit bounds checking: validate offset and length before buffer operations.",

  "javascript.lang.security.detect-child-process": "Use `child_process.execFile()` or `spawn()` with `shell: false`. Validate all arguments and use absolute paths for executables.",

  "javascript.lang.security.detect-disable-mustache-escape": "Never disable Mustache HTML escaping. Remove `Mustache.escape = ...` and use default escaping. For trusted HTML, use triple braces with caution.",

  "javascript.lang.security.detect-eval-with-expression": "Replace `eval()` with safer alternatives. Use `JSON.parse()` for JSON data, or implement specific parsing logic. Consider using a sandboxed environment.",

  "javascript.lang.security.detect-insecure-websocket": "Use secure WebSocket connections (`wss://`). Replace `new WebSocket('ws://...')` with `new WebSocket('wss://...')` and validate server certificates.",

  "javascript.lang.security.detect-no-csrf-before-method-override": "Load CSRF middleware before method-override. Ensure `app.use(csrf())` comes before `app.use(methodOverride())` in Express.",

  "javascript.lang.security.detect-pseudoRandomBytes": "Replace `pseudoRandomBytes` with `crypto.randomBytes()`. Use synchronous version only when necessary: `crypto.randomBytes(32)`.",

  "javascript.lang.security.html-in-template-string": "Escape HTML in template strings. Use a templating library with autoescaping or manually escape with a function like `escapeHtml()`.",

  "javascript.lang.security.insecure-object-assign": "Validate source objects before `Object.assign()`. Check for prototype pollution by validating keys: `if (key === '__proto__' || key === 'constructor') return;`.",

  "javascript.lang.security.spawn-git-clone": "Validate repository URLs before git clone. Use allowlists for permitted hosts and sanitize branch names. Avoid user-controlled URLs.",

  "javascript.lang.security.audit.code-string-concat": "Avoid concatenating user input into code strings. Use parameterized templates or safe alternatives to dynamic code generation.",

  "javascript.lang.security.audit.dangerous-spawn-shell": "Use `spawn()` with `shell: false`. Pass arguments as an array: `spawn('cmd', ['arg1', 'arg2'], { shell: false })`.",

  "javascript.lang.security.audit.detect-non-literal-fs-filename": "Validate file paths before filesystem operations. Use `path.resolve()` and verify paths are within allowed directories to prevent path traversal.",

  "javascript.lang.security.audit.detect-non-literal-regexp": "Validate regex patterns before creating RegExp objects. Use a timeout or safe-regex library to prevent ReDoS attacks.",

  "javascript.lang.security.audit.detect-non-literal-require": "Avoid dynamic `require()` with user input. Use allowlists for permitted modules or static imports.",

  "javascript.lang.security.audit.detect-redos": "Avoid regex patterns vulnerable to ReDoS. Use atomic groups, possessive quantifiers, or the `safe-regex` library to validate patterns.",

  "javascript.lang.security.audit.hardcoded-hmac-key": "Move HMAC keys to environment variables. Use `process.env.HMAC_KEY` instead of hardcoded strings. Rotate keys regularly.",

  "javascript.lang.security.audit.incomplete-sanitization": "Use comprehensive sanitization. Replace single `replace()` with `replaceAll()` or global regex: `str.replace(/[<>]/g, '')`.",

  "javascript.lang.security.audit.md5-used-as-password": "Never use MD5 for passwords. Use `bcrypt`, `scrypt`, or `argon2` via libraries like `bcryptjs` for secure password hashing.",

  "javascript.lang.security.audit.spawn-shell-true": "Use `shell: false` in spawn options. Pass arguments as an array and validate all inputs to prevent command injection.",

  "javascript.lang.security.audit.unknown-value-with-script-tag": "Escape dynamic content in script tags. Use JSON.stringify with proper escaping or Content Security Policy to prevent XSS.",

  "javascript.lang.security.audit.unsafe-dynamic-method": "Avoid dynamic method calls with user input. Validate method names against an allowlist before calling.",

  "javascript.lang.security.audit.unsafe-formatstring": "Avoid format strings with user input. Use template literals with proper escaping or parameterized logging.",

  "typescript.lang.security.audit.cors-regex-wildcard": "Avoid regex wildcards in CORS origin validation. Use explicit origin allowlists: `if (allowedOrigins.includes(origin)) { ... }`.",

  // ============================================================================
  // Generic/Multi-language Rules
  // ============================================================================

  "generic.secrets.security.detected-aws-access-key-id": "Remove AWS access key from code. Use IAM roles, environment variables, or AWS Secrets Manager. Add credentials to .gitignore.",

  "generic.secrets.security.detected-aws-secret-access-key": "Remove AWS secret key from code. Use IAM roles or AWS credentials chain. Never commit secrets to source control.",

  "generic.secrets.security.detected-private-key": "Remove private keys from code. Store in secure key management systems and load from environment variables or secure files.",

  "generic.secrets.security.detected-generic-api-key": "Remove API keys from code. Use environment variables: `api_key = os.environ.get('API_KEY')` and add to .gitignore.",

  "generic.secrets.security.detected-jwt-token": "Remove JWT tokens from code. Generate tokens dynamically and store in secure session storage.",

  "generic.secrets.security.detected-password": "Remove hardcoded passwords. Use environment variables, secrets managers, or secure configuration files. Add to .gitignore.",

  "generic.secrets.security.detected-slack-token": "Remove Slack tokens from code. Use environment variables and Slack's OAuth flow for token management.",

  "generic.secrets.security.detected-github-token": "Remove GitHub tokens from code. Use environment variables or GitHub Apps for authentication. Rotate compromised tokens immediately.",

  "generic.ci.security.audit.script-injection": "Avoid script injection in CI pipelines. Validate inputs and use parameterized commands. Never interpolate untrusted data into scripts.",

  // ============================================================================
  // Go Security
  // ============================================================================

  "go.lang.security.audit.dangerous-exec-command": "Use `exec.Command()` with separate arguments. Validate all inputs and use absolute paths. Avoid shell execution.",

  "go.lang.security.audit.sqli.string-concat-sqli": "Use parameterized queries. Replace string concatenation with `db.Query(\"SELECT * FROM users WHERE id = $1\", userID)`.",

  "go.lang.security.audit.xss.template-xss": "Use `html/template` for HTML output, not `text/template`. Ensure autoescaping is enabled for user-provided content.",

  "go.lang.security.audit.crypto.weak-crypto": "Replace weak cryptographic algorithms. Use AES-GCM for encryption and SHA-256 for hashing. Avoid MD5, SHA1, DES, and RC4.",

  "go.lang.security.audit.crypto.insecure-tls": "Set minimum TLS version to 1.2. Configure: `tls.Config{MinVersion: tls.VersionTLS12}` and use strong cipher suites.",

  "go.lang.security.audit.net.unvalidated-redirect": "Validate redirect URLs. Use allowlists for permitted domains and verify URLs are relative or within your domain.",

  "go.lang.security.audit.path-traversal": "Validate file paths. Use `filepath.Clean()` and verify the cleaned path is within allowed directories.",

  // ============================================================================
  // Java Security
  // ============================================================================

  "java.lang.security.audit.sqli.jdbc-sqli": "Use PreparedStatement with parameterized queries. Replace string concatenation with: `PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); ps.setInt(1, userId);`.",

  "java.lang.security.audit.xss.servlet-xss": "Encode output to prevent XSS. Use `org.owasp.encoder.Encode.forHtml()` for HTML context. Enable Content-Security-Policy headers.",

  "java.lang.security.audit.crypto.weak-hash": "Replace weak hash algorithms. Use `MessageDigest.getInstance(\"SHA-256\")` instead of MD5 or SHA1.",

  "java.lang.security.audit.crypto.weak-cipher": "Replace weak ciphers with AES-GCM. Use `Cipher.getInstance(\"AES/GCM/NoPadding\")` with proper key sizes.",

  "java.lang.security.audit.deserialization.object-deserialization": "Avoid Java deserialization of untrusted data. Use JSON with type validation or implement `ObjectInputFilter` for necessary cases.",

  "java.lang.security.audit.command-injection.runtime-exec": "Use ProcessBuilder with argument list. Validate inputs and avoid shell execution: `new ProcessBuilder(\"cmd\", \"arg1\", \"arg2\").start()`.",

  "java.lang.security.audit.xxe.documentbuilderfactory-xxe": "Disable external entities in DocumentBuilderFactory. Set: `factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`.",

  "java.lang.security.audit.ssrf.httpclient-ssrf": "Validate URLs before HTTP requests. Use allowlists for permitted domains and protocols. Never pass user input directly to HTTP clients.",

  "java.lang.security.audit.path-traversal.file-path-traversal": "Validate file paths. Use `Paths.get(basePath).resolve(userPath).normalize()` and verify the result is within the base directory.",

  // ============================================================================
  // Ruby Security
  // ============================================================================

  "ruby.lang.security.audit.dangerous-exec": "Use parameterized commands with `system()`. Pass arguments as array: `system('cmd', 'arg1', 'arg2')` instead of shell strings.",

  "ruby.lang.security.audit.sqli.string-concat-sqli": "Use parameterized queries. Replace string interpolation with: `User.where('id = ?', user_id)` or `User.where(id: user_id)`.",

  "ruby.lang.security.audit.xss.erb-xss": "Use `<%=h ... %>` or `<%= sanitize(...) %>` for user content. Enable default escaping in Rails applications.",

  "ruby.lang.security.audit.deserialization.marshal-load": "Avoid `Marshal.load()` on untrusted data. Use JSON or implement signature verification for marshaled data.",

  "ruby.lang.security.audit.eval-injection": "Replace `eval()` with safer alternatives. Use specific parsing methods or sandboxed environments for dynamic code needs.",

  // ============================================================================
  // PHP Security
  // ============================================================================

  "php.lang.security.audit.sqli.string-concat-sqli": "Use prepared statements with PDO. Replace concatenation with: `$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);`.",

  "php.lang.security.audit.xss.echo-xss": "Escape output with `htmlspecialchars($data, ENT_QUOTES, 'UTF-8')`. Use templating engines with autoescaping enabled.",

  "php.lang.security.audit.dangerous-exec": "Use `escapeshellarg()` for arguments and `escapeshellcmd()` for commands. Prefer `proc_open()` with arguments array.",

  "php.lang.security.audit.file-inclusion": "Validate file paths against an allowlist. Never include files based on user input. Use absolute paths and verify file existence.",

  "php.lang.security.audit.deserialization.unserialize": "Avoid `unserialize()` on user data. Use JSON with `json_decode()` or implement signature verification.",

  // ============================================================================
  // C# Security
  // ============================================================================

  "csharp.lang.security.audit.sqli.string-concat-sqli": "Use parameterized queries. Replace string concatenation with `SqlCommand cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id\"); cmd.Parameters.AddWithValue(\"@id\", userId);`.",

  "csharp.lang.security.audit.xss.razor-xss": "Use `@Html.Encode()` or `@Html.Raw()` only for trusted content. Enable request validation and output encoding.",

  "csharp.lang.security.audit.dangerous-process-start": "Validate all inputs to `Process.Start()`. Use `UseShellExecute = false` and pass arguments separately.",

  "csharp.lang.security.audit.deserialization.binaryformatter": "Replace `BinaryFormatter` with secure serializers. Use `System.Text.Json` or `XmlSerializer` with type restrictions.",

  "csharp.lang.security.audit.xxe.xmldocument-xxe": "Disable DTD processing: `XmlDocument doc = new XmlDocument(); doc.XmlResolver = null;` before loading untrusted XML.",

  "csharp.lang.security.audit.path-traversal": "Validate paths with `Path.GetFullPath()` and ensure they're within allowed directories. Check for `..` sequences.",

  "csharp.lang.security.cryptography.weak-hashing-algorithm": "Replace MD5/SHA1 with SHA256 or SHA512. Use `SHA256.Create()` for hashing sensitive data.",

  "csharp.lang.security.cryptography.weak-cipher-algorithm": "Replace DES/3DES with AES. Use `Aes.Create()` with key sizes of 256 bits and GCM mode when available.",

  // ============================================================================
  // Rust Security
  // ============================================================================

  "rust.lang.security.audit.dangerous-command": "Use `Command::new()` with `arg()` method for each argument. Avoid shell execution and validate all inputs.",

  "rust.lang.security.audit.sqli.string-concat-sqli": "Use parameterized queries. With sqlx: `sqlx::query!(\"SELECT * FROM users WHERE id = $1\", id)`. Never concatenate user input.",

  "rust.lang.security.audit.path-traversal": "Validate paths with `canonicalize()` and verify they're within allowed directories. Check for path traversal attempts.",

  "rust.lang.security.audit.unsafe-block": "Minimize `unsafe` blocks. Document safety invariants and consider safe abstractions. Review all unsafe code carefully.",

  // ============================================================================
  // Kotlin Security
  // ============================================================================

  "kotlin.lang.security.audit.sqli.string-concat-sqli": "Use parameterized queries. Replace string templates with prepared statements or ORM parameterized methods.",

  "kotlin.lang.security.audit.dangerous-exec": "Use ProcessBuilder with arguments list. Validate inputs and avoid shell command execution.",

  "kotlin.lang.security.audit.insecure-random": "Replace `java.util.Random` with `java.security.SecureRandom` for security-sensitive random number generation.",

  // ============================================================================
  // Swift Security
  // ============================================================================

  "swift.lang.security.audit.sqli.string-concat-sqli": "Use parameterized queries with your database library. Never interpolate user input into SQL strings.",

  "swift.lang.security.audit.insecure-transport": "Use HTTPS for all network requests. Configure ATS (App Transport Security) to require secure connections.",

  "swift.lang.security.audit.hardcoded-credentials": "Remove hardcoded credentials. Use Keychain for secure storage and environment configuration for API keys.",

  // ============================================================================
  // Scala Security
  // ============================================================================

  "scala.lang.security.audit.sqli.string-concat-sqli": "Use parameterized queries. With Slick: `sql\"SELECT * FROM users WHERE id = $id\".as[User]`. Avoid string interpolation.",

  "scala.lang.security.audit.dangerous-exec": "Use `ProcessBuilder` with arguments list. Avoid shell strings and validate all inputs to external processes.",

  "scala.lang.security.audit.deserialization.java-serialization": "Avoid Java serialization. Use JSON with circe or Play JSON. If required, implement custom serialization with validation.",
};
