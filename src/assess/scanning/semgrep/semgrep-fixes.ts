import type { Remediation } from '../remediation/types.js';

export const SemgrepFixes: Record<string, Omit<Remediation, 'id'>> = {
  // ==== C ====
  "c.lang.security.insecure-use-gets-fn.insecure-use-gets-fn": {
    priority: "HIGH",
    intent: "Replace `gets()` with `fgets()` or `gets_s()`, passing an explicit buffer size. `gets()` performs no bounds checking and will overflow the destination buffer on any input longer than it."
  },
  "c.lang.security.insecure-use-scanf-fn.insecure-use-scanf-fn": {
    priority: "HIGH",
    intent: "Avoid bare `scanf()` for string input. Use `fgets()` to read into a sized buffer, or give every `%s` conversion an explicit field width (e.g. `%31s` for a 32-byte buffer) so the write cannot exceed it."
  },
  "c.lang.security.insecure-use-strtok-fn.insecure-use-strtok-fn": {
    priority: "HIGH",
    intent: "Replace `strtok()` with `strtok_r()`. `strtok()` keeps parser state in a static buffer, so it is not reentrant or thread-safe, and it destructively overwrites the delimiters in the input string."
  },
  "c.lang.security.random-fd-exhaustion.random-fd-exhaustion": {
    priority: "HIGH",
    intent: "Check the return value of every `read()` call and handle short reads and errors. For random bytes, prefer `getrandom()`, which needs no file descriptor and cannot fail because the descriptor table is exhausted."
  },

  // ==== Clojure ====
  "clojure.lang.security.documentbuilderfactory-xxe.documentbuilderfactory-xxe": {
    priority: "HIGH",
    intent: "Disable DOCTYPE processing on the XML parser factory before parsing untrusted input. Set the `http://apache.org/xml/features/disallow-doctype-decl` feature to true, or disable external general and parameter entities, to prevent XML external entity (XXE) attacks."
  },
  "clojure.lang.security.use-of-md5.use-of-md5": {
    priority: "HIGH",
    intent: "Replace MD5 with SHA-256 or SHA-3 for integrity and signature use. For password storage use a dedicated password hash such as bcrypt, scrypt or Argon2 rather than any general-purpose hash."
  },
  "clojure.lang.security.use-of-sha1.use-of-sha1": {
    priority: "HIGH",
    intent: "Replace SHA-1 with SHA-256 or SHA-3. SHA-1 is not collision resistant and is unsuitable for signatures or any integrity check that an attacker could influence."
  },

  // ==== C# ====
  "csharp.lang.security.injections.os-command.os-command-injection": {
    priority: "HIGH",
    intent: "Do not build shell command strings from user input. Pass the executable and each argument separately via `ProcessStartInfo.ArgumentList`, leave `UseShellExecute` false, and validate any user-supplied value against an allowlist."
  },
  "csharp.lang.security.insecure-deserialization.binary-formatter.insecure-binaryformatter-deserialization": {
    priority: "HIGH",
    intent: "Stop using `BinaryFormatter`; it can instantiate arbitrary types during deserialization and is unfixable by configuration. Move to a contract-based serializer such as `System.Text.Json`, `DataContractSerializer` or protobuf, and reject payloads that carry their own type information."
  },
  "csharp.lang.security.insecure-deserialization.data-contract-resolver.data-contract-resolver": {
    priority: "HIGH",
    intent: "Restrict which types a custom `DataContractResolver` will resolve to an explicit allowlist. Returning arbitrary attacker-named types lets a crafted payload construct dangerous objects during deserialization."
  },
  "csharp.lang.security.insecure-deserialization.fast-json.insecure-fastjson-deserialization": {
    priority: "HIGH",
    intent: "Disable fastJSON's `$type` handling for untrusted input by setting `BadListTypeChecking` or turning off type extension. Deserialize into a known concrete type instead of letting the payload choose the type."
  },
  "csharp.lang.security.insecure-deserialization.fs-pickler.insecure-fspickler-deserialization": {
    priority: "HIGH",
    intent: "Do not use `FsPickler` on untrusted data. Its default configuration will deserialize arbitrary types and can execute code; use a contract-based serializer with an explicit type allowlist instead."
  },
  "csharp.lang.security.insecure-deserialization.insecure-typefilterlevel-full.insecure-typefilterlevel-full": {
    priority: "HIGH",
    intent: "Do not expose .NET Remoting endpoints. `TypeFilterLevel.Full` permits full deserialization and remote code execution, and `Low` is not a reliable defence either. Migrate the endpoint to WCF or an HTTP API with a contract-based serializer."
  },
  "csharp.lang.security.insecure-deserialization.los-formatter.insecure-losformatter-deserialization": {
    priority: "HIGH",
    intent: "Stop using `LosFormatter`, which deserializes arbitrary types and enables remote code execution. Replace it with a contract-based serializer, and protect ASP.NET view state with `ViewStateUserKey` and MAC validation."
  },
  "csharp.lang.security.insecure-deserialization.net-data-contract.insecure-netdatacontract-deserialization": {
    priority: "HIGH",
    intent: "Replace `NetDataContractSerializer` with `DataContractSerializer`. `NetDataContractSerializer` reads .NET type names from the payload, letting an attacker choose which types get constructed."
  },
  "csharp.lang.security.insecure-deserialization.newtonsoft.insecure-newtonsoft-deserialization": {
    priority: "HIGH",
    intent: "Set `TypeNameHandling` to `None` for untrusted JSON. If polymorphic deserialization is genuinely required, supply a custom `SerializationBinder` that resolves only an explicit allowlist of expected types."
  },
  "csharp.lang.security.insecure-deserialization.soap-formatter.insecure-soapformatter-deserialization": {
    priority: "HIGH",
    intent: "Stop using `SoapFormatter`; it constructs arbitrary types named in the payload. Use a contract-based serializer such as `DataContractSerializer` or `System.Text.Json` with a known target type."
  },
  "csharp.lang.security.sqli.csharp-sqli.csharp-sqli": {
    priority: "HIGH",
    intent: "Replace the interpolated or concatenated SQL string with a parameterised command. Use placeholders in the SQL text and bind each value through `SqlCommand.Parameters.Add`, or use an ORM's parameterised query API."
  },

  // ==== Docker ====
  "dockerfile.audit.dockerfile-pip-extra-index-url.dockerfile-pip-extra-index-url": {
    priority: "HIGH",
    intent: "Replace `--extra-index-url` with `--index-url` so only the intended index is consulted. With `--extra-index-url`, pip also searches PyPI and will install a public package that shadows your private package name, which is a dependency-confusion attack."
  },
  "dockerfile.security.dockerd-socket-mount.dockerfile-dockerd-socket-mount": {
    priority: "HIGH",
    intent: "Do not mount `/var/run/docker.sock` into the container. Access to the daemon socket is equivalent to root on the host, so any code execution inside the container becomes a host compromise. Use a scoped API proxy or a rootless build backend instead."
  },

  // ==== Generic - secrets and CI ====
  "generic.ci.security.bash-reverse-shell.bash_reverse_shell": {
    priority: "HIGH",
    intent: "Remove this reverse shell. A pipeline step that opens an outbound interactive shell exfiltrates build credentials and is almost never legitimate; if it was added for debugging, delete it and rotate any secrets the job could reach."
  },
  "generic.secrets.security.detected-amazon-mws-auth-token.detected-amazon-mws-auth-token": {
    priority: "HIGH",
    intent: "Remove the hardcoded Amazon MWS auth token and rotate it, since committed values must be treated as compromised. Load it at runtime from a secrets manager or an environment variable, and add the file to `.gitignore` if it holds local configuration."
  },
  "generic.secrets.security.detected-artifactory-password.detected-artifactory-password": {
    priority: "HIGH",
    intent: "Remove the hardcoded Artifactory password and rotate it. Supply the credential at runtime from a secrets manager or environment variable, and use a scoped deploy token rather than an account password."
  },
  "generic.secrets.security.detected-artifactory-token.detected-artifactory-token": {
    priority: "HIGH",
    intent: "Remove the hardcoded Artifactory token and revoke it, since a committed token must be treated as compromised. Inject it at runtime from a secrets manager or environment variable."
  },
  "generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value": {
    priority: "HIGH",
    intent: "Remove the hardcoded AWS access key ID and deactivate the key pair. Use an IAM role for the compute platform instead of long-lived keys; where keys are unavoidable, read them from the environment or a secrets manager."
  },
  "generic.secrets.security.detected-aws-appsync-graphql-key.detected-aws-appsync-graphql-key": {
    priority: "HIGH",
    intent: "Remove the hardcoded AppSync API key and rotate it. Prefer IAM or Cognito authorization for AppSync over API keys, and inject any remaining key at runtime from a secrets manager."
  },
  "generic.secrets.security.detected-aws-secret-access-key.detected-aws-secret-access-key": {
    priority: "HIGH",
    intent: "Remove AWS secret key from code. Use IAM roles or AWS credentials chain. Never commit secrets to source control."
  },
  "generic.secrets.security.detected-aws-session-token.detected-aws-session-token": {
    priority: "HIGH",
    intent: "Remove the hardcoded AWS session token. Session tokens are short-lived credentials that should never be written to source; obtain them at runtime from the instance or container credential provider, or from an assumed role."
  },
  "generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash": {
    priority: "HIGH",
    intent: "Remove the bcrypt hash from source. Even hashed credentials are crackable offline once committed, so treat the underlying password as compromised, reset it, and store password hashes in the database rather than in code."
  },
  "generic.secrets.security.detected-codeclimate.detected-codeclimate": {
    priority: "HIGH",
    intent: "Remove the hardcoded CodeClimate reporter token and rotate it. Provide it to the CI job as a masked secret environment variable instead of committing it."
  },
  "generic.secrets.security.detected-generic-api-key.detected-generic-api-key": {
    priority: "MEDIUM",
    intent: "Remove API keys from code. Use environment variables: `api_key = os.environ.get('API_KEY')` and add to .gitignore."
  },
  "generic.secrets.security.detected-github-token.detected-github-token": {
    priority: "MEDIUM",
    intent: "Remove GitHub tokens from code. Use environment variables or GitHub Apps for authentication. Rotate compromised tokens immediately."
  },
  "generic.secrets.security.detected-jwt-token.detected-jwt-token": {
    priority: "MEDIUM",
    intent: "Remove JWT tokens from code. Generate tokens dynamically and store in secure session storage."
  },
  "generic.secrets.security.detected-onfido-live-api-token.detected-onfido-live-api-token": {
    priority: "HIGH",
    intent: "Remove the hardcoded Onfido live API token and rotate it immediately, since it grants access to production identity data. Load it at runtime from a secrets manager."
  },
  "generic.secrets.security.detected-private-key.detected-private-key": {
    priority: "MEDIUM",
    intent: "Remove private keys from code. Store in secure key management systems and load from environment variables or secure files."
  },
  "generic.secrets.security.detected-slack-token.detected-slack-token": {
    priority: "MEDIUM",
    intent: "Remove Slack tokens from code. Use environment variables and Slack's OAuth flow for token management."
  },
  "generic.secrets.security.google-maps-apikeyleak.google-maps-apikeyleak": {
    priority: "HIGH",
    intent: "Remove the hardcoded Google Maps API key and rotate it. Restrict the replacement key by HTTP referrer, IP or app identity and to the specific APIs it needs, so a leaked key cannot be billed against your project."
  },
  "generic.unicode.security.bidi.contains-bidirectional-characters": {
    priority: "HIGH",
    intent: "Remove the Unicode bidirectional control characters. They change how the code is displayed without changing what it executes, so reviewed code can differ from executed code (the 'Trojan Source' attack, CVE-2021-42574). If right-to-left text is genuinely needed, use escape sequences so the characters are visible in review."
  },

  // ==== Go ====
  "go.lang.security.audit.dangerous-command-write.dangerous-command-write": {
    priority: "HIGH",
    intent: "Do not write unvalidated user input to a command's stdin where it will be interpreted. Validate the input against an allowlist, or pass data as explicit arguments to a fixed executable rather than as shell input."
  },
  "go.lang.security.audit.dangerous-exec-cmd.dangerous-exec-cmd": {
    priority: "HIGH",
    intent: "Keep the command name static and pass user input only as separate arguments to `exec.Command`. Never build the command or its arguments by string concatenation, and avoid invoking a shell (`sh -c`) at all."
  },
  "go.lang.security.audit.dangerous-exec-command.dangerous-exec-command": {
    priority: "HIGH",
    intent: "Use `exec.Command()` with separate arguments. Validate all inputs and use absolute paths. Avoid shell execution."
  },
  "go.lang.security.audit.dangerous-syscall-exec.dangerous-syscall-exec": {
    priority: "HIGH",
    intent: "Keep the path passed to `syscall.Exec` static and validate any user-controlled argument against an allowlist. Building the executable path or argument vector from user input allows arbitrary command execution."
  },
  "go.lang.security.audit.database.string-formatted-query.string-formatted-query": {
    priority: "HIGH",
    intent: "Replace the formatted SQL string with a parameterised query. Use `?` or `$1` placeholders and pass values as arguments to `Query`, `QueryRow` or `Exec` so the driver binds them."
  },
  "go.lang.security.audit.sqli.gosql-sqli.gosql-sqli": {
    priority: "HIGH",
    intent: "Replace the concatenated SQL with placeholders and pass the values as arguments to the `database/sql` call. Only literal SQL should be built in code; user data must always be bound as a parameter."
  },
  "go.lang.security.audit.sqli.pg-orm-sqli.pg-orm-sqli": {
    priority: "HIGH",
    intent: "Use go-pg's parameterised placeholders (`?`) and pass the values as arguments rather than concatenating them into the ORM query string."
  },
  "go.lang.security.audit.sqli.pg-sqli.pg-sqli": {
    priority: "HIGH",
    intent: "Use go-pg's `?` placeholders and pass each value as an argument instead of concatenating user input into the SQL string."
  },
  "go.lang.security.audit.sqli.pgx-sqli.pgx-sqli": {
    priority: "HIGH",
    intent: "Use pgx's `$1`-style placeholders and pass the values as arguments to `Query` or `Exec`, rather than concatenating user input into the SQL string."
  },
  "go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface": {
    priority: "HIGH",
    intent: "Deserialize into a concrete struct with the fields you expect rather than into `interface{}` or `map[string]interface{}`. An open target type lets the payload dictate the shape of the data and defeats validation."
  },
  "go.otto.security.audit.dangerous-execution.dangerous-execution": {
    priority: "HIGH",
    intent: "Do not pass user-controlled script text to the otto VM. Expose a fixed set of Go functions to the script instead, and if scripts must be dynamic, restrict them to a reviewed set held server-side rather than supplied by the caller."
  },

  // ==== Java ====
  "java.aws-lambda.security.tainted-sql-string.tainted-sql-string": {
    priority: "HIGH",
    intent: "Do not build SQL from the Lambda event payload. Use a `PreparedStatement` with `?` placeholders and bind each event-derived value as a parameter."
  },
  "java.aws-lambda.security.tainted-sqli.tainted-sqli": {
    priority: "HIGH",
    intent: "Do not interpolate Lambda event data into the SQL statement. Use a `PreparedStatement` with `?` placeholders and bind each event field as a parameter, validating it against an allowlist first if it must name a column or table."
  },
  "java.java-jwt.security.audit.jwt-decode-without-verify.java-jwt-decode-without-verify": {
    priority: "HIGH",
    intent: "Verify the JWT before reading its claims. Build a verifier with the expected algorithm, key, issuer and audience and call `verify()`, rather than using `decode()`, which parses the token without checking its signature."
  },
  "java.jboss.security.session_sqli.find-sql-string-concatenation": {
    priority: "HIGH",
    intent: "Replace the concatenated or formatted SQL string with a parameterised query. Bind every user-supplied value as a parameter (`?` placeholders with `PreparedStatement`, or named parameters in the ORM) so the value can never be parsed as SQL."
  },
  "java.lang.security.audit.anonymous-ldap-bind.anonymous-ldap-bind": {
    priority: "HIGH",
    intent: "Require authentication for the LDAP connection. Set the security principal and credentials rather than binding anonymously, and use LDAPS or StartTLS so those credentials are not sent in clear text."
  },
  "java.lang.security.audit.command-injection-formatted-runtime-call.command-injection-formatted-runtime-call": {
    priority: "HIGH",
    intent: "Do not pass a formatted or concatenated string to `Runtime.exec`. Use the array form so the executable and each argument are separate, keep the executable static, and validate user-supplied arguments against an allowlist."
  },
  "java.lang.security.audit.command-injection-process-builder.command-injection-process-builder": {
    priority: "HIGH",
    intent: "Pass the command and each argument as separate list elements to `ProcessBuilder` rather than building one string. Keep the executable static and avoid invoking a shell."
  },
  "java.lang.security.audit.el-injection.el-injection": {
    priority: "HIGH",
    intent: "Do not build Expression Language expressions from dynamic values. Keep the expression text static and pass user data in as bound variables, or validate the value against an allowlist before use."
  },
  "java.lang.security.audit.java-reverse-shell.java-reverse-shell": {
    priority: "HIGH",
    intent: "Remove this reverse shell. Code that opens an outbound socket and wires it to a shell process is almost never legitimate; if it was added for debugging, delete it and rotate any credentials the process could reach."
  },
  "java.lang.security.audit.jdbc-sql-formatted-string.jdbc-sql-formatted-string": {
    priority: "HIGH",
    intent: "Use the parameterised form of the JDBC template call: pass the SQL with `?` placeholders and supply the values as a separate argument array, rather than formatting them into the query string."
  },
  "java.lang.security.audit.ldap-entry-poisoning.ldap-entry-poisoning": {
    priority: "HIGH",
    intent: "Disable object deserialization from LDAP search results by setting the search controls' `returningObjFlag` to false. An attacker-controlled directory entry can otherwise return a serialized object and achieve code execution."
  },
  "java.lang.security.audit.ldap-injection.ldap-injection": {
    priority: "HIGH",
    intent: "Escape or validate user input before placing it in an LDAP filter. Use a filter with placeholder arguments, or encode the value per RFC 4515, so it cannot alter the filter's structure."
  },
  "java.lang.security.audit.object-deserialization.object-deserialization": {
    priority: "HIGH",
    intent: "Do not deserialize untrusted data with `ObjectInputStream`. Use a data-only format such as JSON with a known target type, or install an `ObjectInputFilter` that allowlists the exact classes expected."
  },
  "java.lang.security.audit.sqli.hibernate-sqli.hibernate-sqli": {
    priority: "HIGH",
    intent: "Use Hibernate's named or positional query parameters (`setParameter`) instead of formatting values into the HQL or SQL string."
  },
  "java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli": {
    priority: "HIGH",
    intent: "Use PreparedStatement with parameterized queries. Replace string concatenation with: `PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); ps.setInt(1, userId);`."
  },
  "java.lang.security.audit.sqli.jdo-sqli.jdo-sqli": {
    priority: "HIGH",
    intent: "Use JDO query parameters via `setParameters` and a parameter declaration, instead of formatting values into the query filter string."
  },
  "java.lang.security.audit.sqli.jpa-sqli.jpa-sqli": {
    priority: "HIGH",
    intent: "Use JPA named parameters (`:name` with `setParameter`) instead of concatenating values into the JPQL or native query string."
  },
  "java.lang.security.audit.sqli.turbine-sqli.turbine-sqli": {
    priority: "HIGH",
    intent: "Build the Turbine criteria with typed criterion objects and bound values rather than formatting user input into the SQL string."
  },
  "java.lang.security.audit.sqli.vertx-sqli.vertx-sqli": {
    priority: "HIGH",
    intent: "Use Vert.x `preparedQuery` with a `Tuple` of bound values instead of formatting user input into the SQL string."
  },
  "java.lang.security.audit.xml-decoder.xml-decoder": {
    priority: "HIGH",
    intent: "Do not parse untrusted input with `XMLDecoder`; it instantiates and invokes arbitrary classes named in the document. Use a data-only parser such as Jackson or JAXB bound to an expected type."
  },
  "java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-false.documentbuilderfactory-disallow-doctype-decl-false": {
    priority: "HIGH",
    intent: "Set the `http://apache.org/xml/features/disallow-doctype-decl` feature to true on the DocumentBuilderFactory. Leaving DOCTYPE processing enabled allows XML external entity (XXE) attacks."
  },
  "java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing": {
    priority: "HIGH",
    intent: "Explicitly set the `http://apache.org/xml/features/disallow-doctype-decl` feature to true on the DocumentBuilderFactory. The default permits DOCTYPE declarations and is vulnerable to XXE."
  },
  "java.lang.security.audit.xxe.documentbuilderfactory-external-general-entities-true.documentbuilderfactory-external-general-entities-true": {
    priority: "HIGH",
    intent: "Set the `http://xml.org/sax/features/external-general-entities` feature to false, and disable DOCTYPE declarations entirely, so external entities cannot be resolved."
  },
  "java.lang.security.audit.xxe.documentbuilderfactory-external-parameter-entities-true.documentbuilderfactory-external-parameter-entities-true": {
    priority: "HIGH",
    intent: "Set the `http://xml.org/sax/features/external-parameter-entities` feature to false, and disable DOCTYPE declarations entirely, so external parameter entities cannot be resolved."
  },
  "java.lang.security.audit.xxe.saxparserfactory-disallow-doctype-decl-missing.saxparserfactory-disallow-doctype-decl-missing": {
    priority: "HIGH",
    intent: "Set the `http://apache.org/xml/features/disallow-doctype-decl` feature to true on the SAXParserFactory before parsing untrusted XML."
  },
  "java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled": {
    priority: "HIGH",
    intent: "Set both `XMLConstants.ACCESS_EXTERNAL_DTD` and `XMLConstants.ACCESS_EXTERNAL_STYLESHEET` to the empty string on the TransformerFactory so it cannot load external DTDs or stylesheets."
  },
  "java.lang.security.jackson-unsafe-deserialization.jackson-unsafe-deserialization": {
    priority: "HIGH",
    intent: "Do not enable Jackson default typing. Remove `enableDefaultTyping`/`activateDefaultTyping`, and where polymorphism is required use `@JsonTypeInfo` with an explicit subtype allowlist or a validating `PolymorphicTypeValidator`."
  },
  "java.lang.security.use-snakeyaml-constructor.use-snakeyaml-constructor": {
    priority: "HIGH",
    intent: "Construct SnakeYAML with a restricted constructor, for example `new Yaml(new SafeConstructor())` or a `Constructor` bound to the expected type. The no-argument constructor instantiates arbitrary classes named in the document."
  },
  "java.lang.security.xmlinputfactory-external-entities-enabled.xmlinputfactory-external-entities-enabled": {
    priority: "HIGH",
    intent: "Set `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES` to false and `SUPPORT_DTD` to false on the XMLInputFactory."
  },
  "java.lang.security.xmlinputfactory-possible-xxe.xmlinputfactory-possible-xxe": {
    priority: "HIGH",
    intent: "Explicitly disable external entities and DTD support on the XMLInputFactory by setting `IS_SUPPORTING_EXTERNAL_ENTITIES` and `SUPPORT_DTD` to false, rather than relying on defaults."
  },
  "java.rmi.security.server-dangerous-class-deserialization.server-dangerous-class-deserialization": {
    priority: "HIGH",
    intent: "Avoid accepting non-primitive parameter types over Java RMI. Accept primitives or strings and validate them, or place the endpoint behind a serialization filter that allowlists the expected classes."
  },
  "java.rmi.security.server-dangerous-object-deserialization.server-dangerous-object-deserialization": {
    priority: "HIGH",
    intent: "Do not accept arbitrary `Object` parameters over Java RMI, since the payload chooses which classes get constructed. Declare specific parameter types and apply an `ObjectInputFilter` allowlist."
  },
  "java.spring.security.audit.spel-injection.spel-injection": {
    priority: "HIGH",
    intent: "Do not build Spring Expression Language expressions from user input. Keep the expression static and supply user data through the evaluation context as variables, or use a `SimpleEvaluationContext` to restrict what the expression can reach."
  },
  "java.spring.security.audit.spring-actuator-fully-enabled.spring-actuator-fully-enabled": {
    priority: "HIGH",
    intent: "Do not expose all Spring Boot Actuator endpoints. Set `management.endpoints.web.exposure.include` to only the endpoints you need (typically `health`), and require authentication for the rest, since endpoints like `env` and `heapdump` disclose secrets."
  },
  "java.spring.security.injection.tainted-file-path.tainted-file-path": {
    priority: "HIGH",
    intent: "Do not build file paths from user input. Resolve the path against a fixed base directory, then verify the canonical result still sits inside that directory so `../` sequences cannot escape it."
  },
  "java.spring.security.injection.tainted-system-command.tainted-system-command": {
    priority: "HIGH",
    intent: "Do not pass user input into a system command. Use a fixed executable with arguments supplied separately, validate the input against an allowlist, and prefer a library call over shelling out."
  },

  // ==== JavaScript ====
  "javascript.aws-lambda.security.detect-child-process.detect-child-process": {
    priority: "HIGH",
    intent: "Do not spawn processes with user-controlled program names or arguments. Use `execFile` or `spawn` with a fixed executable and an argument array, never `exec` with a built string, and validate any user value against an allowlist."
  },
  "javascript.aws-lambda.security.dynamodb-request-object.dynamodb-request-object": {
    priority: "HIGH",
    intent: "Do not build DynamoDB request parameters directly from the Lambda event. Construct the request from validated fields and use expression attribute names and values rather than interpolating event data into expressions."
  },
  "javascript.aws-lambda.security.knex-sqli.knex-sqli": {
    priority: "HIGH",
    intent: "Use Knex's parameter bindings — `knex.raw(sql, [values])` or the query builder methods — instead of interpolating event data into the SQL string."
  },
  "javascript.aws-lambda.security.mysql-sqli.mysql-sqli": {
    priority: "HIGH",
    intent: "Use placeholders and pass values as the second argument to `query()` so the mysql driver escapes them, rather than concatenating event data into the SQL string."
  },
  "javascript.aws-lambda.security.pg-sqli.pg-sqli": {
    priority: "HIGH",
    intent: "Use `$1`-style placeholders and pass the values array to `query()` so node-postgres binds them, rather than concatenating event data into the SQL string."
  },
  "javascript.aws-lambda.security.sequelize-sqli.sequelize-sqli": {
    priority: "HIGH",
    intent: "Use Sequelize's `replacements` or `bind` options, or the model query API, instead of interpolating event data into a raw SQL string."
  },
  "javascript.aws-lambda.security.tainted-eval.tainted-eval": {
    priority: "HIGH",
    intent: "Remove `eval()`. Parse data with `JSON.parse`, look behaviour up in an object keyed by a validated value, or call a fixed function — never evaluate a string built from the event payload."
  },
  "javascript.deno.security.audit.deno-dangerous-run.deno-dangerous-run": {
    priority: "HIGH",
    intent: "Keep the command passed to `Deno.run` static and supply user input only as separate arguments after validation. Also narrow the process's `--allow-run` permission to the specific binaries required."
  },
  "javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage": {
    priority: "HIGH",
    intent: "Add CSRF protection to the Express application. Register a CSRF middleware such as `csrf`, and set session cookies with `sameSite` and `httpOnly` so state-changing requests cannot be forged from another site."
  },
  "javascript.express.security.audit.express-detect-notevil-usage.express-detect-notevil-usage": {
    priority: "HIGH",
    intent: "Remove the `notevil` package; it is unmaintained and its sandbox has known bypasses. Eliminate the need to evaluate strings, or run untrusted code in a separate isolated process."
  },
  "javascript.express.security.audit.express-libxml-noent.express-libxml-noent": {
    priority: "HIGH",
    intent: "Set `noent` to false (the default) when parsing untrusted XML with libxmljs, so external entities are not substituted. Also disable DTD loading to prevent XXE."
  },
  "javascript.express.security.audit.express-libxml-vm-noent.express-libxml-vm-noent": {
    priority: "HIGH",
    intent: "Do not pass `noent: true` to `parseXml()` for untrusted input; it enables external entity substitution and allows XXE. Leave entity substitution off and disable DTD loading."
  },
  "javascript.express.security.audit.express-session-hardcoded-secret.express-session-hardcoded-secret": {
    priority: "HIGH",
    intent: "Remove the hardcoded session secret and rotate it. Read it at runtime from an environment variable or secrets manager, and use a long random value so session cookies cannot be forged."
  },
  "javascript.express.security.audit.express-ssrf.express-ssrf": {
    priority: "HIGH",
    intent: "Do not build outbound request URLs from request data. Resolve the target from a server-side allowlist of hosts, reject redirects to other hosts, and block requests to internal and link-local addresses."
  },
  "javascript.express.security.audit.express-third-party-object-deserialization.express-third-party-object-deserialization": {
    priority: "HIGH",
    intent: "Do not deserialize request data with a library that reconstructs arbitrary objects or functions. Use `JSON.parse` and validate the result against an expected schema."
  },
  "javascript.express.security.audit.express-xml2json-xxe-event.express-xml2json-xxe-event": {
    priority: "HIGH",
    intent: "Ensure request data does not reach the XML parser with entity or DTD processing enabled. Disable external entities in the parser options, and validate the payload before parsing."
  },
  "javascript.intercom.security.audit.intercom-settings-user-identifier-without-user-hash.intercom-settings-user-identifier-without-user-hash": {
    priority: "HIGH",
    intent: "Supply a server-generated `user_hash` (an HMAC of the user id keyed with your Intercom secret) alongside the user identifier. Without it, a visitor can impersonate another user by changing the identifier."
  },
  "javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg": {
    priority: "HIGH",
    intent: "Do not use the `none` algorithm. Sign tokens with a strong algorithm such as RS256 or HS256, and when verifying, pass an explicit `algorithms` allowlist so an attacker cannot present an unsigned token."
  },
  "javascript.jwt-simple.security.jwt-simple-noverify.jwt-simple-noverify": {
    priority: "HIGH",
    intent: "Verify the JWT signature before trusting its claims. Call `decode` with verification enabled and an explicit algorithm, rather than skipping the verify step."
  },
  "javascript.lang.security.audit.code-string-concat.code-string-concat": {
    priority: "MEDIUM",
    intent: "Avoid concatenating user input into code strings. Use parameterized templates or safe alternatives to dynamic code generation."
  },
  "javascript.lang.security.audit.dangerous-spawn-shell.dangerous-spawn-shell": {
    priority: "MEDIUM",
    intent: "Use `spawn()` with `shell: false`. Pass arguments as an array: `spawn('cmd', ['arg1', 'arg2'], { shell: false })`."
  },
  "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp": {
    priority: "MEDIUM",
    intent: "Validate regex patterns before creating RegExp objects. Use a timeout or safe-regex library to prevent ReDoS attacks."
  },
  "javascript.lang.security.audit.hardcoded-hmac-key.hardcoded-hmac-key": {
    priority: "LOW",
    intent: "Move HMAC keys to environment variables. Use `process.env.HMAC_KEY` instead of hardcoded strings. Rotate keys regularly."
  },
  "javascript.lang.security.audit.incomplete-sanitization.incomplete-sanitization": {
    priority: "LOW",
    intent: "Use comprehensive sanitization. Replace single `replace()` with `replaceAll()` or global regex: `str.replace(/[<>]/g, '')`."
  },
  "javascript.lang.security.audit.md5-used-as-password.md5-used-as-password": {
    priority: "MEDIUM",
    intent: "Never use MD5 for passwords. Use `bcrypt`, `scrypt`, or `argon2` via libraries like `bcryptjs` for secure password hashing."
  },
  "javascript.lang.security.audit.spawn-shell-true.spawn-shell-true": {
    priority: "LOW",
    intent: "Use `shell: false` in spawn options. Pass arguments as an array and validate all inputs to prevent command injection."
  },
  "javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag": {
    priority: "LOW",
    intent: "Escape dynamic content in script tags. Use JSON.stringify with proper escaping or Content Security Policy to prevent XSS."
  },
  "javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring": {
    priority: "LOW",
    intent: "Avoid format strings with user input. Use template literals with proper escaping or parameterized logging."
  },
  "javascript.lang.security.detect-buffer-noassert.detect-buffer-noassert": {
    priority: "HIGH",
    intent: "Remove `noAssert` parameter from Buffer methods. Use explicit bounds checking: validate offset and length before buffer operations."
  },
  "javascript.lang.security.detect-child-process.detect-child-process": {
    priority: "HIGH",
    intent: "Use `child_process.execFile()` or `spawn()` with `shell: false`. Validate all arguments and use absolute paths for executables."
  },
  "javascript.lang.security.detect-disable-mustache-escape.detect-disable-mustache-escape": {
    priority: "MEDIUM",
    intent: "Never disable Mustache HTML escaping. Remove `Mustache.escape = ...` and use default escaping. For trusted HTML, use triple braces with caution."
  },
  "javascript.lang.security.detect-eval-with-expression.detect-eval-with-expression": {
    priority: "MEDIUM",
    intent: "Replace `eval()` with safer alternatives. Use `JSON.parse()` for JSON data, or implement specific parsing logic. Consider using a sandboxed environment."
  },
  "javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket": {
    priority: "MEDIUM",
    intent: "Use secure WebSocket connections (`wss://`). Replace `new WebSocket('ws://...')` with `new WebSocket('wss://...')` and validate server certificates."
  },
  "javascript.lang.security.detect-no-csrf-before-method-override.detect-no-csrf-before-method-override": {
    priority: "LOW",
    intent: "Load CSRF middleware before method-override. Ensure `app.use(csrf())` comes before `app.use(methodOverride())` in Express."
  },
  "javascript.lang.security.insecure-object-assign.insecure-object-assign": {
    priority: "MEDIUM",
    intent: "Validate source objects before `Object.assign()`. Check for prototype pollution by validating keys: `if (key === '__proto__' || key === 'constructor') return;`."
  },
  "javascript.lang.security.spawn-git-clone.spawn-git-clone": {
    priority: "LOW",
    intent: "Validate repository URLs before git clone. Use allowlists for permitted hosts and sanitize branch names. Avoid user-controlled URLs."
  },
  "javascript.playwright.security.audit.playwright-addinitscript-code-injection.playwright-addinitscript-code-injection": {
    priority: "HIGH",
    intent: "Do not pass user-controlled content to `addInitScript`. Keep the injected script static and supply data through a validated argument, so the page cannot be made to fetch or execute attacker-chosen resources."
  },
  "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection": {
    priority: "HIGH",
    intent: "Use Sequelize's `replacements` or `bind` options, or the model query API with `where` objects, instead of building the query from request data."
  },
  "javascript.shelljs.security.shelljs-exec-injection.shelljs-exec-injection": {
    priority: "HIGH",
    intent: "Do not pass user input to `shelljs.exec`, which runs the string through a shell. Use a Node API or `child_process.execFile` with a fixed executable and an argument array instead."
  },
  "javascript.thenify.security.audit.multiargs-code-execution.multiargs-code-execution": {
    priority: "HIGH",
    intent: "Remove the path that pipes a value into `eval`. Pass a function reference rather than code as a string, so no caller-supplied text is ever evaluated."
  },
  "javascript.vm2.security.audit.vm2-code-injection.vm2-code-injection": {
    priority: "HIGH",
    intent: "Do not run user-supplied code in `vm2`; it has known sandbox escapes and is no longer maintained. Remove dynamic evaluation, or move untrusted execution into an isolated process or a purpose-built sandbox such as `isolated-vm`."
  },
  "javascript.vm2.security.audit.vm2-context-injection.vm2-context-injection": {
    priority: "HIGH",
    intent: "Do not place user-controlled values into the `vm2` sandbox context, since they can be used to break out of the sandbox. Remove the dependency on `vm2` and isolate untrusted execution at the process level instead."
  },

  // ==== JSON - AWS policy ====
  "json.aws.security.public-s3-bucket.public-s3-bucket": {
    priority: "HIGH",
    intent: "Remove the public grant from the S3 bucket. Scope the policy principal to specific accounts, roles or a CloudFront origin access identity, and enable the bucket's public access block settings."
  },
  "json.aws.security.public-s3-policy-statement.public-s3-policy-statement": {
    priority: "HIGH",
    intent: "Replace the wildcard principal in the bucket policy with the specific accounts or roles that need access, and enable S3 Block Public Access on the bucket so a public statement cannot take effect."
  },
  "json.aws.security.wildcard-assume-role.wildcard-assume-role": {
    priority: "HIGH",
    intent: "Replace the wildcard principal on `sts:AssumeRole` with the specific accounts, roles or services allowed to assume the role, and add a condition such as `sts:ExternalId` or `aws:PrincipalOrgID` for cross-account trust."
  },

  // ==== Kotlin ====
  "kotlin.gradle.security.build-gradle-password-hardcoded.build-gradle-password-hardcoded": {
    priority: "HIGH",
    intent: "Remove the hardcoded credential from the Gradle build script and rotate it. Read it from a Gradle property supplied at build time, an environment variable, or a credentials provider, and keep it out of version control."
  },
  "kotlin.lang.security.command-injection-formatted-runtime-call.command-injection-formatted-runtime-call": {
    priority: "HIGH",
    intent: "Do not pass a formatted or concatenated string to `Runtime.exec`. Use the array overload so the executable and each argument are separate, keep the executable static, and validate user-supplied arguments against an allowlist."
  },

  // ==== Package managers - supply chain ====
  "package_managers.bun.bun-missing-minimum-release-age.bun-missing-minimum-release-age": {
    priority: "HIGH",
    intent: "Set a minimum release age in `bunfig.toml` so freshly published versions are not installed immediately. A cooldown of several days gives compromised or malicious releases time to be detected and yanked before they reach your build."
  },
  "package_managers.dependabot.dependabot-missing-cooldown.dependabot-missing-cooldown": {
    priority: "HIGH",
    intent: "Add a `cooldown` block to the Dependabot configuration so update pull requests are not raised against versions published moments ago. This limits exposure to a compromised release that is withdrawn shortly after publication."
  },
  "package_managers.npm.npm-missing-minimum-release-age.npm-missing-minimum-release-age": {
    priority: "HIGH",
    intent: "Set `min-release-age` in `.npmrc` so npm will not install a version published within the cooldown window, reducing exposure to malicious releases that are removed soon after publication."
  },
  "package_managers.pnpm.pnpm-block-exotic-sub-dependencies.pnpm-block-exotic-sub-dependencies": {
    priority: "HIGH",
    intent: "Set `blockExoticSubdeps: true` in the pnpm configuration so transitive dependencies cannot be pulled from git URLs, tarball URLs or other non-registry sources that bypass registry controls."
  },
  "package_managers.pnpm.pnpm-missing-minimum-release-age.pnpm-minimum-release-age": {
    priority: "HIGH",
    intent: "Set a minimum release age in the pnpm workspace configuration so newly published versions are not installed until the cooldown has elapsed."
  },
  "package_managers.pnpm.pnpm-trust-policy.pnpm-trust-policy": {
    priority: "HIGH",
    intent: "Set `trustPolicy: no-downgrade` in the pnpm configuration so an update cannot move a dependency to a version with weaker integrity guarantees than the one already resolved."
  },
  "package_managers.renovate.renovate-missing-minimum-release-age.renovate-missing-minimum-release-age": {
    priority: "HIGH",
    intent: "Set `minimumReleaseAge` in the Renovate configuration so it waits before proposing a newly published version, reducing exposure to releases that are later found malicious."
  },
  "package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown": {
    priority: "HIGH",
    intent: "Configure a uv dependency cooldown in `pyproject.toml` by excluding newly published versions, so a compromised release is not resolved the moment it appears on the index."
  },
  "package_managers.yarn.yarn-missing-minimal-age-gate.yarn-missing-minimal-age-gate": {
    priority: "HIGH",
    intent: "Set a minimal age gate in `.yarnrc.yml` so Yarn will not install versions published inside the cooldown window."
  },

  // ==== PHP ====
  "php.doctrine.security.audit.doctrine-dbal-dangerous-query.doctrine-dbal-dangerous-query": {
    priority: "HIGH",
    intent: "Use Doctrine DBAL's parameter binding — placeholders with `executeQuery($sql, $params)` or the query builder's `setParameter` — instead of concatenating values into the SQL string."
  },
  "php.lang.security.backticks-use.backticks-use": {
    priority: "HIGH",
    intent: "Remove the backtick operator, which passes its contents to a shell. Use `proc_open` or `escapeshellarg`-protected arguments with a fixed executable, or a native PHP function that avoids shelling out entirely."
  },
  "php.lang.security.eval-use.eval-use": {
    priority: "HIGH",
    intent: "Remove `eval()`. Replace dynamic evaluation with a fixed function call, or dispatch through an array keyed by a validated value, so no caller-supplied text is executed."
  },
  "php.lang.security.exec-use.exec-use": {
    priority: "HIGH",
    intent: "Keep the executed command static. Pass user input only as arguments escaped with `escapeshellarg()`, or avoid the shell entirely by using `proc_open` with a fixed program."
  },
  "php.lang.security.injection.tainted-callable.tainted-callable": {
    priority: "HIGH",
    intent: "Do not resolve a callable from user input. Map the validated input to a fixed set of permitted handlers with a `match` or array lookup, so an attacker cannot name an arbitrary function."
  },
  "php.lang.security.injection.tainted-exec.tainted-exec": {
    priority: "HIGH",
    intent: "Do not pass user input to a shell-executing function. Use a fixed executable with `escapeshellarg()`-escaped arguments, validate the input against an allowlist, and prefer a native PHP API over shelling out."
  },
  "php.lang.security.tainted-exec.tainted-exec": {
    priority: "HIGH",
    intent: "Keep the command string static and wrap any user-supplied argument in `escapeshellarg()`. Better still, avoid the shell and call a fixed program with an argument list."
  },
  "php.wordpress-plugins.security.audit.wp-ssrf-audit.wp-ssrf-audit": {
    priority: "HIGH",
    intent: "Do not build outbound request URLs from user input. Validate the target against a server-side allowlist of hosts, and reject requests to private, loopback and link-local addresses so internal services cannot be reached."
  },

  // ==== Python ====
  "python.airflow.security.audit.formatted-string-bashoperator.formatted-string-bashoperator": {
    priority: "HIGH",
    intent: "Do not build the BashOperator command from formatted strings containing variables an external party can set. Pass values through Airflow templating with proper quoting, or use a PythonOperator that calls `subprocess` with an argument list."
  },
  "python.aws-lambda.security.dangerous-spawn-process.dangerous-spawn-process": {
    priority: "MEDIUM",
    intent: "Avoid spawning processes in Lambda. Use Lambda layers or SDK calls instead. If subprocess is required, validate all inputs."
  },
  "python.cryptography.security.empty-aes-key.empty-aes-key": {
    priority: "HIGH",
    intent: "Generate proper AES keys using `os.urandom(32)` for AES-256 or use `cryptography.fernet.Fernet.generate_key()`. Never use empty or hardcoded keys."
  },
  "python.cryptography.security.insecure-cipher-mode-ecb.insecure-cipher-mode-ecb": {
    priority: "LOW",
    intent: "Replace ECB mode with GCM, CTR, or CBC with proper IV. ECB mode reveals patterns in encrypted data. Use `modes.GCM()` for authenticated encryption."
  },
  "python.cryptography.security.insufficient-dsa-key-size.insufficient-dsa-key-size": {
    priority: "MEDIUM",
    intent: "Use DSA keys of at least 2048 bits. Consider migrating to ECDSA or EdDSA for better performance and security."
  },
  "python.cryptography.security.insufficient-ec-key-size.insufficient-ec-key-size": {
    priority: "MEDIUM",
    intent: "Use EC curves with at least 256 bits (P-256 or higher). Recommended: `SECP384R1` or `SECP521R1` for high-security applications."
  },
  "python.cryptography.security.insufficient-rsa-key-size.insufficient-rsa-key-size": {
    priority: "MEDIUM",
    intent: "Use RSA keys of at least 2048 bits, preferably 4096 bits for long-term security. Generate with `rsa.generate_private_key(public_exponent=65537, key_size=4096)`."
  },
  "python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql": {
    priority: "HIGH",
    intent: "Return parameter placeholders and a params tuple from `as_sql()` rather than interpolating values into the SQL fragment. Custom expressions that build SQL by string formatting reintroduce SQL injection inside the ORM."
  },
  "python.django.security.audit.django-rest-framework.missing-throttle-config.missing-throttle-config": {
    priority: "HIGH",
    intent: "Set `DEFAULT_THROTTLE_CLASSES` and `DEFAULT_THROTTLE_RATES` in the Django REST framework settings so unauthenticated and authenticated callers are rate limited, preventing resource exhaustion."
  },
  "python.django.security.audit.extends-custom-expression.extends-custom-expression": {
    priority: "HIGH",
    intent: "When extending a Django expression, keep the generated SQL parameterised: emit placeholders and return the values as params, never format user data into the SQL fragment."
  },
  "python.django.security.audit.query-set-extra.avoid-query-set-extra": {
    priority: "HIGH",
    intent: "Replace `QuerySet.extra()` with the ORM's own filtering, annotation or `Func` expressions. If raw SQL is unavoidable, pass values through the `params` argument so they are bound rather than interpolated."
  },
  "python.django.security.audit.raw-query.avoid-raw-sql": {
    priority: "HIGH",
    intent: "Use the ORM query API instead of `raw()` or `RawSQL`. Where raw SQL is required, supply values via the `params` argument so Django binds them as query parameters."
  },
  "python.django.security.django-no-csrf-token.django-no-csrf-token": {
    priority: "MEDIUM",
    intent: "Add `{% csrf_token %}` to all POST forms. Ensure `django.middleware.csrf.CsrfViewMiddleware` is enabled in settings."
  },
  "python.django.security.django-using-request-post-after-is-valid.django-using-request-post-after-is-valid": {
    priority: "MEDIUM",
    intent: "Access form data through the cleaned form object after validation. Use `form.cleaned_data['field']` instead of `request.POST['field']`."
  },
  "python.django.security.globals-as-template-context.globals-as-template-context": {
    priority: "HIGH",
    intent: "Never pass `globals()` to template context. Create explicit context dictionaries with only required variables."
  },
  "python.django.security.hashids-with-django-secret.hashids-with-django-secret": {
    priority: "HIGH",
    intent: "Use a separate secret for Hashids, not `settings.SECRET_KEY`. Generate a dedicated secret: `hashids.Hashids(salt=settings.HASHIDS_SALT)`."
  },
  "python.django.security.injection.code.user-eval-format-string.user-eval-format-string": {
    priority: "HIGH",
    intent: "Remove `eval()`. Parse structured input with `json.loads`, or dispatch on a validated value through a dictionary of permitted callables, so request data is never evaluated as code."
  },
  "python.django.security.injection.code.user-eval.user-eval": {
    priority: "HIGH",
    intent: "Remove `eval()` from this path. Use `json.loads` for data, or map the validated request value to a fixed set of handlers, so user input is never executed."
  },
  "python.django.security.injection.code.user-exec-format-string.user-exec-format-string": {
    priority: "HIGH",
    intent: "Remove `exec()`. Replace dynamic code execution with explicit functions selected by a validated value, so no part of the request becomes executable code."
  },
  "python.django.security.injection.code.user-exec.user-exec": {
    priority: "HIGH",
    intent: "Remove `exec()` from this path. Dispatch to a fixed set of functions based on a validated request value instead of executing request-derived text."
  },
  "python.django.security.injection.command.command-injection-os-system.command-injection-os-system": {
    priority: "HIGH",
    intent: "Replace `os.system()` with `subprocess.run()` using `shell=False` and an argument list, keeping the executable static. Validate any request-derived argument against an allowlist."
  },
  "python.django.security.injection.command.subprocess-injection.subprocess-injection": {
    priority: "HIGH",
    intent: "Call `subprocess` with `shell=False` and pass the command as a list, keeping the program name static. Validate request-derived arguments against an allowlist."
  },
  "python.django.security.injection.path-traversal.path-traversal-open.path-traversal-open": {
    priority: "MEDIUM",
    intent: "Validate file paths against a base directory. Use `os.path.realpath()` and verify the resolved path starts with the allowed directory."
  },
  "python.django.security.injection.sql.sql-injection-extra.sql-injection-using-extra-where": {
    priority: "HIGH",
    intent: "Do not pass request data into `extra()`. Express the filter through the ORM, or pass the values via the `params` argument so they are bound instead of interpolated into the WHERE clause."
  },
  "python.django.security.injection.sql.sql-injection-rawsql.sql-injection-using-rawsql": {
    priority: "HIGH",
    intent: "Do not build `RawSQL()` from request data. Pass the values through `RawSQL`'s params argument, or replace the raw expression with ORM filters and annotations."
  },
  "python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute": {
    priority: "HIGH",
    intent: "Pass query parameters as the second argument to `cursor.execute()` using `%s` placeholders, rather than formatting request data into the SQL string."
  },
  "python.django.security.injection.sql.sql-injection-using-raw.sql-injection-using-raw": {
    priority: "HIGH",
    intent: "Do not interpolate request data into `raw()`. Use `%s` placeholders with the `params` argument, or switch to the ORM query API."
  },
  "python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests": {
    priority: "HIGH",
    intent: "Validate URLs before making requests. Use domain allowlists and validate protocols. Consider using a URL validation library."
  },
  "python.django.security.injection.ssrf.ssrf-injection-urllib.ssrf-injection-urllib": {
    priority: "HIGH",
    intent: "Validate URLs against an allowlist of domains and protocols. Never pass user input directly to URL fetching functions."
  },
  "python.django.security.locals-as-template-context.locals-as-template-context": {
    priority: "HIGH",
    intent: "Avoid passing `locals()` to templates. Create explicit context dictionaries to prevent exposing sensitive variables."
  },
  "python.django.security.nan-injection.nan-injection": {
    priority: "MEDIUM",
    intent: "Validate numeric inputs before database queries. Check for NaN and Infinity values: `if math.isnan(value) or math.isinf(value): raise ValidationError()`."
  },
  "python.django.security.passwords.password-empty-string.password-empty-string": {
    priority: "MEDIUM",
    intent: "Never use empty passwords. Implement proper password validation using Django's password validators and enforce minimum complexity requirements."
  },
  "python.docker.security.audit.docker-arbitrary-container-run.docker-arbitrary-container-run": {
    priority: "HIGH",
    intent: "Do not let user input choose the image, command or mounts for `run`/`create`. Restrict launches to a fixed set of reviewed images and arguments, since arbitrary container execution with daemon access is equivalent to host compromise."
  },
  "python.flask.security.audit.debug-enabled.debug-enabled": {
    priority: "MEDIUM",
    intent: "Disable debug mode in production. Set `app.debug = False` and use environment variables: `app.debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'`."
  },
  "python.flask.security.audit.secure-set-cookie.secure-set-cookie": {
    priority: "LOW",
    intent: "Set secure cookie flags. Use `response.set_cookie(key, value, secure=True, httponly=True, samesite='Strict')` for sensitive cookies."
  },
  "python.flask.security.dangerous-template-string.dangerous-template-string": {
    priority: "MEDIUM",
    intent: "Use `render_template()` with separate template files instead of `render_template_string()`. If using string templates, never include user input in the template source."
  },
  "python.flask.security.flask-api-method-string-format.flask-api-method-string-format": {
    priority: "MEDIUM",
    intent: "Avoid string formatting in API responses. Use proper JSON serialization with `jsonify()` and validate all user inputs."
  },
  "python.flask.security.hashids-with-flask-secret.hashids-with-flask-secret": {
    priority: "HIGH",
    intent: "Use a separate secret for Hashids. Generate a dedicated key: `hashids = Hashids(salt=app.config['HASHIDS_SALT'])` instead of using `app.secret_key`."
  },
  "python.flask.security.injection.os-system-injection.os-system-injection": {
    priority: "HIGH",
    intent: "Replace `os.system()` with `subprocess.run()` using `shell=False` and an argument list. Never pass request data through a shell."
  },
  "python.flask.security.injection.path-traversal-open.path-traversal-open": {
    priority: "HIGH",
    intent: "Do not open a path built from request data. Resolve the filename against a fixed base directory with `os.path.realpath`, confirm the result is still inside that directory, and prefer `send_from_directory` for serving files."
  },
  "python.flask.security.injection.ssrf-requests.ssrf-requests": {
    priority: "HIGH",
    intent: "Do not pass request data as the URL of an outbound request. Resolve the target from a server-side allowlist, disable redirects or re-validate them, and block private, loopback and link-local addresses."
  },
  "python.flask.security.injection.user-exec.exec-injection": {
    priority: "HIGH",
    intent: "Remove `exec()` from the request handler. Select behaviour from a fixed mapping keyed by a validated request value rather than executing request data."
  },
  "python.flask.security.insecure-deserialization.insecure-deserialization": {
    priority: "MEDIUM",
    intent: "Replace insecure deserialization with JSON. Use `request.get_json()` for JSON data. Never unpickle user-provided data."
  },
  "python.flask.security.open-redirect.open-redirect": {
    priority: "MEDIUM",
    intent: "Validate redirect URLs against an allowlist. Use `url_for()` for internal redirects. Check that redirect targets are within your domain."
  },
  "python.flask.security.unescaped-template-extension.unescaped-template-extension": {
    priority: "MEDIUM",
    intent: "Use `.html` extension for Jinja2 templates to enable autoescaping. Avoid `.txt`, `.xml`, or custom extensions without explicit escaping."
  },
  "python.jwt.security.unverified-jwt-decode.unverified-jwt-decode": {
    priority: "MEDIUM",
    intent: "Always verify JWT signatures. Use `jwt.decode(token, secret, algorithms=['HS256'])` instead of `jwt.decode(token, options={'verify_signature': False})`."
  },
  "python.lang.security.audit.dangerous-annotations-usage.dangerous-annotations-usage": {
    priority: "LOW",
    intent: "Avoid using dangerous type annotations that could execute code during runtime. Use string annotations with `from __future__ import annotations`."
  },
  "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected": {
    priority: "LOW",
    intent: "Validate URLs before passing to urllib. Use allowlists for permitted domains and protocols. Consider using the `requests` library with proper validation."
  },
  "python.lang.security.audit.eval-detected.eval-detected": {
    priority: "HIGH",
    intent: "Replace `eval()` with safer alternatives. Use `ast.literal_eval()` for parsing simple Python literals, or implement specific parsing logic for your use case."
  },
  "python.lang.security.audit.exec-detected.exec-detected": {
    priority: "HIGH",
    intent: "Replace `exec()` with safer alternatives. Use specific function calls, imports, or data structures instead of dynamic code execution. Validate inputs if exec is unavoidable."
  },
  "python.lang.security.audit.formatted-sql-query.formatted-sql-query": {
    priority: "HIGH",
    intent: "Use parameterized queries instead of string formatting for SQL. Use database-specific parameter placeholders (`?`, `%s`, `:name`) to prevent SQL injection."
  },
  "python.lang.security.audit.hardcoded-password-default-argument.hardcoded-password-default-argument": {
    priority: "MEDIUM",
    intent: "Remove hardcoded password defaults from function parameters. Load passwords from environment variables using `os.environ.get()` or a secrets manager."
  },
  "python.lang.security.audit.httpsconnection-detected.httpsconnection-detected": {
    priority: "LOW",
    intent: "Ensure HTTPS connections verify SSL certificates. Use `ssl.create_default_context()` for proper certificate validation."
  },
  "python.lang.security.audit.insecure-file-permissions.insecure-file-permissions": {
    priority: "MEDIUM",
    intent: "Set secure file permissions. Use specific octal values (e.g., `0o644` for files, `0o755` for directories) instead of overly permissive `0o777`."
  },
  "python.lang.security.audit.mako-templates-detected.mako-templates-detected": {
    priority: "MEDIUM",
    intent: "Sanitize all user inputs before rendering in Mako templates. Use `| h` filter for HTML escaping: `${user_input | h}`."
  },
  "python.lang.security.audit.md5-used-as-password.md5-used-as-password": {
    priority: "LOW",
    intent: "Never use MD5 for password hashing. Use `bcrypt`, `argon2`, or `scrypt` via the `passlib` library for secure password storage."
  },
  "python.lang.security.audit.non-literal-import.non-literal-import": {
    priority: "MEDIUM",
    intent: "Avoid dynamic imports with user-controlled module names. Use allowlists for permitted modules or static imports."
  },
  "python.lang.security.audit.paramiko-implicit-trust-host-key.paramiko-implicit-trust-host-key": {
    priority: "MEDIUM",
    intent: "Set explicit host key policy for Paramiko. Use `client.set_missing_host_key_policy(paramiko.RejectPolicy())` in production instead of `AutoAddPolicy`."
  },
  "python.lang.security.audit.paramiko.paramiko-exec-command.paramiko-exec-command": {
    priority: "HIGH",
    intent: "Do not build the remote command passed to Paramiko's `exec_command` from user input; it is interpreted by the remote shell. Keep the command static, pass data via stdin or a file, and validate any user-supplied component against an allowlist."
  },
  "python.lang.security.audit.python-reverse-shell.python-reverse-shell": {
    priority: "MEDIUM",
    intent: "Remove reverse shell code. This pattern is commonly used in malware. If this is for legitimate penetration testing, ensure proper authorization."
  },
  "python.lang.security.audit.sha224-hash.sha224-hash": {
    priority: "LOW",
    intent: "Use SHA-256 or stronger instead of SHA-224 for security-sensitive applications. SHA-224 provides less security margin."
  },
  "python.lang.security.audit.sqli.aiopg-sqli.aiopg-sqli": {
    priority: "HIGH",
    intent: "Pass values as parameters to the aiopg cursor's `execute()` using placeholders, instead of concatenating them into the SQL string."
  },
  "python.lang.security.audit.sqli.asyncpg-sqli.asyncpg-sqli": {
    priority: "HIGH",
    intent: "Use asyncpg's `$1`-style placeholders and pass the values as arguments to `fetch`/`execute`, instead of concatenating them into the SQL string."
  },
  "python.lang.security.audit.sqli.pg8000-sqli.pg8000-sqli": {
    priority: "HIGH",
    intent: "Use pg8000's parameter placeholders and pass the values as arguments to `execute()`, instead of concatenating them into the SQL string."
  },
  "python.lang.security.audit.sqli.psycopg-sqli.psycopg-sqli": {
    priority: "HIGH",
    intent: "Pass values as the second argument to psycopg's `execute()` with `%s` placeholders, and use `psycopg.sql.Identifier` for dynamic table or column names. Never build the statement by string concatenation."
  },
  "python.lang.security.audit.ssl-wrap-socket-is-deprecated.ssl-wrap-socket-is-deprecated": {
    priority: "MEDIUM",
    intent: "Replace `ssl.wrap_socket()` with `ssl.SSLContext.wrap_socket()`. Use `ssl.create_default_context()` for secure defaults."
  },
  "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true": {
    priority: "LOW",
    intent: "Use `shell=False` in subprocess calls. Pass arguments as a list: `subprocess.run(['cmd', 'arg'], shell=False)` to prevent shell injection."
  },
  "python.lang.security.audit.system-wildcard-detected.system-wildcard-detected": {
    priority: "LOW",
    intent: "Avoid shell wildcards in system commands. Enumerate files explicitly using `glob.glob()` or `os.listdir()` and pass as a list to subprocess."
  },
  "python.lang.security.audit.telnetlib.telnetlib": {
    priority: "LOW",
    intent: "Replace `telnetlib` with encrypted alternatives. Use SSH via `paramiko` or secure APIs for remote connections."
  },
  "python.lang.security.audit.weak-ssl-version.weak-ssl-version": {
    priority: "MEDIUM",
    intent: "Use TLS 1.2 or higher. Set `ssl.PROTOCOL_TLS_CLIENT` or use `ssl.create_default_context()` which disables weak protocols by default."
  },
  "python.lang.security.dangerous-code-run.dangerous-interactive-code-run": {
    priority: "HIGH",
    intent: "Do not pass user-controlled data to `InteractiveConsole` or `InteractiveInterpreter`; they execute it as Python. Remove the interactive interpreter from this path entirely."
  },
  "python.lang.security.dangerous-globals-use.dangerous-globals-use": {
    priority: "MEDIUM",
    intent: "Avoid using `globals()` for dynamic variable access. Use explicit dictionaries or classes to manage dynamic data. If globals access is necessary, validate and sanitize all keys."
  },
  "python.lang.security.dangerous-os-exec.dangerous-os-exec": {
    priority: "MEDIUM",
    intent: "Replace `os.exec*()` calls with `subprocess.run()` with `shell=False`. Pass arguments as a list and validate all inputs. Use absolute paths for executables."
  },
  "python.lang.security.dangerous-spawn-process.dangerous-spawn-process": {
    priority: "MEDIUM",
    intent: "Replace `os.spawn*()` calls with `subprocess.run()` with `shell=False`. Pass arguments as a list, validate inputs, and use absolute paths for executables."
  },
  "python.lang.security.dangerous-subinterpreters-run-string.dangerous-subinterpreters-run-string": {
    priority: "HIGH",
    intent: "Avoid running arbitrary strings in subinterpreters. Validate and sanitize all code strings. Consider using pre-compiled modules or safe APIs instead."
  },
  "python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use": {
    priority: "HIGH",
    intent: "Use `subprocess.run()` with `shell=False` and pass arguments as a list. Validate all inputs and use absolute paths for executables. Avoid shell=True unless absolutely necessary."
  },
  "python.lang.security.dangerous-system-call.dangerous-system-call": {
    priority: "HIGH",
    intent: "Replace `os.system()` with `subprocess.run()` with `shell=False`. Pass arguments as a list, validate all inputs, and use `shlex.quote()` if shell usage is unavoidable."
  },
  "python.lang.security.dangerous-testcapi-run-in-subinterp.dangerous-testcapi-run-in-subinterp": {
    priority: "HIGH",
    intent: "Avoid using `_testcapi.run_in_subinterp()` in production code. This is intended for testing purposes only and can execute arbitrary code."
  },
  "python.lang.security.deserialization.avoid-jsonpickle.avoid-jsonpickle": {
    priority: "MEDIUM",
    intent: "Replace `jsonpickle` with standard `json` module for untrusted data. jsonpickle can execute arbitrary code during deserialization."
  },
  "python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load": {
    priority: "MEDIUM",
    intent: "Replace `yaml.load()` with `yaml.safe_load()` to prevent arbitrary code execution. Use `yaml.safe_load()` for all untrusted YAML data."
  },
  "python.lang.security.deserialization.avoid-unsafe-ruamel.avoid-unsafe-ruamel": {
    priority: "MEDIUM",
    intent: "Use `ruamel.yaml.YAML(typ='safe')` for loading untrusted YAML. The default loader can execute arbitrary code."
  },
  "python.lang.security.deserialization.pickle.avoid-pickle": {
    priority: "MEDIUM",
    intent: "Replace `pickle` with safer serialization like JSON for untrusted data. If pickle is required, validate data sources and consider using `hmac` for integrity verification."
  },
  "python.lang.security.insecure-hash-function.insecure-hash-function": {
    priority: "MEDIUM",
    intent: "Replace insecure hash functions with cryptographically secure alternatives. Use `hashlib.sha256()` or stronger algorithms for security-sensitive operations."
  },
  "python.lang.security.insecure-uuid-version.insecure-uuid-version": {
    priority: "MEDIUM",
    intent: "Use `uuid.uuid4()` for generating random UUIDs. Avoid `uuid1()` which exposes MAC address information. For security tokens, consider `secrets.token_hex()` instead."
  },
  "python.lang.security.unverified-ssl-context.unverified-ssl-context": {
    priority: "MEDIUM",
    intent: "Create SSL contexts with proper certificate verification. Use `ssl.create_default_context()` which enables certificate verification by default. Never use `ssl._create_unverified_context()` in production."
  },
  "python.lang.security.use-defused-xml-parse.use-defused-xml-parse": {
    priority: "MEDIUM",
    intent: "Replace standard XML parsing with `defusedxml` to prevent XXE attacks. Use `defusedxml.ElementTree.parse()` instead of `xml.etree.ElementTree.parse()`."
  },
  "python.lang.security.use-defused-xmlrpc.use-defused-xmlrpc": {
    priority: "MEDIUM",
    intent: "Replace `xmlrpc` with `defusedxml.xmlrpc` to prevent XXE attacks. Configure XML-RPC clients and servers to use safe parsing."
  },
  "python.pyramid.security.sqlalchemy-sql-injection.pyramid-sqlalchemy-sql-injection": {
    priority: "HIGH",
    intent: "Pass SQLAlchemy clause constructs or bound parameters to `filter`, `order_by`, `group_by` and `having` rather than raw SQL strings built from request data. Use `text()` with `bindparams` if raw SQL is unavoidable."
  },
  "python.requests.security.disabled-cert-validation.disabled-cert-validation": {
    priority: "LOW",
    intent: "Enable SSL certificate verification. Remove `verify=False` from requests calls. Use `verify=True` or specify a CA bundle path."
  },
  "python.requests.security.no-auth-over-http.no-auth-over-http": {
    priority: "LOW",
    intent: "Use HTTPS for authenticated requests. Change `http://` to `https://` and ensure certificates are verified."
  },
  "python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query": {
    priority: "HIGH",
    intent: "Use SQLAlchemy ORM methods or parameterized queries. Replace `execute('SELECT * FROM t WHERE id=' + user_id)` with `execute(text('SELECT * FROM t WHERE id=:id'), {'id': user_id})`."
  },
  "python.sqlalchemy.security.sqlalchemy-sql-injection.sqlalchemy-sql-injection": {
    priority: "HIGH",
    intent: "Use parameterized queries with SQLAlchemy. Pass parameters separately: `session.execute(text('SELECT * FROM users WHERE id=:id'), {'id': user_id})`."
  },

  // ==== Ruby ====
  "ruby.aws-lambda.security.activerecord-sqli.activerecord-sqli": {
    priority: "HIGH",
    intent: "Use ActiveRecord's parameterised forms — `where(\"col = ?\", value)` or `where(col: value)` — instead of interpolating event data into the SQL fragment."
  },
  "ruby.aws-lambda.security.mysql2-sqli.mysql2-sqli": {
    priority: "HIGH",
    intent: "Use a prepared statement (`client.prepare(sql).execute(value)`) or escape values with `client.escape`, rather than interpolating event data into the SQL string."
  },
  "ruby.aws-lambda.security.pg-sqli.pg-sqli": {
    priority: "HIGH",
    intent: "Use `exec_params` with `$1`-style placeholders and pass the values separately, instead of interpolating event data into the SQL string."
  },
  "ruby.aws-lambda.security.sequel-sqli.sequel-sqli": {
    priority: "HIGH",
    intent: "Use Sequel's placeholder literals or dataset filters with bound values instead of interpolating event data into the SQL string."
  },
  "ruby.aws-lambda.security.tainted-deserialization.tainted-deserialization": {
    priority: "HIGH",
    intent: "Do not deserialize event data with `Marshal.load` or YAML's unsafe loaders, which instantiate arbitrary Ruby objects. Use `JSON.parse`, or `YAML.safe_load` with an explicit permitted class list."
  },
  "ruby.aws-lambda.security.tainted-sql-string.tainted-sql-string": {
    priority: "HIGH",
    intent: "Do not build SQL by hand from the Lambda event. Use the database library's parameter binding so event data is always passed as a bound value rather than as SQL text."
  },
  "ruby.lang.security.bad-deserialization.bad-deserialization": {
    priority: "HIGH",
    intent: "Replace `Marshal.load` and unsafe YAML loading of untrusted input with `JSON.parse` or `YAML.safe_load`, restricting permitted classes to those you expect."
  },
  "ruby.lang.security.cookie-serialization.cookie-serialization": {
    priority: "HIGH",
    intent: "Set the Rails cookie serializer to `:json` rather than `:marshal` or `:hybrid`. Marshal-serialized cookies allow remote code execution if an attacker can forge or replay a cookie."
  },
  "ruby.lang.security.dangerous-exec.dangerous-exec": {
    priority: "HIGH",
    intent: "Keep the executed command static and pass user input only as separate arguments, using the multi-argument form of `system`/`exec` so no shell is involved."
  },
  "ruby.lang.security.dangerous-open.dangerous-open": {
    priority: "HIGH",
    intent: "Use `File.open` rather than `Kernel#open`, which executes the argument as a command when it begins with a pipe character. Validate the path and resolve it inside a fixed base directory."
  },
  "ruby.lang.security.dangerous-open3-pipeline.dangerous-open3-pipeline": {
    priority: "HIGH",
    intent: "Pass each command and its arguments to Open3 as separate array elements rather than as one string, so no shell interprets the input, and keep the program names static."
  },
  "ruby.lang.security.dangerous-subshell.dangerous-subshell": {
    priority: "HIGH",
    intent: "Remove the backtick subshell. Use the multi-argument form of `system` or Open3 with a fixed executable and separate arguments so user data is never interpreted by a shell."
  },
  "ruby.lang.security.dangerous-syscall.dangerous-syscall": {
    priority: "HIGH",
    intent: "Replace `syscall` with a supported Ruby API or an FFI binding such as Fiddle. `syscall` is unportable and takes raw numeric arguments, making it easy to invoke unintended behaviour."
  },
  "ruby.lang.security.mass-assignment-protection-disabled.mass-assignment-protection-disabled": {
    priority: "HIGH",
    intent: "Do not disable mass-assignment protection. Use strong parameters (`params.require(...).permit(...)`) to allowlist exactly the attributes a request may set, so sensitive fields cannot be assigned."
  },
  "ruby.lang.security.weak-hashes-md5.weak-hashes-md5": {
    priority: "HIGH",
    intent: "Replace MD5 with SHA-256 for integrity use. For passwords, use bcrypt, scrypt or Argon2 rather than any fast general-purpose hash."
  },
  "ruby.rails.security.brakeman.check-render-local-file-include.check-render-local-file-include": {
    priority: "HIGH",
    intent: "Do not pass request parameters to `render`. Map the validated parameter to a fixed set of permitted template or file names so a caller cannot select arbitrary local files."
  },
  "ruby.rails.security.brakeman.check-unscoped-find.check-unscoped-find": {
    priority: "HIGH",
    intent: "Scope the lookup to the current user or tenant, for example `current_user.orders.find(params[:id])`, so an attacker cannot read another user's record by changing the identifier."
  },
  "ruby.rails.security.injection.tainted-sql-string.tainted-sql-string": {
    priority: "HIGH",
    intent: "Do not build SQL strings from request parameters. Use `where` with placeholders or a hash condition so ActiveRecord binds the values."
  },
  "ruby.rails.security.injection.tainted-url-host.tainted-url-host": {
    priority: "HIGH",
    intent: "Do not build the host portion of a URL from user data. Keep the host fixed in configuration and allow only the path or query to vary, so requests and links cannot be redirected to an attacker's server."
  },

  // ==== Scala ====
  "scala.lang.security.audit.dangerous-seq-run.dangerous-seq-run": {
    priority: "HIGH",
    intent: "Keep the command static and pass user input only as separate sequence elements, so the process is executed without a shell. Validate any user-supplied argument against an allowlist."
  },
  "scala.lang.security.audit.dangerous-shell-run.dangerous-shell-run": {
    priority: "HIGH",
    intent: "Do not build shell command strings from dynamic content. Use the sequence form to invoke a fixed executable with separate arguments rather than passing a string to a shell."
  },
  "scala.lang.security.audit.dispatch-ssrf.dispatch-ssrf": {
    priority: "HIGH",
    intent: "Do not pass user input directly to `url`. Resolve the target from a server-side allowlist of hosts, and reject private, loopback and link-local addresses before making the request."
  },
  "scala.lang.security.audit.io-source-ssrf.io-source-ssrf": {
    priority: "HIGH",
    intent: "Do not pass user input to `Source.fromURL`. Validate the target against an allowlist of permitted hosts and block internal address ranges."
  },
  "scala.lang.security.audit.scalaj-http-ssrf.scalaj-http-ssrf": {
    priority: "HIGH",
    intent: "Do not construct `Http` requests from user-supplied URLs. Resolve the host from a server-side allowlist and block requests to internal address ranges."
  },
  "scala.play.security.webservice-ssrf.webservice-ssrf": {
    priority: "HIGH",
    intent: "Do not pass user input as the URL to `WSClient`. Choose the target from a server-side allowlist, disable or re-validate redirects, and block internal address ranges."
  },
  "scala.slick.security.scala-slick-overridesql-literal.scala-slick-overrideSql-literal": {
    priority: "HIGH",
    intent: "Do not build the overridden SQL from formatted strings. Use Slick's `sql`/`sqlu` interpolators, which bind interpolated values as query parameters."
  },
  "scala.slick.security.scala-slick-sql-non-literal.scala-slick-sql-non-literal": {
    priority: "HIGH",
    intent: "Use Slick's `sql` or `sqlu` string interpolator with a literal query so values are bound as parameters, rather than assembling the statement from a non-literal string."
  },

  // ==== Solidity ====
  "solidity.security.balancer-readonly-reentrancy-getpooltokens.balancer-readonly-reentrancy-getpooltokens": {
    priority: "HIGH",
    intent: "Guard the `getPoolTokens()` read against read-only reentrancy by checking the Balancer Vault's reentrancy state (`ensureNotInVaultContext`) before trusting the values, since balances can be observed mid-transaction while the pool is inconsistent."
  },
  "solidity.security.balancer-readonly-reentrancy-getrate.balancer-readonly-reentrancy-getrate": {
    priority: "HIGH",
    intent: "Check the Balancer Vault's reentrancy state before using `getRate()`, or derive the rate from a source that cannot be observed mid-callback. Read-only reentrancy lets an attacker read a stale rate during a transfer callback."
  },
  "solidity.security.compound-borrowfresh-reentrancy.compound-borrowfresh-reentrancy": {
    priority: "HIGH",
    intent: "Apply the checks-effects-interactions pattern: update all internal accounting before calling `doTransferOut()`. Performing the state update after the external transfer allows a reentrant call to borrow against stale balances."
  },
  "solidity.security.compound-sweeptoken-not-restricted.compound-sweeptoken-not-restricted": {
    priority: "HIGH",
    intent: "Restrict `sweepToken` to an authorised caller with an `onlyOwner` or role-based modifier, and prevent it sweeping the market's own underlying asset."
  },
  "solidity.security.curve-readonly-reentrancy.curve-readonly-reentrancy": {
    priority: "HIGH",
    intent: "Do not trust `get_virtual_price()` during a callback. Check the Curve pool's lock state first, or use an oracle value that cannot be manipulated by reentering mid-transaction."
  },
  "solidity.security.erc677-reentrancy.erc677-reentrancy": {
    priority: "HIGH",
    intent: "Complete all state updates before invoking `callAfterTransfer()`, and add a reentrancy guard. The recipient callback can otherwise re-enter the contract while balances are inconsistent."
  },
  "solidity.security.erc721-arbitrary-transferfrom.erc721-arbitrary-transferfrom": {
    priority: "HIGH",
    intent: "Add ownership and approval checks to `_transfer()`: require that the caller is the token owner or an approved operator, and that `from` actually owns the token."
  },
  "solidity.security.erc721-reentrancy.erc721-reentrancy": {
    priority: "HIGH",
    intent: "Update state before calling `onERC721Received()` and protect the function with a reentrancy guard, since the receiver hook hands control to an untrusted contract."
  },
  "solidity.security.erc777-reentrancy.erc777-reentrancy": {
    priority: "HIGH",
    intent: "Update balances before the `tokensReceived()` hook runs and add a reentrancy guard. ERC777 hooks give the recipient control during the transfer."
  },
  "solidity.security.keeper-network-oracle-manipulation.keeper-network-oracle-manipulation": {
    priority: "HIGH",
    intent: "Do not price assets from `Keep3rV2.current()` alone; it is cheap to manipulate. Use a time-weighted average price from a deep liquidity source, or aggregate several independent oracles with a deviation check."
  },
  "solidity.security.missing-self-transfer-check-ercx.missing-self-transfer-check-ercx": {
    priority: "HIGH",
    intent: "Require that `from` and `to` differ, or compute both balance updates from the same starting values, so a self-transfer cannot be used to mint balance out of the ordering of the two writes."
  },
  "solidity.security.proxy-storage-collision.proxy-storage-collision": {
    priority: "HIGH",
    intent: "Do not declare state variables in the proxy that share slots with the implementation. Use an unstructured storage layout at a hashed slot (the EIP-1967 pattern) so proxy and implementation storage cannot collide."
  },
  "solidity.security.redacted-cartel-custom-approval-bug.redacted-cartel-custom-approval-bug": {
    priority: "HIGH",
    intent: "Check and decrement the allowance of the `from` account in `transferFrom()`, keyed on `(from, msg.sender)`. Reading the wrong allowance entry lets a caller spend another account's approval."
  },
  "solidity.security.rigoblock-missing-access-control.rigoblock-missing-access-control": {
    priority: "HIGH",
    intent: "Add the `onlyOwner` modifier to `setMultipleAllowances()` so arbitrary callers cannot set token allowances."
  },
  "solidity.security.sense-missing-oracle-access-control.sense-missing-oracle-access-control": {
    priority: "HIGH",
    intent: "Restrict the oracle update function to an authorised address with an `onlyOwner` or role-based modifier, so prices cannot be set by an arbitrary caller."
  },
  "solidity.security.superfluid-ctx-injection.superfluid-ctx-injection": {
    priority: "HIGH",
    intent: "Validate the Superfluid context with the host's `isCtxValid`/`authorizeOperation` check before trusting it. Unvalidated context in calldata allows an attacker to impersonate another account."
  },
  "solidity.security.tecra-coin-burnfrom-bug.tecra-coin-burnfrom-bug": {
    priority: "HIGH",
    intent: "Index the `_allowances` mapping as `_allowances[from][msg.sender]` when checking and reducing the allowance in `burnFrom()`. Checking the wrong position lets a caller burn tokens they were never approved to spend."
  },

  // ==== Swift ====
  "swift.lang.storage.sensitive-storage-userdefaults.swift-user-defaults": {
    priority: "HIGH",
    intent: "Do not store sensitive values in `UserDefaults`, which is an unencrypted plist readable from a device backup. Use the Keychain, with an appropriate accessibility class, for credentials and tokens."
  },

  // ==== Terraform ====
  "terraform.aws.security.aws-ebs-volume-unencrypted.aws-ebs-volume-unencrypted": {
    priority: "HIGH",
    intent: "Set `encrypted = true` on the `aws_ebs_volume` resource, and supply a `kms_key_id` where a customer-managed key is required. Encryption cannot be enabled in place after creation, so unencrypted volumes must be replaced."
  },
  "terraform.aws.security.aws-ec2-launch-template-metadata-service-v1-enabled.aws-ec2-launch-template-metadata-service-v1-enabled": {
    priority: "HIGH",
    intent: "Require IMDSv2 in the launch template's `metadata_options` block by setting `http_tokens = \"required\"`. IMDSv2's session tokens prevent SSRF from reaching the metadata service and stealing instance credentials."
  },
  "terraform.aws.security.aws-ecr-mutable-image-tags.aws-ecr-mutable-image-tags": {
    priority: "HIGH",
    intent: "Set `image_tag_mutability = \"IMMUTABLE\"` on the `aws_ecr_repository` so a tag cannot be repointed to a different image after it has been reviewed and deployed."
  },
  "terraform.aws.security.aws-kinesis-stream-unencrypted.aws-kinesis-stream-unencrypted": {
    priority: "HIGH",
    intent: "Enable server-side encryption on the Kinesis stream by setting `encryption_type = \"KMS\"` and a `kms_key_id`, so records are encrypted at rest."
  },
  "terraform.aws.security.aws-lambda-environment-credentials.aws-lambda-environment-credentials": {
    priority: "HIGH",
    intent: "Remove the credential from the Lambda function's environment variables and rotate it. Grant the function an IAM execution role for AWS access, and read any remaining third-party secret from Secrets Manager or Parameter Store at runtime."
  },
  "terraform.aws.security.unrestricted-github-oidc-policy.unrestricted-github-oidc-policy": {
    priority: "HIGH",
    intent: "Add a `condition` block to the GitHub OIDC trust policy that restricts `token.actions.githubusercontent.com:sub` to your specific repository, and branch or environment. Without it, any GitHub repository can assume the role."
  },

  // ==== Trail of Bits - Python ====
  "trailofbits.python.pickles-in-numpy.pickles-in-numpy": {
    priority: "HIGH",
    intent: "Load NumPy data with `allow_pickle=False`. Pickled arrays execute arbitrary code on load; use `.npy`/`.npz` without object arrays, or a format such as Arrow or HDF5, for data you do not fully control."
  },
  "trailofbits.python.pickles-in-pandas.pickles-in-pandas": {
    priority: "HIGH",
    intent: "Do not read untrusted data with `pandas.read_pickle`, which executes code during unpickling. Use Parquet, CSV or Arrow for interchange instead."
  },
  "trailofbits.python.pickles-in-pytorch.pickles-in-pytorch": {
    priority: "HIGH",
    intent: "Load PyTorch checkpoints with `weights_only=True`, or load a `state_dict` into a model you construct yourself, so the file cannot execute code during unpickling."
  },

  // ==== TypeScript ====
  "typescript.aws-cdk.security.audit.awscdk-bucket-encryption.awscdk-bucket-encryption": {
    priority: "HIGH",
    intent: "Set `encryption` on the CDK `Bucket` props to `BucketEncryption.S3_MANAGED`, or `KMS_MANAGED`/`KMS` where a customer-managed key is required, so objects are encrypted at rest."
  },
  "typescript.aws-cdk.security.audit.awscdk-sqs-unencryptedqueue.awscdk-sqs-unencryptedqueue": {
    priority: "HIGH",
    intent: "Set `encryption` on the CDK `Queue` props to `QueueEncryption.KMS_MANAGED`, or `KMS` with your own key, so messages are encrypted at rest."
  },
  "typescript.aws-cdk.security.awscdk-bucket-grantpublicaccessmethod.awscdk-bucket-grantpublicaccessmethod": {
    priority: "HIGH",
    intent: "Remove the `grantPublicAccess()` call, which makes every object world readable. Serve content through a CloudFront distribution with an origin access identity, or grant read access to specific principals."
  },
  "typescript.lang.security.audit.cors-regex-wildcard.cors-regex-wildcard": {
    priority: "LOW",
    intent: "Avoid regex wildcards in CORS origin validation. Use explicit origin allowlists: `if (allowedOrigins.includes(origin)) { ... }`."
  },

  // ==== YAML - CI, Kubernetes and OpenAPI ====
  "yaml.argo.security.argo-workflow-parameter-command-injection.argo-workflow-parameter-command-injection": {
    priority: "HIGH",
    intent: "Do not interpolate workflow or input parameters into a here-script. Pass them as environment variables and reference the variables in the script, so parameter values cannot be parsed as shell code."
  },
  "yaml.docker-compose.security.exposing-docker-socket-volume.exposing-docker-socket-volume": {
    priority: "HIGH",
    intent: "Remove the `/var/run/docker.sock` volume mount. Access to the daemon socket is equivalent to root on the host; use a scoped API proxy or a rootless builder if the service genuinely needs to manage containers."
  },
  "yaml.docker-compose.security.no-new-privileges.no-new-privileges": {
    priority: "HIGH",
    intent: "Add `no-new-privileges:true` to the service's `security_opt` so a process inside the container cannot gain privileges through setuid or setgid binaries."
  },
  "yaml.docker-compose.security.privileged-service.privileged-service": {
    priority: "HIGH",
    intent: "Remove `privileged: true`. Grant only the specific Linux capabilities the service needs via `cap_add`, since privileged mode gives the container the equivalent of root on the host."
  },
  "yaml.docker-compose.security.seccomp-confinement-disabled.seccomp-confinement-disabled": {
    priority: "HIGH",
    intent: "Remove `seccomp:unconfined` from `security_opt` so the default seccomp profile applies. If a specific syscall is required, supply a narrow custom profile instead of disabling confinement."
  },
  "yaml.docker-compose.security.selinux-separation-disabled.selinux-separation-disabled": {
    priority: "HIGH",
    intent: "Remove `label:disable` from `security_opt` so SELinux separation stays in force. Use a specific label if the service needs access to a particular host resource."
  },
  "yaml.docker-compose.security.writable-filesystem-service.writable-filesystem-service": {
    priority: "HIGH",
    intent: "Set `read_only: true` on the service and mount named volumes or `tmpfs` for the specific paths that must be writable, so a compromised process cannot persist payloads in the image filesystem."
  },
  "yaml.github-actions.security.allowed-unsecure-commands.allowed-unsecure-commands": {
    priority: "MEDIUM",
    intent: "Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` from your workflow. This enables deprecated commands that can be exploited for command injection. Use environment files instead."
  },
  "yaml.github-actions.security.curl-eval.curl-eval": {
    priority: "HIGH",
    intent: "Do not evaluate the output of a `curl` command. Download to a file, verify it against a pinned checksum or signature, and then run it, so a compromised or hijacked server cannot inject code into the workflow."
  },
  "yaml.github-actions.security.detect-shai-hulud-backdoor.detect-shai-hulud-backdoor": {
    priority: "HIGH",
    intent: "Delete this workflow file; it is a backdoor planted by the Shai-Hulud worm rather than a legitimate action. Audit the repository and its published packages for other changes, and rotate every credential the workflow could reach."
  },
  "yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell": {
    priority: "HIGH",
    intent: "Do not pipe `curl` or `wget` output straight into a shell. Download the script, verify a pinned checksum or signature, then execute it, so a change on the remote host cannot silently run arbitrary code in the job."
  },
  "yaml.github-actions.security.gha-workflow-env-secret.gha-workflow-env-secret": {
    priority: "HIGH",
    intent: "Move the secret out of the workflow-level `env:` block and into the specific job or step that needs it, so it is not exposed to every step in the workflow, including third-party actions."
  },
  "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag": {
    priority: "HIGH",
    intent: "Pin the action to a full commit SHA rather than a tag or branch. Tags can be repointed by the action owner, which silently changes the code running in your workflow."
  },
  "yaml.github-actions.security.github-script-injection.github-script-injection": {
    priority: "HIGH",
    intent: "Do not interpolate `${{ github.* }}` values into an `actions/github-script` `script:` block. Pass them through `env:` and read them from `process.env` inside the script, so attacker-controlled text cannot become code."
  },
  "yaml.github-actions.security.pull-request-target-code-checkout.pull-request-target-code-checkout": {
    priority: "HIGH",
    intent: "When using `pull_request_target`, avoid checking out code from the incoming pull request as it runs with access to repository secrets. Either use `pull_request` trigger instead, or ensure no code from the incoming PR is executed (no build scripts, no dependency installation). See https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
  },
  "yaml.github-actions.security.run-shell-injection.run-shell-injection": {
    priority: "HIGH",
    intent: "Avoid using variable interpolation `${{...}}` with `github` context data directly in `run:` steps. Instead, use an intermediate environment variable with `env:` to store the data, then reference the environment variable in the script using double quotes: \"$ENVVAR\"."
  },
  "yaml.github-actions.security.secrets-inherit.secrets-inherit": {
    priority: "HIGH",
    intent: "Replace `secrets: inherit` with an explicit `secrets:` mapping listing only the secrets the reusable workflow needs, so it cannot access the caller's entire secret set."
  },
  "yaml.kubernetes.security.exposing-docker-socket-hostpath.exposing-docker-socket-hostpath": {
    priority: "HIGH",
    intent: "Remove the `hostPath` volume that mounts the Docker socket. Access to it is equivalent to root on the node; use a purpose-built controller or a rootless build backend instead."
  },
  "yaml.kubernetes.security.legacy-api-clusterrole-excessive-permissions.legacy-api-clusterrole-excessive-permissions": {
    priority: "HIGH",
    intent: "Narrow the ClusterRole's rules to the specific resources and verbs required, and avoid wildcards on core API groups. Bind it with a namespaced RoleBinding where cluster-wide scope is not needed."
  },
  "yaml.openapi.security.openai-consequential-action-false.openai-consequential-action-false": {
    priority: "HIGH",
    intent: "Set `x-openai-isConsequential: true` for state-changing operations. Marking them false enables 'Always Allow', so the action can be invoked repeatedly without the user confirming each call."
  },
  "yaml.openapi.security.use-of-basic-authentication.use-of-basic-authentication": {
    priority: "HIGH",
    intent: "Replace the basic authentication scheme with OAuth2, OpenID Connect or mTLS. Basic auth sends reusable credentials on every request and offers no scoping or expiry."
  },
};
