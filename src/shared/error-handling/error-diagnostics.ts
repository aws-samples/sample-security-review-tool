const MAX_CAUSE_DEPTH = 10;

export interface AwsErrorMetadata {
    httpStatusCode?: number;
    requestId?: string;
    extendedRequestId?: string;
    cfId?: string;
    attempts?: number;
    totalRetryDelay?: number;
}

export interface ErrorDiagnostic {
    name: string;
    message: string;
    stack?: string;
    code?: string | number;
    fault?: string;
    originalStatusCode?: number;
    originalMessage?: string;
    resourceName?: string;
    path?: string;
    syscall?: string;
    errno?: string | number;
    retryable?: boolean;
    throttling?: boolean;
    metadata?: AwsErrorMetadata;
}

export function errorCauseChain(error: unknown): unknown[] {
    const chain: unknown[] = [];
    const seen = new Set<object>();
    let current: unknown = error;

    while (chain.length < MAX_CAUSE_DEPTH) {
        if (isObject(current)) {
            if (seen.has(current)) break;
            seen.add(current);
        }

        chain.push(current);
        if (!isObject(current)) break;
        const cause = readProperty(current, "cause");
        if (cause === undefined) break;
        current = cause;
    }

    return chain;
}

export function describeErrorChain(error: unknown): ErrorDiagnostic[] {
    return errorCauseChain(error).map(describeError);
}

export function formatErrorSummary(error: unknown): string {
    return describeErrorChain(error)
        .map((diagnostic, index) => {
            const prefix = index === 0 ? "" : "caused by ";
            const attributes = diagnosticAttributes(diagnostic);
            const detail =
                attributes.length > 0 ? ` (${attributes.join(", ")})` : "";
            const originalMessage =
                diagnostic.originalMessage &&
                diagnostic.originalMessage !== diagnostic.message
                    ? `\n  provider message: ${diagnostic.originalMessage}`
                    : "";
            return `${prefix}${diagnostic.name}: ${diagnostic.message}${detail}${originalMessage}`;
        })
        .join("\n");
}

function describeError(error: unknown): ErrorDiagnostic {
    if (!isObject(error)) {
        return {
            name: typeof error,
            message: safeString(error),
        };
    }

    const retryable = readProperty(error, "$retryable");
    const diagnostic: ErrorDiagnostic = {
        name: readString(error, "name") ?? error.constructor?.name ?? "Error",
        message: readString(error, "message") ?? safeString(error),
    };

    assignString(diagnostic, "stack", readProperty(error, "stack"));
    assignStringOrNumber(diagnostic, "code", readProperty(error, "code"));
    assignString(diagnostic, "fault", readProperty(error, "$fault"));
    assignNumber(
        diagnostic,
        "originalStatusCode",
        readProperty(error, "originalStatusCode"),
    );
    assignString(
        diagnostic,
        "originalMessage",
        readProperty(error, "originalMessage"),
    );
    assignString(
        diagnostic,
        "resourceName",
        readProperty(error, "resourceName"),
    );
    assignString(diagnostic, "path", readProperty(error, "path"));
    assignString(diagnostic, "syscall", readProperty(error, "syscall"));
    assignStringOrNumber(diagnostic, "errno", readProperty(error, "errno"));

    if (retryable !== undefined) diagnostic.retryable = true;
    if (isObject(retryable)) {
        const throttling = readProperty(retryable, "throttling");
        if (typeof throttling === "boolean") diagnostic.throttling = throttling;
    }

    const metadata = describeAwsMetadata(readProperty(error, "$metadata"));
    if (metadata) diagnostic.metadata = metadata;

    return diagnostic;
}

function describeAwsMetadata(value: unknown): AwsErrorMetadata | undefined {
    if (!isObject(value)) return undefined;

    const metadata: AwsErrorMetadata = {};
    assignNumber(
        metadata,
        "httpStatusCode",
        readProperty(value, "httpStatusCode"),
    );
    assignString(metadata, "requestId", readProperty(value, "requestId"));
    assignString(
        metadata,
        "extendedRequestId",
        readProperty(value, "extendedRequestId"),
    );
    assignString(metadata, "cfId", readProperty(value, "cfId"));
    assignNumber(metadata, "attempts", readProperty(value, "attempts"));
    assignNumber(
        metadata,
        "totalRetryDelay",
        readProperty(value, "totalRetryDelay"),
    );

    return Object.keys(metadata).length > 0 ? metadata : undefined;
}

function diagnosticAttributes(diagnostic: ErrorDiagnostic): string[] {
    const attributes: string[] = [];
    if (diagnostic.metadata?.httpStatusCode !== undefined)
        attributes.push(`HTTP ${diagnostic.metadata.httpStatusCode}`);
    if (diagnostic.originalStatusCode !== undefined)
        attributes.push(`original status ${diagnostic.originalStatusCode}`);
    if (diagnostic.metadata?.requestId)
        attributes.push(`request ${diagnostic.metadata.requestId}`);
    if (diagnostic.metadata?.attempts !== undefined)
        attributes.push(`${diagnostic.metadata.attempts} SDK attempt(s)`);
    if (diagnostic.code !== undefined)
        attributes.push(`code ${diagnostic.code}`);
    return attributes;
}

function isObject(value: unknown): value is Record<PropertyKey, unknown> {
    return (
        (typeof value === "object" && value !== null) ||
        typeof value === "function"
    );
}

function readProperty(
    object: Record<PropertyKey, unknown>,
    property: PropertyKey,
): unknown {
    try {
        return object[property];
    } catch {
        return undefined;
    }
}

function readString(
    object: Record<PropertyKey, unknown>,
    property: PropertyKey,
): string | undefined {
    const value = readProperty(object, property);
    return typeof value === "string" ? value : undefined;
}

function assignString<T extends object, K extends keyof T>(
    target: T,
    key: K,
    value: unknown,
): void {
    if (typeof value === "string") target[key] = value as T[K];
}

function assignNumber<T extends object, K extends keyof T>(
    target: T,
    key: K,
    value: unknown,
): void {
    if (typeof value === "number") target[key] = value as T[K];
}

function assignStringOrNumber<T extends object, K extends keyof T>(
    target: T,
    key: K,
    value: unknown,
): void {
    if (typeof value === "string" || typeof value === "number")
        target[key] = value as T[K];
}

function safeString(value: unknown): string {
    try {
        return String(value);
    } catch {
        return "<unprintable>";
    }
}
