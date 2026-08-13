type Dict = Record<string, unknown>;

const S3_URI_SCHEME = 's3://';
const SECURE_TRANSPORT_CONDITION_KEY = 'aws:securetransport';
const BOOLEAN_OPERATOR_FRAGMENT = 'bool';
const ALL_ACTIONS = ['*', 's3:*'];
const ALL_RESOURCES = '*';
const ALL_PRINCIPALS = '*';
const OBJECT_SCOPE_SUFFIX = '/*';

/** Whether a bucket policy demonstrably enforces TLS, demonstrably does not, or cannot be decided. */
export type TlsEnforcementVerdict = 'enforced' | 'not-enforced' | 'unknown';

/** Extracts the bucket identifier from an Athena output location such as `s3://bucket/prefix/`. */
export function bucketFromOutputLocation(outputLocation: string): string {
  const trimmed = outputLocation.trim();
  const withoutScheme = trimmed.toLowerCase().startsWith(S3_URI_SCHEME)
    ? trimmed.slice(S3_URI_SCHEME.length)
    : trimmed;
  return withoutScheme.split('/')[0] ?? '';
}

/**
 * Classifies a bucket policy document. A document enforces TLS when it contains a Deny
 * statement that fires on every non-TLS request to the bucket and its objects. Documents that
 * cannot be resolved at analysis time are reported as unknown so callers can stay silent.
 */
export function evaluateTlsEnforcement(policyDocument: unknown): TlsEnforcementVerdict {
  const document = asPolicyDocument(policyDocument);
  if (document === null || containsUnresolvedIntrinsic(document)) return 'unknown';
  return statementsOf(document).some(enforcesTlsForAllRequests) ? 'enforced' : 'not-enforced';
}

function asPolicyDocument(value: unknown): Dict | null {
  if (typeof value === 'string') return parseJson(value);
  return asDict(value);
}

function parseJson(value: string): Dict | null {
  try {
    return asDict(JSON.parse(value));
  } catch {
    return null;
  }
}

function containsUnresolvedIntrinsic(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsUnresolvedIntrinsic);
  const dict = asDict(value);
  if (!dict) return false;
  if (Object.keys(dict).some(isIntrinsicKey)) return true;
  return Object.values(dict).some(containsUnresolvedIntrinsic);
}

function isIntrinsicKey(key: string): boolean {
  return key === 'Ref' || key.startsWith('Fn::');
}

function statementsOf(document: Dict): Dict[] {
  const statement = document['Statement'] ?? document['statement'];
  return toArray(statement)
    .map(asDict)
    .filter((entry): entry is Dict => entry !== null);
}

function enforcesTlsForAllRequests(statement: Dict): boolean {
  return isDeny(field(statement, 'Effect'))
    && appliesToAllPrincipals(statement)
    && coversAllActions(field(statement, 'Action'))
    && coversBucketAndObjects(field(statement, 'Resource'))
    && firesOnlyOnInsecureTransport(field(statement, 'Condition'));
}

function field(statement: Dict, name: string): unknown {
  return statement[name] ?? statement[name.toLowerCase()];
}

function isDeny(effect: unknown): boolean {
  return typeof effect === 'string' && effect.toLowerCase() === 'deny';
}

function appliesToAllPrincipals(statement: Dict): boolean {
  if (field(statement, 'NotPrincipal') !== undefined) return false;
  const principal = field(statement, 'Principal');
  if (principal === undefined) return true;
  return principalValues(principal).includes(ALL_PRINCIPALS);
}

function principalValues(principal: unknown): string[] {
  const dict = asDict(principal);
  const raw = dict ? Object.values(dict) : [principal];
  return raw.flatMap(toArray).filter((entry): entry is string => typeof entry === 'string');
}

function coversAllActions(action: unknown): boolean {
  if (action === undefined) return true;
  return strings(action).some(entry => ALL_ACTIONS.includes(entry.toLowerCase()));
}

function coversBucketAndObjects(resource: unknown): boolean {
  if (resource === undefined) return true;
  const scopes = strings(resource);
  return scopes.some(isBucketScope) && scopes.some(isObjectScope);
}

function isBucketScope(scope: string): boolean {
  return scope === ALL_RESOURCES || !scope.replace(/^arn:[^:]*:s3:::/, '').includes('/');
}

function isObjectScope(scope: string): boolean {
  return scope === ALL_RESOURCES || scope.endsWith(OBJECT_SCOPE_SUFFIX);
}

/**
 * True when the only thing gating the Deny is aws:SecureTransport being false. Any additional
 * condition key would carve requests out of the Deny, leaving plaintext access possible.
 */
function firesOnlyOnInsecureTransport(condition: unknown): boolean {
  const operators = asDict(condition);
  if (!operators) return false;
  const comparisons = Object.entries(operators);
  if (comparisons.length === 0) return false;
  return comparisons.every(([operator, comparison]) =>
    isBooleanOperator(operator) && deniesInsecureTransportOnly(comparison));
}

function isBooleanOperator(operator: string): boolean {
  return operator.toLowerCase().includes(BOOLEAN_OPERATOR_FRAGMENT);
}

function deniesInsecureTransportOnly(comparison: unknown): boolean {
  const keys = asDict(comparison);
  if (!keys) return false;
  const entries = Object.entries(keys);
  if (entries.length === 0) return false;
  return entries.every(([key, value]) =>
    key.toLowerCase() === SECURE_TRANSPORT_CONDITION_KEY && isFalse(value));
}

function isFalse(value: unknown): boolean {
  return toArray(value).every(entry => entry === false || String(entry).toLowerCase() === 'false');
}

function strings(value: unknown): string[] {
  return toArray(value).filter((entry): entry is string => typeof entry === 'string');
}

function toArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function asDict(value: unknown): Dict | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Dict) : null;
}
