const WILDCARD = '*';
const LAMBDA_SERVICE_PRINCIPAL = 'lambda.amazonaws.com';

const BROAD_POLICY_NAMES = ['administratoraccess', 'poweruseraccess'];
const BROAD_POLICY_SUFFIXES = ['fullaccess', 'admin', 'administrator'];

/**
 * True when the document contains an allow grant that is not scoped to specific
 * resource identifiers (i.e. it targets every resource).
 */
export function hasWildcardActionAndResource(document: unknown): boolean {
  return statementsOf(document).some(isUnscopedAllowStatement);
}

/**
 * True when the trust policy lets the Lambda service assume the role. Lambda cannot assume a role
 * without this principal, so it identifies an execution role even where no function is in scope.
 */
export function trustsLambdaServicePrincipal(document: unknown): boolean {
  return statementsOf(document).some(allowsLambdaToAssume);
}

/** True when the reference names an administrator-level or service-wide managed policy. */
export function isBroadManagedPolicy(reference: unknown): boolean {
  const name = policyNameOf(reference);
  if (name === null) return false;
  if (BROAD_POLICY_NAMES.includes(name)) return true;
  return BROAD_POLICY_SUFFIXES.some(suffix => name.endsWith(suffix));
}

function policyNameOf(reference: unknown): string | null {
  if (typeof reference !== 'string') return null;
  const lastSegment = reference.split('/').pop();
  return lastSegment ? lastSegment.toLowerCase() : null;
}

function statementsOf(document: unknown): Record<string, unknown>[] {
  const parsed = asDocument(document);
  if (parsed === null) return [];
  return toArray(parsed['Statement']).filter(isRecord);
}

function asDocument(document: unknown): Record<string, unknown> | null {
  if (typeof document === 'string') return parseJson(document);
  return isRecord(document) ? document : null;
}

function parseJson(value: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function allowsLambdaToAssume(statement: Record<string, unknown>): boolean {
  if (statement['Effect'] !== undefined && statement['Effect'] !== 'Allow') return false;
  const principal = statement['Principal'];
  if (!isRecord(principal)) return false;
  return toArray(principal['Service']).includes(LAMBDA_SERVICE_PRINCIPAL);
}

function isUnscopedAllowStatement(statement: Record<string, unknown>): boolean {
  if (statement['Effect'] !== undefined && statement['Effect'] !== 'Allow') return false;
  if (!grantsAnyAction(statement)) return false;
  return coversAllResources(statement);
}

function grantsAnyAction(statement: Record<string, unknown>): boolean {
  return toArray(statement['Action']).length > 0 || toArray(statement['NotAction']).length > 0;
}

function coversAllResources(statement: Record<string, unknown>): boolean {
  return containsWildcard(statement['Resource']) || containsWildcard(statement['NotResource']);
}

function containsWildcard(value: unknown): boolean {
  return toArray(value).some(entry => entry === WILDCARD);
}

function toArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  return value === undefined || value === null ? [] : [value];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
