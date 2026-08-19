import { isUnresolved } from '../../../terraform-rule-base.js';

const REQUIRED_ACTIONS = ['s3:getbucketacl', 's3:getbucketlocation'] as const;
const ARN_PREFIX = 'arn:aws:s3:::';

export interface PolicyStatement {
  /** True when the statement's contents could not be determined. */
  readonly unknown: boolean;
  readonly allow: boolean;
  readonly actions: string[];
  readonly notActions: string[];
  readonly resources: string[];
  readonly notResources: string[];
}

const UNKNOWN_STATEMENT: PolicyStatement = {
  unknown: true,
  allow: true,
  actions: [],
  notActions: [],
  resources: [],
  notResources: [],
};

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function toArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * The bucket name a project location denotes, or null when the location is not
 * a usable literal.
 */
export function bucketNameFromLocation(location: unknown): string | null {
  if (typeof location !== 'string') return null;
  const literal = location.startsWith(ARN_PREFIX) ? location.slice(ARN_PREFIX.length) : location;
  const bucket = literal.split('/')[0]?.trim();
  return bucket ? bucket : null;
}

export function parsePolicyDocument(document: unknown): PolicyStatement[] {
  const parsed = typeof document === 'string' ? parseJsonDocument(document) : document;
  if (parsed === undefined) return [UNKNOWN_STATEMENT];
  if (!isRecord(parsed)) return [];
  if (isIntrinsic(parsed)) return [UNKNOWN_STATEMENT];
  return toArray(parsed['Statement']).map(toStatement);
}

export function statementsAllowRequiredActions(statements: PolicyStatement[], bucket: string): boolean {
  if (statements.some(statement => statement.unknown)) return true;
  return REQUIRED_ACTIONS.every(action => isEffectivelyAllowed(statements, action, bucket));
}

function isEffectivelyAllowed(statements: PolicyStatement[], action: string, bucket: string): boolean {
  const relevant = statements.filter(statement => covers(statement, action, bucket));
  if (relevant.some(statement => !statement.allow)) return false;
  return relevant.some(statement => statement.allow);
}

function covers(statement: PolicyStatement, action: string, bucket: string): boolean {
  return coversAction(statement, action) && coversResource(statement, bucket);
}

function coversAction(statement: PolicyStatement, action: string): boolean {
  if (statement.notActions.length > 0) return !statement.notActions.some(pattern => matches(pattern, action));
  return statement.actions.some(pattern => matches(pattern, action));
}

function coversResource(statement: PolicyStatement, bucket: string): boolean {
  const candidates = [`${ARN_PREFIX}${bucket}`.toLowerCase(), bucket.toLowerCase()];
  const covers = (pattern: string) => candidates.some(value => matches(pattern, value));
  if (statement.notResources.length > 0) {
    return !statement.notResources.some(covers);
  }
  if (statement.resources.length === 0) return true;
  return statement.resources.some(covers);
}

function matches(pattern: string, value: string): boolean {
  const escaped = pattern
    .toLowerCase()
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`).test(value);
}

function toStatement(statement: unknown): PolicyStatement {
  if (!isRecord(statement)) return UNKNOWN_STATEMENT;
  const fields = ['Action', 'NotAction', 'Resource', 'NotResource', 'Effect'];
  if (fields.some(field => isUnknownField(statement[field]))) return UNKNOWN_STATEMENT;
  return {
    unknown: false,
    allow: String(statement['Effect'] ?? 'Allow').toLowerCase() !== 'deny',
    actions: strings(statement['Action']),
    notActions: strings(statement['NotAction']),
    resources: strings(statement['Resource']),
    notResources: strings(statement['NotResource']),
  };
}

function isUnknownField(value: unknown): boolean {
  return toArray(value).some(entry => typeof entry !== 'string' || isUnresolved(entry));
}

function strings(value: unknown): string[] {
  return toArray(value)
    .filter((entry): entry is string => typeof entry === 'string')
    .map(entry => entry.toLowerCase());
}

function isIntrinsic(value: Record<string, unknown>): boolean {
  return Object.keys(value).some(key => key.startsWith('Fn::') || key === 'Ref');
}

/** Undefined when the text is not a policy document the scanner can read. */
function parseJsonDocument(text: string): unknown {
  if (isUnresolved(text)) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
