import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { PolicyStatement, S3002Adapter } from './s3-002.adapter.js';

const WILDCARD_PRINCIPAL_FINDING = 'wildcard-principal-without-condition';
const UNRESTRICTED_SERVICE_PRINCIPAL_FINDING = 'service-principal-without-source-scope';

const SOURCE_SCOPE_CONDITION_KEYS = ['aws:SourceAccount', 'aws:SourceArn', 'aws:SourceOwner'];

/**
 * Only these narrow WHO may use a wildcard grant. A condition on a request
 * property — aws:SecureTransport, s3:x-amz-acl — restricts how the caller asks,
 * not which callers qualify, so it leaves the grant open to everyone.
 */
const IDENTITY_SCOPE_CONDITION_KEYS = [
  'aws:PrincipalOrgID',
  'aws:PrincipalOrgPaths',
  'aws:PrincipalArn',
  'aws:PrincipalAccount',
  'aws:SourceAccount',
  'aws:SourceArn',
  'aws:SourceOwner',
  'aws:SourceVpc',
  'aws:SourceVpce',
  'aws:SourceIp',
  'aws:VpcSourceIp',
  'aws:userid',
  'aws:PrincipalTag',
];

const FINDINGS = {
  [WILDCARD_PRINCIPAL_FINDING]: {
    issue: 'Bucket policy Allow statement grants access to a wildcard principal without any condition constraining who may assume it',
    remediation: 'Restrict the bucket policy allow statement so it targets specific, trusted principals, or scope the wildcard principal with a condition that constrains who may assume it.',
  },
  [UNRESTRICTED_SERVICE_PRINCIPAL_FINDING]: {
    issue: 'Bucket policy Allow statement grants access to an AWS service principal without a condition restricting the source account or source ARN',
    remediation: 'Constrain the service-principal allow statement with a condition that binds it to a specific source account or source ARN so it cannot be invoked on behalf of arbitrary accounts.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class S3002Control extends SecurityControl<S3002Adapter, FindingKey> {
  constructor() {
    super({
      id: 'S3-002',
      priority: 'HIGH',
      description: 'S3 bucket policies must not grant access to untrusted principals',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: S3002Adapter): FindingKey | null {
    const statements = adapter.getPolicyStatements();
    if (statements.some(isUnconditionalWildcardAllow)) return WILDCARD_PRINCIPAL_FINDING;
    if (statements.some(isUnrestrictedServicePrincipalAllow)) return UNRESTRICTED_SERVICE_PRINCIPAL_FINDING;
    return null;
  }
}

function isUnconditionalWildcardAllow(statement: PolicyStatement): boolean {
  if (!isAllow(statement.effect)) return false;
  if (hasIdentityScopeCondition(statement.condition)) return false;
  return isWildcardPrincipal(statement.principal);
}

function isUnrestrictedServicePrincipalAllow(statement: PolicyStatement): boolean {
  if (!isAllow(statement.effect)) return false;
  if (!hasServicePrincipal(statement.principal)) return false;
  return !hasSourceScopeCondition(statement.condition);
}

function isAllow(effect: unknown): boolean {
  return typeof effect === 'string' && effect.toLowerCase() === 'allow';
}

function hasIdentityScopeCondition(condition: unknown): boolean {
  return conditionReferencesKey(condition, IDENTITY_SCOPE_CONDITION_KEYS);
}

function isWildcardPrincipal(principal: unknown): boolean {
  if (principal === '*') return true;
  if (typeof principal !== 'object' || principal === null) return false;
  return Object.values(principal as Record<string, unknown>).some(containsWildcard);
}

function containsWildcard(value: unknown): boolean {
  if (value === '*') return true;
  if (Array.isArray(value)) return value.some(containsWildcard);
  return false;
}

function hasServicePrincipal(principal: unknown): boolean {
  if (typeof principal !== 'object' || principal === null) return false;
  const service = (principal as Record<string, unknown>)['Service'];
  if (service === undefined || service === null) return false;
  if (typeof service === 'string') return service.length > 0;
  if (Array.isArray(service)) return service.some((entry) => typeof entry === 'string' && entry.length > 0);
  return false;
}

function hasSourceScopeCondition(condition: unknown): boolean {
  return conditionReferencesKey(condition, SOURCE_SCOPE_CONDITION_KEYS);
}

/**
 * IAM condition keys are case-insensitive, and operators may be wrapped in
 * ForAnyValue:/ForAllValues:/...IfExists variants, so the operator name is not
 * inspected — only the keys it constrains.
 */
function conditionReferencesKey(condition: unknown, scopeKeys: readonly string[]): boolean {
  if (typeof condition !== 'object' || condition === null) return false;
  for (const operatorValue of Object.values(condition as Record<string, unknown>)) {
    if (typeof operatorValue !== 'object' || operatorValue === null) continue;
    const keys = Object.keys(operatorValue as Record<string, unknown>);
    if (keys.some((key) => matchesScopeKey(key, scopeKeys))) return true;
  }
  return false;
}

function matchesScopeKey(key: string, scopeKeys: readonly string[]): boolean {
  const lowered = key.toLowerCase();
  return scopeKeys.some((scopeKey) => scopeKey.toLowerCase() === lowered);
}

export const s3002Control = new S3002Control();
