import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Apigw008Adapter } from './apigw-008.adapter.js';

const UNENCRYPTED_CACHE = 'unencrypted-cache';

const FINDINGS = {
  [UNENCRYPTED_CACHE]: {
    issue: 'API stage has response caching enabled for one or more methods while the cached response data is not encrypted at rest',
    remediation: 'Enable encryption of cached response data for every method that has response caching enabled on the API stage.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Apigw008Control extends SecurityControl<Apigw008Adapter, FindingKey> {
  constructor() {
    super({
      id: 'APIGW-008',
      priority: 'HIGH',
      description: 'API Gateway stages with caching enabled must have cache data encryption enabled for all cached methods (via a catch-all or per-method setting)',
      supersedes: ['CKV_AWS_308'],
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Apigw008Adapter): FindingKey | null {
    if (!adapter.hasUnencryptedCachedMethod()) return null;
    return UNENCRYPTED_CACHE;
  }
}

export const apigw008Control = new Apigw008Control();
