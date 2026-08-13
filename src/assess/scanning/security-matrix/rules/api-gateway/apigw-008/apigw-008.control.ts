import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Apigw008Adapter } from './apigw-008.adapter.js';

const UNENCRYPTED_CACHE = 'unencrypted-cache';

export class Apigw008Control extends SecurityControl<Apigw008Adapter> {
  constructor() {
    super({
      id: 'APIGW-008',
      priority: 'HIGH',
      description: 'API Gateway stages with caching enabled must have cache data encryption enabled for all cached methods (via a catch-all or per-method setting)',
      supersedes: ['CKV_AWS_308'],
      remediationScenarios: [
        {
          scenario: UNENCRYPTED_CACHE,
          intent: 'Enable encryption of cached response data for every method that has response caching enabled on the API stage.',
        },
      ],
    });
  }

  protected evaluate(adapter: Apigw008Adapter): ControlFinding | null {
    if (!adapter.hasUnencryptedCachedMethod()) return null;
    return {
      scenario: UNENCRYPTED_CACHE,
      issue: 'API stage has response caching enabled for one or more methods while the cached response data is not encrypted at rest',
    };
  }
}

export const apigw008Control = new Apigw008Control();
