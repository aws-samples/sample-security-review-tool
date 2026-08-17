import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Ddb002Adapter } from './ddb-002.adapter.js';
import { s3001Control } from '../../s3/s3-001/s3-001.control.js';
import { s3008Control } from '../../s3/s3-008/s3-008.control.js';

const MISSING_DATA_EVENT_TRAIL = 'no-trail-captures-dynamodb-data-events';

const FINDINGS = {
  [MISSING_DATA_EVENT_TRAIL]: {
    issue: 'DynamoDB table data plane events are not captured by any CloudTrail trail in the template',
    remediation: 'Add a CloudTrail trail to the template that captures DynamoDB data plane (item-level) events for the offending DynamoDB table. The trail must be actively logging and must include a data event selector whose data resources cover this specific table (or all DynamoDB tables). Do NOT modify the DynamoDB table resource itself — the fix is to introduce CloudTrail (and its supporting resources) into the same template.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Ddb002Control extends SecurityControl<Ddb002Adapter, FindingKey> {
  constructor() {
    super({
      id: 'DDB-002',
      priority: 'HIGH',
      description: 'DynamoDB data plan events must be captured by CloudTrail logging',
      findings: FINDINGS,
      relatedRules: [s3001Control, s3008Control],
    });
  }

  protected evaluate(adapter: Ddb002Adapter): FindingKey | null {
    if (adapter.hasTrailCapturingDynamoDbDataEvents()) return null;
    return MISSING_DATA_EVENT_TRAIL;
  }
}

export const ddb002Control = new Ddb002Control();
