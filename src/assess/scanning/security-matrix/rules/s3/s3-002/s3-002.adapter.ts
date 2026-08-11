import { ControlAdapter } from '../../../controls/types.js';

export interface PolicyStatement {
  readonly effect?: unknown;
  readonly principal?: unknown;
  readonly condition?: unknown;
}

export interface S3002Adapter extends ControlAdapter {
  /**
   * Parsed Allow/Deny statements from the bucket policy. Returns an empty array
   * when this resource does not carry a policy (e.g. a bare AWS::S3::Bucket
   * with no inline policy) or when the policy cannot be parsed.
   */
  getPolicyStatements(): PolicyStatement[];
}
