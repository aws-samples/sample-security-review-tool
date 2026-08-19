import { ControlAdapter } from '../../../controls/types.js';

export interface Codebuild009Adapter extends ControlAdapter {
  /**
   * Names of S3 buckets associated with the build project whose service role
   * does not effectively allow both required bucket-inspection permissions.
   * Empty when the project complies or when the configuration is unknown.
   */
  bucketsMissingRequiredPermissions(): string[];
}
