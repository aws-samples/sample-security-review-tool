import { ControlAdapter } from '../../../controls/types.js';

export interface Lambda005Adapter extends ControlAdapter {
  /** True when this resource is an IAM role the Lambda service may assume, or one a function names as its role. */
  isLambdaExecutionRole(): boolean;
  /** True when a permission grant on the role allows all actions on all resources. */
  grantsWildcardActionOnAllResources(): boolean;
  /** True when the role is attached to an admin-level or service-wide permission set. */
  usesOverlyBroadManagedPolicy(): boolean;
}
