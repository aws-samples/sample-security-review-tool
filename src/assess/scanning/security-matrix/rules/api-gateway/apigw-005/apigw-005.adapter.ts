import { ControlAdapter } from '../../../controls/types.js';

export interface Apigw005Adapter extends ControlAdapter {
  /** Declared endpoint types, or undefined when no endpoint-type configuration exists. */
  getEndpointTypes(): string[] | undefined;
  /** True when the API is wired to a VPC endpoint for execute-api with subnets, security groups and private DNS. */
  hasCompliantVpcEndpoint(): boolean;
  /** The API access policy document, or undefined when none is declared or it cannot be read. */
  getPolicyDocument(): Record<string, unknown> | undefined;
  /** Identifiers (endpoint and VPC references) that constitute the private access path. */
  getPrivateAccessIdentifiers(): string[];
  /** True when the analysed infrastructure contains VPC-attached callers that would invoke the API. */
  hasVpcCallers(): boolean;
  /** True when a value the verdict depends on cannot be resolved at analysis time. */
  hasUnresolvableDecidingValue(): boolean;
}
