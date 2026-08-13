import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Apigw005Adapter } from './apigw-005.adapter.js';

const MISSING_ENDPOINT_CONFIGURATION = 'missing-endpoint-configuration';
const PUBLIC_ENDPOINT_TYPE = 'public-endpoint-type';
const MISSING_VPC_ENDPOINT = 'missing-vpc-endpoint';
const POLICY_EXCLUDES_PRIVATE_PATH = 'policy-excludes-private-path';

const PRIVATE = 'PRIVATE';
const VPC_CONDITION_KEYS = ['aws:sourcevpce', 'aws:sourcevpc'];

export class Apigw005Control extends SecurityControl<Apigw005Adapter> {
  constructor() {
    super({
      id: 'APIGW-005',
      priority: 'HIGH',
      description: 'When VPC-connected resources such as EC2 instances or VPC-connected Lambda functions call an API, API Gateway REST APIs must be configured as PRIVATE endpoints and accessed through a properly configured VPC endpoint (with subnet IDs, security group IDs, and private DNS enabled) for the API Gateway execute-api service, rather than being exposed as a public endpoint.',
      remediationScenarios: [
        {
          scenario: MISSING_ENDPOINT_CONFIGURATION,
          intent: 'Declare the REST API endpoint type explicitly as private, and associate it with an interface VPC endpoint for the API Gateway execute-api service that specifies subnets, security groups and enables private DNS.',
        },
        {
          scenario: PUBLIC_ENDPOINT_TYPE,
          intent: 'Change the REST API endpoint type to private, and associate it with an interface VPC endpoint for the API Gateway execute-api service that specifies subnets, security groups and enables private DNS.',
        },
        {
          scenario: MISSING_VPC_ENDPOINT,
          intent: 'Associate the private REST API with an interface VPC endpoint for the API Gateway execute-api service that specifies subnets, security groups and enables private DNS.',
        },
        {
          scenario: POLICY_EXCLUDES_PRIVATE_PATH,
          intent: 'Update the private REST API access policy so that invocations arriving through the associated interface VPC endpoint (or its VPC) are allowed, and remove any statement that denies that endpoint or VPC.',
        },
      ],
    });
  }

  protected evaluate(adapter: Apigw005Adapter): ControlFinding | null {
    if (adapter.hasUnresolvableDecidingValue()) return null;

    const types = adapter.getEndpointTypes();

    if (!types || types.length === 0) {
      if (!adapter.hasVpcCallers()) return null;
      return {
        scenario: MISSING_ENDPOINT_CONFIGURATION,
        issue: 'The API Gateway REST API does not specify an endpoint type, so it defaults to a publicly reachable internet-facing endpoint instead of a private endpoint reachable only from within a VPC.',
      };
    }

    if (!types.some(type => type.toUpperCase() === PRIVATE)) {
      if (!adapter.hasVpcCallers()) return null;
      return {
        scenario: PUBLIC_ENDPOINT_TYPE,
        issue: 'The API Gateway REST API is configured with a publicly reachable endpoint type instead of a private endpoint reachable only from within a VPC.',
      };
    }

    if (!adapter.hasCompliantVpcEndpoint()) {
      return {
        scenario: MISSING_VPC_ENDPOINT,
        issue: 'The private API Gateway REST API is not associated with a VPC endpoint for the API Gateway execute-api service that specifies subnets, security groups and has private DNS enabled.',
      };
    }

    if (this.policyExcludesPrivatePath(adapter)) {
      return {
        scenario: POLICY_EXCLUDES_PRIVATE_PATH,
        issue: 'The private API Gateway REST API access policy denies or does not allow invocations arriving through the VPC endpoint that provides its private access path, so callers inside the VPC cannot reach the API.',
      };
    }

    return null;
  }

  private policyExcludesPrivatePath(adapter: Apigw005Adapter): boolean {
    const statements = this.statementsOf(adapter.getPolicyDocument());
    const identifiers = adapter.getPrivateAccessIdentifiers();
    if (statements.length === 0 || identifiers.length === 0) return false;

    const invocationStatements = statements.filter(statement => this.isRecord(statement)) as Record<string, unknown>[];

    if (invocationStatements.some(statement => this.isEffect(statement, 'Deny') && this.referencesIdentifier(statement, identifiers))) {
      return true;
    }

    const allows = invocationStatements.filter(statement => this.isEffect(statement, 'Allow'));
    if (allows.length === 0) return false;
    if (allows.some(statement => !this.hasVpcCondition(statement))) return false;
    return !allows.some(statement => this.referencesIdentifier(statement, identifiers));
  }

  private statementsOf(policy: Record<string, unknown> | undefined): unknown[] {
    const statement = policy?.['Statement'] ?? policy?.['statement'];
    if (Array.isArray(statement)) return statement;
    return statement === undefined ? [] : [statement];
  }

  private isEffect(statement: Record<string, unknown>, effect: string): boolean {
    const value = statement['Effect'] ?? statement['effect'];
    return typeof value === 'string' && value.toUpperCase() === effect.toUpperCase();
  }

  private hasVpcCondition(statement: Record<string, unknown>): boolean {
    return this.vpcConditionValues(statement).length > 0;
  }

  private referencesIdentifier(statement: Record<string, unknown>, identifiers: string[]): boolean {
    return this.vpcConditionValues(statement).some(value => identifiers.includes(value));
  }

  private vpcConditionValues(statement: Record<string, unknown>): string[] {
    const condition = statement['Condition'] ?? statement['condition'];
    if (!this.isRecord(condition)) return [];
    const values: string[] = [];
    for (const operatorValue of Object.values(condition)) {
      if (!this.isRecord(operatorValue)) continue;
      for (const [key, value] of Object.entries(operatorValue)) {
        if (!VPC_CONDITION_KEYS.includes(key.toLowerCase())) continue;
        values.push(...this.asStrings(value));
      }
    }
    return values;
  }

  private asStrings(value: unknown): string[] {
    const candidates = Array.isArray(value) ? value : [value];
    return candidates.filter((candidate): candidate is string => typeof candidate === 'string');
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}

export const apigw005Control = new Apigw005Control();
