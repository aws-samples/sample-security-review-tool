import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { Apigw005Adapter } from './apigw-005.adapter.js';

const VPC_ENDPOINT_TYPE = 'AWS::EC2::VPCEndpoint';
const EXECUTE_API = 'execute-api';

/** Resource types that only exist when the workload has private, in-VPC networking. */
const VPC_NETWORK_TYPES = [VPC_ENDPOINT_TYPE, 'AWS::EC2::VPC', 'AWS::EC2::Subnet'];
/** Compute types that are VPC-attached whenever the listed property is present. */
const VPC_ATTACHED_COMPUTE: Record<string, string> = {
  'AWS::EC2::Instance': 'SubnetId',
  'AWS::Lambda::Function': 'VpcConfig',
  'AWS::ECS::Service': 'NetworkConfiguration',
};

export class Apigw005CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::ApiGateway::RestApi'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Apigw005CfnAdapter {
    return new Apigw005CfnAdapter(context);
  }
}

class Apigw005CfnAdapter implements Apigw005Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  getEndpointTypes(): string[] | undefined {
    const types = this.endpointConfiguration()?.['Types'];
    if (!Array.isArray(types)) return undefined;
    return types.filter((type): type is string => typeof type === 'string');
  }

  hasCompliantVpcEndpoint(): boolean {
    return this.compliantVpcEndpointIds().length > 0;
  }

  getPolicyDocument(): Record<string, unknown> | undefined {
    const policy = this.properties()['Policy'];
    if (this.isRecord(policy)) return policy;
    if (typeof policy === 'string') return this.parse(policy);
    return undefined;
  }

  getPrivateAccessIdentifiers(): string[] {
    const identifiers: string[] = [];
    for (const logicalId of this.compliantVpcEndpointIds()) {
      identifiers.push(logicalId);
      const vpcId = this.vpcEndpointProperties(logicalId)['VpcId'];
      if (typeof vpcId === 'string') identifiers.push(vpcId);
    }
    return identifiers;
  }

  hasVpcCallers(): boolean {
    return Object.values(this.resources()).some(resource => this.isVpcCaller(resource as Resource));
  }

  hasUnresolvableDecidingValue(): boolean {
    return this.hasUnresolvableEndpointTypes() || this.hasUnresolvablePrivateDns();
  }

  private isVpcCaller(resource: Resource): boolean {
    const type = resource.Type;
    if (VPC_NETWORK_TYPES.includes(type)) return true;
    const marker = VPC_ATTACHED_COMPUTE[type];
    if (!marker) return false;
    return ((resource as { Properties?: Record<string, unknown> }).Properties ?? {})[marker] !== undefined;
  }

  /**
   * Templates commonly wrap the whole endpoint block in a condition, e.g.
   * `EndpointConfiguration: {Fn::If: [IsPrivateApi, {Types: [PRIVATE], ...}, {Types: [REGIONAL]}]}`.
   * The chosen branch is unknowable here, so the endpoint type is unresolvable, not absent.
   */
  private hasUnresolvableEndpointTypes(): boolean {
    const config = this.endpointConfiguration();
    if (config && this.isIntrinsic(config)) return true;

    const types = config?.['Types'];
    if (types === undefined) return false;
    if (!Array.isArray(types)) return true;
    return types.some(type => typeof type !== 'string');
  }

  private hasUnresolvablePrivateDns(): boolean {
    return this.referencedVpcEndpointIds().some(logicalId => this.hasUnknownPrivateDns(logicalId));
  }

  private hasUnknownPrivateDns(logicalId: string): boolean {
    const props = this.vpcEndpointProperties(logicalId);
    if (!this.servesExecuteApi(props)) return false;
    if (!this.isNonEmptyArray(props['SubnetIds']) || !this.isNonEmptyArray(props['SecurityGroupIds'])) return false;
    const privateDns = props['PrivateDnsEnabled'];
    return privateDns !== undefined && typeof privateDns !== 'boolean';
  }

  private compliantVpcEndpointIds(): string[] {
    return this.referencedVpcEndpointIds().filter(logicalId => this.isCompliantVpcEndpoint(logicalId));
  }

  private referencedVpcEndpointIds(): string[] {
    const ids = this.endpointConfiguration()?.['VpcEndpointIds'];
    if (!Array.isArray(ids)) return [];
    return ids.filter((id): id is string => typeof id === 'string');
  }

  private endpointConfiguration(): Record<string, unknown> | undefined {
    const config = this.properties()['EndpointConfiguration'];
    return this.isRecord(config) ? config : undefined;
  }

  private properties(): Record<string, unknown> {
    return (this.ctx.resource as { Properties?: Record<string, unknown> }).Properties ?? {};
  }

  private resources(): Record<string, unknown> {
    return (this.ctx.template.Resources ?? {}) as Record<string, unknown>;
  }

  private isCompliantVpcEndpoint(logicalId: string): boolean {
    const props = this.vpcEndpointProperties(logicalId);
    return this.servesExecuteApi(props) &&
      this.isNonEmptyArray(props['SubnetIds']) &&
      this.isNonEmptyArray(props['SecurityGroupIds']) &&
      props['PrivateDnsEnabled'] === true;
  }

  private servesExecuteApi(props: Record<string, unknown>): boolean {
    const serviceName = props['ServiceName'];
    return typeof serviceName === 'string' && serviceName.includes(EXECUTE_API);
  }

  private vpcEndpointProperties(logicalId: string): Record<string, unknown> {
    const resource = (this.ctx.template.Resources ?? {})[logicalId] as Resource | undefined;
    if (!resource || resource.Type !== VPC_ENDPOINT_TYPE) return {};
    return (resource as { Properties?: Record<string, unknown> }).Properties ?? {};
  }

  private parse(policy: string): Record<string, unknown> | undefined {
    try {
      const parsed: unknown = JSON.parse(policy);
      return this.isRecord(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }

  private isNonEmptyArray(value: unknown): boolean {
    return Array.isArray(value) && value.length > 0;
  }

  private isIntrinsic(value: Record<string, unknown>): boolean {
    return Object.keys(value).some(key => key.startsWith('Fn::'));
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
