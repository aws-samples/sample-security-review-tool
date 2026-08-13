import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Apigw005Adapter } from './apigw-005.adapter.js';

const VPC_ENDPOINT_TYPE = 'aws_vpc_endpoint';
const EXECUTE_API = 'execute-api';

/** Resource types that only exist when the workload has private, in-VPC networking. */
const VPC_NETWORK_TYPES = [VPC_ENDPOINT_TYPE, 'aws_vpc', 'aws_subnet'];
/** Compute types that are VPC-attached whenever the listed argument is present. */
const VPC_ATTACHED_COMPUTE: Record<string, string> = {
  aws_instance: 'subnet_id',
  aws_lambda_function: 'vpc_config',
  aws_ecs_service: 'network_configuration',
};

export class Apigw005TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_api_gateway_rest_api'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Apigw005TfAdapter {
    return new Apigw005TfAdapter(context);
  }
}

class Apigw005TfAdapter implements Apigw005Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  getEndpointTypes(): string[] | undefined {
    const types = this.endpointConfiguration()?.['types'];
    if (!Array.isArray(types)) return undefined;
    return types.filter((type): type is string => typeof type === 'string');
  }

  hasCompliantVpcEndpoint(): boolean {
    return this.compliantVpcEndpoints().length > 0;
  }

  getPolicyDocument(): Record<string, unknown> | undefined {
    const policy = this.values(this.ctx.resource)['policy'];
    if (this.isRecord(policy)) return policy;
    if (typeof policy === 'string') return this.parse(policy);
    return undefined;
  }

  getPrivateAccessIdentifiers(): string[] {
    const identifiers: string[] = [];
    for (const endpoint of this.compliantVpcEndpoints()) {
      identifiers.push(endpoint.address);
      const values = this.values(endpoint);
      for (const key of ['id', 'vpc_id']) {
        const value = values[key];
        if (typeof value === 'string') identifiers.push(value);
      }
    }
    return identifiers;
  }

  hasVpcCallers(): boolean {
    return this.ctx.allResources.some(resource => this.isVpcCaller(resource));
  }

  hasUnresolvableDecidingValue(): boolean {
    return this.hasUnresolvableEndpointTypes() || this.hasUnresolvablePrivateDns();
  }

  private isVpcCaller(resource: TerraformResource): boolean {
    if (VPC_NETWORK_TYPES.includes(resource.type)) return true;
    const marker = VPC_ATTACHED_COMPUTE[resource.type];
    if (!marker) return false;
    return this.values(resource)[marker] !== undefined;
  }

  private hasUnresolvableEndpointTypes(): boolean {
    const config = this.endpointConfiguration();
    if (!config || !('types' in config)) return false;
    const types = config['types'];
    if (types === undefined) return false;
    if (!Array.isArray(types)) return true;
    return types.some(type => typeof type !== 'string');
  }

  private hasUnresolvablePrivateDns(): boolean {
    return this.referencedVpcEndpoints().some(endpoint => this.hasUnknownPrivateDns(endpoint));
  }

  private hasUnknownPrivateDns(endpoint: TerraformResource): boolean {
    const values = this.values(endpoint);
    if (!this.servesExecuteApi(values)) return false;
    if (!this.isNonEmptyArray(values['subnet_ids']) || !this.isNonEmptyArray(values['security_group_ids'])) return false;
    const privateDns = values['private_dns_enabled'];
    return privateDns !== undefined && typeof privateDns !== 'boolean';
  }

  private compliantVpcEndpoints(): TerraformResource[] {
    return this.referencedVpcEndpoints().filter(endpoint => this.isCompliant(endpoint));
  }

  private referencedVpcEndpoints(): TerraformResource[] {
    const ids = this.endpointConfiguration()?.['vpc_endpoint_ids'];
    if (!Array.isArray(ids)) return [];
    const references = ids.filter((id): id is string => typeof id === 'string');
    return this.ctx.allResources.filter(resource =>
      resource.type === VPC_ENDPOINT_TYPE &&
      references.some(reference => this.matches(resource, reference)));
  }

  private endpointConfiguration(): Record<string, unknown> | undefined {
    const config = this.values(this.ctx.resource)['endpoint_configuration'];
    const candidate = Array.isArray(config) ? config[0] : config;
    return this.isRecord(candidate) ? candidate : undefined;
  }

  private matches(endpoint: TerraformResource, reference: string): boolean {
    if (endpoint.address === reference) return true;
    const id = this.values(endpoint)['id'];
    return typeof id === 'string' && id === reference;
  }

  private isCompliant(endpoint: TerraformResource): boolean {
    const values = this.values(endpoint);
    return this.servesExecuteApi(values) &&
      this.isNonEmptyArray(values['subnet_ids']) &&
      this.isNonEmptyArray(values['security_group_ids']) &&
      values['private_dns_enabled'] === true;
  }

  private servesExecuteApi(values: Record<string, unknown>): boolean {
    const serviceName = values['service_name'];
    return typeof serviceName === 'string' && serviceName.includes(EXECUTE_API);
  }

  private values(resource: TerraformResource): Record<string, unknown> {
    const values = (resource as { values?: unknown }).values;
    return this.isRecord(values) ? values : {};
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

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
