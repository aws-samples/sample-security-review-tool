import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { Apigw002Adapter } from './apigw-002.adapter.js';
import { hasQueryOrHeaderParameter, hasRequiredQueryOrHeaderParameter } from './apigw-002.request-parameters.js';

const VALIDATOR_TYPE = 'AWS::ApiGateway::RequestValidator';

export class Apigw002CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::ApiGateway::Method'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Apigw002CfnAdapter {
    return new Apigw002CfnAdapter(context);
  }
}

class Apigw002CfnAdapter implements Apigw002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  get httpMethod(): string | undefined {
    const value = this.properties['HttpMethod'];
    return typeof value === 'string' ? value.toUpperCase() : undefined;
  }

  get referencesRequestValidator(): boolean {
    const value = this.properties['RequestValidatorId'];
    if (typeof value === 'string') return value.trim().length > 0;
    return typeof value === 'object' && value !== null;
  }

  get referencedValidatorEnforcesNothing(): boolean {
    const props = this.validatorProperties();
    if (!props) return false;
    return this.isDisabled(props['ValidateRequestBody']) && this.isDisabled(props['ValidateRequestParameters']);
  }

  get referencedValidatorValidatesParametersOnly(): boolean {
    const props = this.validatorProperties();
    if (!props) return false;
    return this.isDisabled(props['ValidateRequestBody']) && this.isEnabled(props['ValidateRequestParameters']);
  }

  get declaresRequiredQueryOrHeaderParameter(): boolean {
    return hasRequiredQueryOrHeaderParameter(this.properties['RequestParameters']);
  }

  get declaresQueryOrHeaderParameter(): boolean {
    return hasQueryOrHeaderParameter(this.properties['RequestParameters']);
  }

  get declaresRequestBodyModel(): boolean {
    return this.hasEntries(this.properties['RequestModels']);
  }

  get referencedValidatorValidatesBody(): boolean {
    const props = this.validatorProperties();
    if (!props) return false;
    return this.isEnabled(props['ValidateRequestBody']);
  }

  get referencedValidatorValidatesParameters(): boolean {
    const props = this.validatorProperties();
    if (!props) return false;
    return this.isEnabled(props['ValidateRequestParameters']);
  }

  private hasEntries(value: unknown): boolean {
    return typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).length > 0;
  }

  /** Both validation flags default to false, so an absent flag is disabled. Unresolved intrinsics are unknown. */
  private isDisabled(value: unknown): boolean {
    if (value === undefined || value === null) return true;
    return value === false || value === 'false';
  }

  private isEnabled(value: unknown): boolean {
    return value === true || value === 'true';
  }

  private validatorProperties(): Record<string, unknown> | undefined {
    const validator = this.findValidator();
    if (!validator) return undefined;
    return (validator.Properties ?? {}) as Record<string, unknown>;
  }

  private findValidator(): Resource | undefined {
    const reference = this.properties['RequestValidatorId'];
    if (typeof reference !== 'string') return undefined;
    const resources = (this.ctx.template.Resources ?? {}) as Record<string, Resource>;
    const candidate = resources[reference];
    if (candidate?.Type === VALIDATOR_TYPE) return candidate;
    return Object.values(resources).find(resource => this.matchesByName(resource, reference));
  }

  private matchesByName(resource: Resource, reference: string): boolean {
    if (resource?.Type !== VALIDATOR_TYPE) return false;
    const name = (resource.Properties as Record<string, unknown> | undefined)?.['Name'];
    return typeof name === 'string' && name === reference;
  }

  private get properties(): Record<string, unknown> {
    return (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
  }
}
