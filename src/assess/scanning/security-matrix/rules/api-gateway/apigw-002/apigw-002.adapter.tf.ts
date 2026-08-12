import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Apigw002Adapter } from './apigw-002.adapter.js';
import { hasAnyRequestParameter, hasRequiredQueryOrHeaderParameter } from './apigw-002.request-parameters.js';

const VALIDATOR_TYPE = 'aws_api_gateway_request_validator';

export class Apigw002TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_api_gateway_method'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Apigw002TfAdapter {
    return new Apigw002TfAdapter(context);
  }
}

class Apigw002TfAdapter implements Apigw002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  get httpMethod(): string | undefined {
    const value = this.values['http_method'];
    return typeof value === 'string' ? value.toUpperCase() : undefined;
  }

  get referencesRequestValidator(): boolean {
    const value = this.values['request_validator_id'];
    if (typeof value === 'string') return value.trim().length > 0;
    return value !== null && value !== undefined;
  }

  get referencedValidatorEnforcesNothing(): boolean {
    const values = this.validatorValues();
    if (!values) return false;
    const body = values['validate_request_body'];
    const parameters = values['validate_request_parameters'];
    if (this.isUndeterminable(body) || this.isUndeterminable(parameters)) return false;
    return this.isDisabled(body) && this.isDisabled(parameters);
  }

  get referencedValidatorValidatesParametersOnly(): boolean {
    const values = this.validatorValues();
    if (!values) return false;
    const body = values['validate_request_body'];
    const parameters = values['validate_request_parameters'];
    if (this.isUndeterminable(body) || this.isUndeterminable(parameters)) return false;
    return this.isDisabled(body) && this.isEnabled(parameters);
  }

  get declaresRequiredQueryOrHeaderParameter(): boolean {
    return hasRequiredQueryOrHeaderParameter(this.values['request_parameters']);
  }

  get declaresAnyRequestParameter(): boolean {
    return hasAnyRequestParameter(this.values['request_parameters']);
  }

  get declaresRequestBodyModel(): boolean {
    return this.hasEntries(this.values['request_models']);
  }

  get referencedValidatorValidatesBody(): boolean {
    const values = this.validatorValues();
    if (!values) return false;
    return this.isEnabled(values['validate_request_body']);
  }

  get referencedValidatorValidatesParameters(): boolean {
    const values = this.validatorValues();
    if (!values) return false;
    return this.isEnabled(values['validate_request_parameters']);
  }

  private hasEntries(value: unknown): boolean {
    return typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).length > 0;
  }

  /** A null flag is a plan-time unknown: the effective value cannot be determined. */
  private isUndeterminable(value: unknown): boolean {
    return value === null;
  }

  /** Both validation flags default to false, so an absent flag is disabled. */
  private isDisabled(value: unknown): boolean {
    if (value === undefined) return true;
    return value === false || value === 'false';
  }

  private isEnabled(value: unknown): boolean {
    return value === true || value === 'true';
  }

  private validatorValues(): Record<string, unknown> | undefined {
    const validator = this.findValidator();
    if (!validator) return undefined;
    return (validator.values ?? {}) as Record<string, unknown>;
  }

  private findValidator(): TerraformResource | undefined {
    const reference = this.values['request_validator_id'];
    if (typeof reference !== 'string') return undefined;
    const candidates = (this.ctx.allResources ?? []).filter(resource => resource.type === VALIDATOR_TYPE);
    return candidates.find(resource => resource.address === reference || this.matchesByName(resource, reference));
  }

  private matchesByName(resource: TerraformResource, reference: string): boolean {
    const name = (resource.values as Record<string, unknown> | undefined)?.['name'];
    return typeof name === 'string' && name === reference;
  }

  private get values(): Record<string, unknown> {
    return (this.ctx.resource.values ?? {}) as Record<string, unknown>;
  }
}
