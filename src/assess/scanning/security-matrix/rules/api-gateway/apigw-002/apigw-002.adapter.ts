import { ControlAdapter } from '../../../controls/types.js';

export interface Apigw002Adapter extends ControlAdapter {
  /** Upper-cased HTTP verb of the method, or undefined when it cannot be determined. */
  readonly httpMethod: string | undefined;
  /** True when the method references a request validator. */
  readonly referencesRequestValidator: boolean;
  /**
   * True only when the referenced validator can be resolved and its configuration
   * enables neither body validation nor query/header parameter validation.
   */
  readonly referencedValidatorEnforcesNothing: boolean;
  /**
   * True only when the referenced validator can be resolved and it validates query/header
   * parameters but not the request body.
   */
  readonly referencedValidatorValidatesParametersOnly: boolean;
  /** True when the method declares at least one required query string or header parameter. */
  readonly declaresRequiredQueryOrHeaderParameter: boolean;
  /** True when the method declares any request parameter at all, of any kind and required or not. */
  readonly declaresAnyRequestParameter: boolean;
  /** True when the method declares at least one request body model. */
  readonly declaresRequestBodyModel: boolean;
  /** True only when the referenced validator can be resolved and it enables body validation. */
  readonly referencedValidatorValidatesBody: boolean;
  /** True only when the referenced validator can be resolved and it enables parameter validation. */
  readonly referencedValidatorValidatesParameters: boolean;
}
