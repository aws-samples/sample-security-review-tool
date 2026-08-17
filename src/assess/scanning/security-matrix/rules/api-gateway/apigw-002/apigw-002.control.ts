import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Apigw002Adapter } from './apigw-002.adapter.js';

const PREFLIGHT_METHOD = 'OPTIONS';
// Verbs for which a request body has no defined semantics, so declaring a body model is not a fix a
// reviewer could reasonably ask for.
const BODYLESS_METHODS = ['GET', 'HEAD', 'DELETE'];
const NO_VALIDATOR_FINDING = 'no-request-validator';
const VALIDATOR_ENFORCES_NOTHING_FINDING = 'request-validator-enforces-nothing';
const NO_REQUIRED_PARAMETERS_FINDING = 'parameter-validation-without-required-parameters';
const BODY_VALIDATION_WITHOUT_MODEL_FINDING = 'body-validation-without-model';

const FINDINGS = {
  [NO_VALIDATOR_FINDING]: {
    issue: 'API method does not reference any request validator, so request bodies and query/header parameters reach the backend unvalidated',
    remediation: 'Associate the API method with a request validator that validates the request body and/or the query string and header parameters, so requests are rejected before reaching the backend.',
  },
  [VALIDATOR_ENFORCES_NOTHING_FINDING]: {
    issue: 'The request validator used by the API method validates neither the request body nor query/header parameters, so requests reach the backend unvalidated',
    remediation: 'Enable body validation and/or query string and header parameter validation on the request validator used by the API method, so requests are rejected before reaching the backend.',
  },
  [NO_REQUIRED_PARAMETERS_FINDING]: {
    issue: 'The API method only validates query/header parameters but declares no required query string or header parameters, so validation enforces nothing',
    remediation: 'Mark at least one query string or header parameter of the API method as required, or also enable request body validation on the validator it uses, so parameter validation actually rejects invalid requests.',
  },
  [BODY_VALIDATION_WITHOUT_MODEL_FINDING]: {
    issue: 'The API method enables request body validation but declares no request body model, and API Gateway does not validate a payload with no matching model, so validation enforces nothing',
    remediation: 'Declare a request body model on the API method for the content type it accepts, so the enabled body validation has a schema to validate against, or mark at least one query string or header parameter as required and enable parameter validation instead.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Apigw002Control extends SecurityControl<Apigw002Adapter, FindingKey> {
  constructor() {
    super({
      id: 'APIGW-002',
      priority: 'HIGH',
      description: 'API Gateway methods must enforce request validation of the request body or query/header parameters, excluding CORS preflight methods',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Apigw002Adapter): FindingKey | null {
    if (this.isPreflight(adapter)) return null;
    if (this.hasNothingToValidate(adapter)) return null;
    if (!adapter.referencesRequestValidator) return NO_VALIDATOR_FINDING;
    if (adapter.referencedValidatorEnforcesNothing) return VALIDATOR_ENFORCES_NOTHING_FINDING;
    if (this.hasParameterValidationWithNothingRequired(adapter)) return NO_REQUIRED_PARAMETERS_FINDING;
    if (this.hasBodyValidationWithoutModel(adapter)) return BODY_VALIDATION_WITHOUT_MODEL_FINDING;
    return null;
  }

  private hasParameterValidationWithNothingRequired(adapter: Apigw002Adapter): boolean {
    return adapter.referencedValidatorValidatesParametersOnly && !adapter.declaresRequiredQueryOrHeaderParameter;
  }

  // Body validation runs only against a model matching the request content type; with no model declared
  // the documentation states validation is not performed. Enforced parameter validation still makes the
  // method compliant, so this fires only when neither half enforces anything.
  private hasBodyValidationWithoutModel(adapter: Apigw002Adapter): boolean {
    if (!adapter.referencedValidatorValidatesBody || adapter.declaresRequestBodyModel) return false;
    return !(adapter.referencedValidatorValidatesParameters && adapter.declaresRequiredQueryOrHeaderParameter);
  }

  // A method declaring neither a body model nor a query or header parameter has no input a validator
  // could check. For these verbs a body has no defined semantics either, so no validator configuration
  // could enforce anything and there is no change worth asking the author to make.
  private hasNothingToValidate(adapter: Apigw002Adapter): boolean {
    if (adapter.httpMethod === undefined || !BODYLESS_METHODS.includes(adapter.httpMethod)) return false;
    return !adapter.declaresRequestBodyModel && !adapter.declaresQueryOrHeaderParameter;
  }

  private isPreflight(adapter: Apigw002Adapter): boolean {
    return adapter.httpMethod === PREFLIGHT_METHOD;
  }
}

export const apigw002Control = new Apigw002Control();
