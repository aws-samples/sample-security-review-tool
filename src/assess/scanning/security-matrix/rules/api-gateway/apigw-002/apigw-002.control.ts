import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Apigw002Adapter } from './apigw-002.adapter.js';

const PREFLIGHT_METHOD = 'OPTIONS';
// Verbs for which a request body has no defined semantics, so declaring a body model is not a fix a
// reviewer could reasonably ask for.
const BODYLESS_METHODS = ['GET', 'HEAD', 'DELETE'];
const NO_VALIDATOR_SCENARIO = 'no-request-validator';
const VALIDATOR_ENFORCES_NOTHING_SCENARIO = 'request-validator-enforces-nothing';
const NO_REQUIRED_PARAMETERS_SCENARIO = 'parameter-validation-without-required-parameters';
const BODY_VALIDATION_WITHOUT_MODEL_SCENARIO = 'body-validation-without-model';

export class Apigw002Control extends SecurityControl<Apigw002Adapter> {
  constructor() {
    super({
      id: 'APIGW-002',
      priority: 'HIGH',
      description: 'API Gateway methods must enforce request validation of the request body or query/header parameters, excluding CORS preflight methods',
      remediationScenarios: [
        {
          scenario: NO_VALIDATOR_SCENARIO,
          intent: 'Associate the API method with a request validator that validates the request body and/or the query string and header parameters, so requests are rejected before reaching the backend.',
        },
        {
          scenario: VALIDATOR_ENFORCES_NOTHING_SCENARIO,
          intent: 'Enable body validation and/or query string and header parameter validation on the request validator used by the API method, so requests are rejected before reaching the backend.',
        },
        {
          scenario: NO_REQUIRED_PARAMETERS_SCENARIO,
          intent: 'Mark at least one query string or header parameter of the API method as required, or also enable request body validation on the validator it uses, so parameter validation actually rejects invalid requests.',
        },
        {
          scenario: BODY_VALIDATION_WITHOUT_MODEL_SCENARIO,
          intent: 'Declare a request body model on the API method for the content type it accepts, so the enabled body validation has a schema to validate against, or mark at least one query string or header parameter as required and enable parameter validation instead.',
        },
      ],
    });
  }

  protected evaluate(adapter: Apigw002Adapter): ControlFinding | null {
    if (this.isPreflight(adapter)) return null;
    if (this.hasNothingToValidate(adapter)) return null;
    if (!adapter.referencesRequestValidator) {
      return {
        scenario: NO_VALIDATOR_SCENARIO,
        issue: 'API method does not reference any request validator, so request bodies and query/header parameters reach the backend unvalidated',
      };
    }
    if (adapter.referencedValidatorEnforcesNothing) {
      return {
        scenario: VALIDATOR_ENFORCES_NOTHING_SCENARIO,
        issue: 'The request validator used by the API method validates neither the request body nor query/header parameters, so requests reach the backend unvalidated',
      };
    }
    if (this.hasParameterValidationWithNothingRequired(adapter)) {
      return {
        scenario: NO_REQUIRED_PARAMETERS_SCENARIO,
        issue: 'The API method only validates query/header parameters but declares no required query string or header parameters, so validation enforces nothing',
      };
    }
    if (this.hasBodyValidationWithoutModel(adapter)) {
      return {
        scenario: BODY_VALIDATION_WITHOUT_MODEL_SCENARIO,
        issue: 'The API method enables request body validation but declares no request body model, and API Gateway does not validate a payload with no matching model, so validation enforces nothing',
      };
    }
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
