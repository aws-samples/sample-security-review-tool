import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';

/**
 * Fixture stack for APIGW-002.
 *
 * Triggers all three remediation scenarios:
 *  1. no-request-validator                          -> method with no RequestValidatorId at all
 *  2. request-validator-enforces-nothing             -> method references a validator that has
 *                                                       both body and parameter validation disabled
 *  3. parameter-validation-without-required-parameters -> method references a validator that only
 *                                                       validates parameters, but the method declares
 *                                                       no required query/header parameters
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const api = new apigateway.RestApi(this, 'Api', {
      deploy: false,
    });

    const integration = new apigateway.MockIntegration({
      integrationResponses: [{ statusCode: '200' }],
      requestTemplates: { 'application/json': '{"statusCode": 200}' },
    });

    // --- Scenario 1: no-request-validator ---------------------------------
    const noValidatorResource = api.root.addResource('no-validator');
    noValidatorResource.addMethod('GET', integration, {
      methodResponses: [{ statusCode: '200' }],
      // Intentionally no requestValidator / requestValidatorOptions configured.
    });

    // --- Scenario 2: request-validator-enforces-nothing --------------------
    const enforcesNothingValidator = new apigateway.RequestValidator(this, 'EnforcesNothingValidator', {
      restApi: api,
      requestValidatorName: 'enforces-nothing-validator',
      validateRequestBody: false,
      validateRequestParameters: false,
    });

    const enforcesNothingResource = api.root.addResource('enforces-nothing');
    enforcesNothingResource.addMethod('GET', integration, {
      methodResponses: [{ statusCode: '200' }],
      requestValidator: enforcesNothingValidator,
    });

    // --- Scenario 3: parameter-validation-without-required-parameters ------
    const paramsOnlyValidator = new apigateway.RequestValidator(this, 'ParamsOnlyValidator', {
      restApi: api,
      requestValidatorName: 'params-only-validator',
      validateRequestBody: false,
      validateRequestParameters: true,
    });

    const noRequiredParamsResource = api.root.addResource('no-required-params');
    noRequiredParamsResource.addMethod('GET', integration, {
      methodResponses: [{ statusCode: '200' }],
      requestValidator: paramsOnlyValidator,
      // Query string parameter declared but not marked as required, so parameter
      // validation enforces nothing.
      requestParameters: {
        'method.request.querystring.filter': false,
      },
    });
  }
}
