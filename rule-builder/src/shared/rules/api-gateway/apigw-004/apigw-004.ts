import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';

/**
 * Fixture for APIGW-004.
 *
 * Remediation scenarios covered:
 *  - missing-authorization: an API Gateway method with AuthorizationType NONE
 *    (i.e. no authorizer configured), which allows unauthenticated access.
 *
 * Only a single scenario exists for this rule, so a single non-compliant
 * method is sufficient to exercise it. An OPTIONS method is also included
 * (it is exempt from the check by design, per isOptionsMethod()) to
 * demonstrate that CORS preflight methods are not flagged.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const api = new apigateway.RestApi(this, 'UnauthenticatedApi', {
      restApiName: 'apigw-004-fixture-api',
      deploy: false,
    });

    const resource = api.root.addResource('items');

    // Non-compliant: no authorization configured at all -> triggers
    // "missing-authorization" scenario.
    resource.addMethod('GET', new apigateway.MockIntegration(), {
      authorizationType: apigateway.AuthorizationType.NONE,
    });

    // Compliant / exempt: OPTIONS methods are excluded from evaluation by
    // isOptionsMethod(), so this method never reaches the authorization
    // check and is not expected to produce a finding.
    resource.addMethod('OPTIONS', new apigateway.MockIntegration(), {
      authorizationType: apigateway.AuthorizationType.NONE,
    });
  }
}
