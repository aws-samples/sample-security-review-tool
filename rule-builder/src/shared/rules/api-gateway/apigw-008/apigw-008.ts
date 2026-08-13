import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';

/**
 * Fixture for APIGW-008.
 *
 * Scenario: unencrypted-cache
 *   An API Gateway stage has response caching enabled for a method
 *   (via a catch-all "*"/"/*" MethodSetting) but CacheDataEncrypted is
 *   explicitly set to false, so the cached response data is not
 *   encrypted at rest.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const api = new apigateway.RestApi(this, 'UnencryptedCacheApi', {
      restApiName: 'unencrypted-cache-api',
      deploy: false,
    });

    const resource = api.root.addResource('items');
    const method = resource.addMethod('GET');

    const deployment = new apigateway.CfnDeployment(this, 'UnencryptedCacheDeployment', {
      restApiId: api.restApiId,
    });
    deployment.addDependency(method.node.defaultChild as apigateway.CfnMethod);

    // eslint-disable-next-line no-new
    new apigateway.CfnStage(this, 'UnencryptedCacheStage', {
      restApiId: api.restApiId,
      deploymentId: deployment.ref,
      stageName: 'prod',
      methodSettings: [
        {
          httpMethod: '*',
          resourcePath: '/*',
          cachingEnabled: true,
          cacheDataEncrypted: false,
        },
      ],
    });
  }
}
