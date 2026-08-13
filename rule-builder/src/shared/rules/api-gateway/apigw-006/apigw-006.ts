import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';

/**
 * Fixture stack for APIGW-006.
 *
 * Triggers all four remediation scenarios by creating four separate
 * REST APIs (each with its own deployment and stage), configured so
 * each stage's MethodSettings hits a different branch of the
 * evaluate() chain in Apigw006Control.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // --- Scenario 1: no-method-logging-configuration ---
    // Stage has no MethodSettings at all.
    const api1 = new apigateway.RestApi(this, 'NoLoggingApi', {
      deploy: false,
      cloudWatchRole: false,
    });
    api1.root.addMethod('GET');
    const deployment1 = new apigateway.Deployment(this, 'NoLoggingDeployment', {
      api: api1,
    });
    new apigateway.CfnStage(this, 'NoLoggingStage', {
      restApiId: api1.restApiId,
      deploymentId: deployment1.deploymentId,
      stageName: 'prod',
      // No methodSettings property -- triggers NO_METHOD_LOGGING_CONFIGURATION.
    });

    // --- Scenario 2: partial-method-logging-coverage ---
    // Stage has MethodSettings, but none of them are catch-all (HttpMethod "*"
    // and ResourcePath one of "/*", "*", "*/*").
    const api2 = new apigateway.RestApi(this, 'PartialCoverageApi', {
      deploy: false,
      cloudWatchRole: false,
    });
    api2.root.addMethod('GET');
    const deployment2 = new apigateway.Deployment(this, 'PartialCoverageDeployment', {
      api: api2,
    });
    new apigateway.CfnStage(this, 'PartialCoverageStage', {
      restApiId: api2.restApiId,
      deploymentId: deployment2.deploymentId,
      stageName: 'prod',
      methodSettings: [
        {
          httpMethod: 'GET',
          resourcePath: '/',
          loggingLevel: 'INFO',
        },
      ],
    });

    // --- Scenario 3: logging-level-not-accepted ---
    // Stage has a catch-all method setting, but its logging level is not
    // INFO or ERROR.
    const api3 = new apigateway.RestApi(this, 'BadLevelApi', {
      deploy: false,
      cloudWatchRole: false,
    });
    api3.root.addMethod('GET');
    const deployment3 = new apigateway.Deployment(this, 'BadLevelDeployment', {
      api: api3,
    });
    new apigateway.CfnStage(this, 'BadLevelStage', {
      restApiId: api3.restApiId,
      deploymentId: deployment3.deploymentId,
      stageName: 'prod',
      methodSettings: [
        {
          httpMethod: '*',
          resourcePath: '/*',
          loggingLevel: 'OFF',
        },
      ],
    });

    // --- Scenario 4: logging-disabled-for-some-method ---
    // Stage has a compliant catch-all setting (INFO/ERROR), but a narrower
    // method-level setting explicitly disables logging for a specific
    // method and path.
    const api4 = new apigateway.RestApi(this, 'DisabledForSomeApi', {
      deploy: false,
      cloudWatchRole: false,
    });
    api4.root.addMethod('GET');
    const deployment4 = new apigateway.Deployment(this, 'DisabledForSomeDeployment', {
      api: api4,
    });
    new apigateway.CfnStage(this, 'DisabledForSomeStage', {
      restApiId: api4.restApiId,
      deploymentId: deployment4.deploymentId,
      stageName: 'prod',
      methodSettings: [
        {
          httpMethod: '*',
          resourcePath: '/*',
          loggingLevel: 'INFO',
        },
        {
          httpMethod: 'POST',
          resourcePath: '/secure',
          loggingLevel: 'OFF',
        },
      ],
    });
  }
}
