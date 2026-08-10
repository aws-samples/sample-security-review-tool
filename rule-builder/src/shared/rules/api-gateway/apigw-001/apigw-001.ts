import { Stack, StackProps } from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

/**
 * Fixture stack for APIGW-001: API Gateway access logging + retention.
 *
 * Scenarios triggered:
 *
 * 1. `missing-access-logging` — A REST API stage with no AccessLogSetting
 *    configured. The default L2 RestApi creates an `AWS::ApiGateway::Stage`
 *    without `AccessLogSetting`, so `hasAccessLogging()` returns false.
 *
 * 2. `missing-log-retention` — An HTTP API (`AWS::ApiGatewayV2::Stage`) with
 *    AccessLogSettings pointing to a CloudWatch log group that exists in the
 *    template but has no `RetentionInDays` property. We use L1 `CfnLogGroup`
 *    so we can omit retention entirely (the L2 `LogGroup` defaults to
 *    `TWO_YEARS`, which would not trigger the scenario).
 *
 *    The stage's `DestinationArn` is the log group's `Fn::GetAtt(..., Arn)`,
 *    which template preprocessing collapses to the log group's logical ID
 *    string. The adapter's `findInTemplateLogGroup` matches that against the
 *    log group's logical ID and confirms there is no `RetentionInDays`,
 *    causing `hasProperLogRetention()` to return false.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // ---------------------------------------------------------------------
    // Scenario 1: REST API stage with no access logging configured.
    // ---------------------------------------------------------------------
    const restApi = new apigateway.RestApi(this, 'NoLoggingRestApi', {
      restApiName: 'no-logging-rest-api',
      // No deployOptions.accessLogDestination -> stage has no AccessLogSetting.
    });
    // RestApi requires at least one method to synthesize.
    restApi.root.addMethod('GET', new apigateway.MockIntegration({
      integrationResponses: [{ statusCode: '200' }],
      requestTemplates: { 'application/json': '{"statusCode": 200}' },
    }), {
      methodResponses: [{ statusCode: '200' }],
    });

    // ---------------------------------------------------------------------
    // Scenario 2: HTTP API stage with access logging to a log group that has
    // no retention period configured.
    // ---------------------------------------------------------------------
    const noRetentionLogGroup = new logs.CfnLogGroup(this, 'NoRetentionLogs', {
      logGroupName: '/aws/apigateway/no-retention-fixture',
      // Intentionally omit RetentionInDays.
    });

    const httpApi = new apigatewayv2.CfnApi(this, 'HttpApiForLoggingFixture', {
      name: 'http-api-no-retention',
      protocolType: 'HTTP',
    });

    new apigatewayv2.CfnStage(this, 'HttpApiStageNoRetention', {
      apiId: httpApi.ref,
      stageName: '$default',
      autoDeploy: true,
      accessLogSettings: {
        // Fn::GetAtt(NoRetentionLogs, Arn) -> preprocessing collapses to the
        // logical ID "NoRetentionLogs", which the adapter matches against the
        // log group resource in the template.
        destinationArn: noRetentionLogGroup.attrArn,
        format: '$context.requestId $context.identity.sourceIp $context.httpMethod $context.routeKey $context.status',
      },
    });
  }
}
