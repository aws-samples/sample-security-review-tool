import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (Terraform): API Gateway stage HAS access logging configured pointing
 * to an aws_cloudwatch_log_group declared in the same project, but that log
 * group has NO retention_in_days configured (logs retained indefinitely).
 *
 * Expected behavior: flag — the rule mandates "proper retention", and a log
 * group without retention_in_days causes log events to never expire, which
 * fails the retention portion of the requirement.
 */
describe('APIGW-001 (TF) REQ-03: access logging present but log group has no retention', () => {
  const factory = new Apigw001TfAdapterFactory();

  it('flags aws_api_gateway_stage when destination log group (referenced) has no retention_in_days', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access',
      address: 'aws_cloudwatch_log_group.access',
      values: {
        name: '/aws/apigateway/access-logs',
        // No retention_in_days — logs retained indefinitely
      },
    };

    // Reference form: in HCL the user wrote
    //   destination_arn = aws_cloudwatch_log_group.access.arn
    // which the plan reader collapses to the target's address string.
    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            destination_arn: 'aws_cloudwatch_log_group.access',
            format: '$context.requestId',
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage, logGroup],
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  it('flags aws_apigatewayv2_stage when destination log group (referenced) has no retention_in_days', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'v2_access',
      address: 'aws_cloudwatch_log_group.v2_access',
      values: {
        name: '/aws/apigateway/v2-access-logs',
        // No retention_in_days — logs retained indefinitely
      },
    };

    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'default',
      address: 'aws_apigatewayv2_stage.default',
      values: {
        name: '$default',
        auto_deploy: true,
        access_log_settings: [
          {
            destination_arn: 'aws_cloudwatch_log_group.v2_access',
            format: '$context.requestId',
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage, logGroup],
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.resourceType).toBe('aws_apigatewayv2_stage');
    expect(result?.resourceName).toBe('aws_apigatewayv2_stage.default');
  });
});
