import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (Terraform):
 * API Gateway stage has access logging enabled and points to an in-plan log group,
 * but the log group's retention_in_days is set to a value the rule does not recognize
 * as a valid CloudWatch retention period (e.g., a non-numeric / otherwise invalid value).
 *
 * Expected: flag — invalid retention will not produce intended retention behavior.
 *
 * Per the SPECIFIC_RESOURCE guidance, we exercise both the literal-name form and
 * the cross-resource reference form (destination_arn collapses to the log group's address).
 */
describe('APIGW-001 TF — invalid log retention value flags as missing retention', () => {
  function runControlOnStage(stage: TerraformResource, allResources: TerraformResource[]) {
    const factory = new Apigw001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources,
    };
    const adapter = factory.bind(context);
    return apigw001Control.run(adapter, context);
  }

  it('flags aws_api_gateway_stage when referenced log group retention_in_days is a non-numeric string (reference form)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access',
      address: 'aws_cloudwatch_log_group.access',
      values: {
        name: '/aws/apigw/access-logs',
        // Invalid: non-numeric retention.
        retention_in_days: 'forever',
      },
    };

    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            // Reference form: destination_arn collapses to the log group's address.
            destination_arn: 'aws_cloudwatch_log_group.access',
            format: '$context.requestId',
          },
        ],
      },
    };

    const result = runControlOnStage(stage, [stage, logGroup]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.issue).toMatch(/retention/i);
  });

  it('flags aws_apigatewayv2_stage when referenced log group retention_in_days is a non-numeric string (literal-name form)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'v2access',
      address: 'aws_cloudwatch_log_group.v2access',
      values: {
        name: '/aws/apigw/v2-access-logs',
        // Invalid: boolean is not a valid retention value.
        retention_in_days: true as unknown as number,
      },
    };

    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'prod',
      address: 'aws_apigatewayv2_stage.prod',
      values: {
        name: 'prod',
        access_log_settings: [
          {
            // Literal-name form: user wrote the log group ARN/name as a string in HCL.
            destination_arn: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigw/v2-access-logs:*',
            format: '$context.requestId',
          },
        ],
      },
    };

    const result = runControlOnStage(stage, [stage, logGroup]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.issue).toMatch(/retention/i);
  });
});
