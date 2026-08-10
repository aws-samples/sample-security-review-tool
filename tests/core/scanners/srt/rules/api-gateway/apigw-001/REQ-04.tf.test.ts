import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw001TfAdapterFactory();

function runControl(target: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: target,
    allResources,
  };
  const adapter = factory.bind(context);
  return apigw001Control.run(adapter, context);
}

describe('APIGW-001 REQ-04 (TF): access log destination log group has zero/non-positive retention', () => {
  it('flags aws_api_gateway_stage when referenced log group has retention_in_days=0 (reference form)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access_logs',
      address: 'aws_cloudwatch_log_group.access_logs',
      values: {
        name: 'apigw-access-logs',
        retention_in_days: 0,
      },
    } as TerraformResource;

    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            // Reference form: aws_cloudwatch_log_group.access_logs.arn collapses to address
            destination_arn: 'aws_cloudwatch_log_group.access_logs',
            format: '$context.requestId',
          },
        ],
      },
    } as TerraformResource;

    const result = runControl(stage, [stage, logGroup]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.issue).toMatch(/retention/i);
  });

  it('flags aws_apigatewayv2_stage when referenced log group has retention_in_days=-1 (literal-name form)', () => {
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access_logs',
      address: 'aws_cloudwatch_log_group.access_logs',
      values: {
        name: 'apigwv2-access-logs',
        retention_in_days: -1,
      },
    } as TerraformResource;

    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'http_prod',
      address: 'aws_apigatewayv2_stage.http_prod',
      values: {
        name: 'prod',
        // Literal-name form: user wrote a string ARN that contains the log group name
        access_log_settings: [
          {
            destination_arn: 'arn:aws:logs:us-east-1:123456789012:log-group:apigwv2-access-logs',
            format: '$context.requestId',
          },
        ],
      },
    } as TerraformResource;

    const result = runControl(stage, [stage, logGroup]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
    expect(result?.issue).toMatch(/retention/i);
  });
});
