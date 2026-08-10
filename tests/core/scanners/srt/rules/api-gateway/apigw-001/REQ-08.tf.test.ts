import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (Terraform): Access log destination value depends on a condition or
 * input that cannot be resolved at analysis time.
 *
 * In a Terraform plan, values that are unknown at plan time appear as `null`
 * in `planned_values` (e.g. when the destination_arn is wired to another
 * resource attribute computed at apply time, or comes from a variable with
 * no concrete value).
 *
 * Expected behavior: PASS. The rule must not flag non-compliance when the
 * destination_arn cannot be resolved.
 */
describe('APIGW-001 TF — REQ-08: unresolvable access log destination', () => {
  const factory = new Apigw001TfAdapterFactory();

  it('does NOT flag aws_api_gateway_stage when destination_arn is null (unknown at plan time)', () => {
    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            destination_arn: null,
            format: '$context.requestId',
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage],
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does NOT flag aws_apigatewayv2_stage when destination_arn is null (unknown at plan time)', () => {
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'default',
      address: 'aws_apigatewayv2_stage.default',
      values: {
        name: '$default',
        access_log_settings: [
          {
            destination_arn: null,
            format: '$context.requestId',
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: stage,
      allResources: [stage],
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does NOT flag when destination_arn references a log group whose retention_in_days is unknown (null)', () => {
    // Reference-form: destination_arn collapses to the log group's address.
    // The log group exists in the plan but its retention_in_days is unknown
    // at analysis time (e.g. driven by a variable). The rule must not flag.
    const logGroup: TerraformResource = {
      type: 'aws_cloudwatch_log_group',
      name: 'access',
      address: 'aws_cloudwatch_log_group.access',
      values: {
        name: 'api-access-logs',
        retention_in_days: null,
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

    expect(result).toBeNull();
  });
});
