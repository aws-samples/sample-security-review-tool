import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (Terraform): Access logging configuration block is present on the
 * stage but contains no destination value (empty/missing destination_arn).
 *
 * Expected behavior: FLAG. Per AWS docs, both destination_arn and format are
 * required to enable access logging. Without a destination, no logs are
 * actually delivered, so the stage should be treated as not having access
 * logging configured.
 */

const factory = new Apigw001TfAdapterFactory();

function buildContext(resource: TerraformResource, allResources: TerraformResource[] = [resource]): TfContext {
  return {
    projectName: 'test-project',
    resource,
    allResources,
  };
}

describe('APIGW-001 REQ-07 (TF): access_log_settings block present but destination_arn missing', () => {
  it('flags aws_api_gateway_stage when access_log_settings has format but no destination_arn', () => {
    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            // destination_arn intentionally omitted
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const ctx = buildContext(stage);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
  });

  it('flags aws_api_gateway_stage when access_log_settings has empty-string destination_arn', () => {
    const stage: TerraformResource = {
      type: 'aws_api_gateway_stage',
      name: 'prod',
      address: 'aws_api_gateway_stage.prod',
      values: {
        stage_name: 'prod',
        access_log_settings: [
          {
            destination_arn: '',
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const ctx = buildContext(stage);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
  });

  it('flags aws_apigatewayv2_stage when access_log_settings has format but no destination_arn', () => {
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'prod',
      address: 'aws_apigatewayv2_stage.prod',
      values: {
        name: 'prod',
        access_log_settings: [
          {
            // destination_arn intentionally omitted
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const ctx = buildContext(stage);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
  });

  it('flags aws_apigatewayv2_stage when access_log_settings has empty-string destination_arn', () => {
    const stage: TerraformResource = {
      type: 'aws_apigatewayv2_stage',
      name: 'prod',
      address: 'aws_apigatewayv2_stage.prod',
      values: {
        name: 'prod',
        access_log_settings: [
          {
            destination_arn: '',
            format: '$context.requestId',
          },
        ],
      },
    } as unknown as TerraformResource;

    const ctx = buildContext(stage);
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
  });
});
