import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type { Apigw003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw003TfAdapterFactory();

/** REST API reachable only from inside a VPC. */
const privateRestApi: TerraformResource = {
  type: 'aws_api_gateway_rest_api',
  name: 'internal',
  address: 'aws_api_gateway_rest_api.internal',
  values: {
    name: 'internal-only-api',
    endpoint_configuration: [{ types: ['PRIVATE'], vpc_endpoint_ids: ['vpce-0123456789abcdef0'] }],
  },
} as unknown as TerraformResource;

/** Reference form: HCL wrote `rest_api_id = aws_api_gateway_rest_api.internal.id`. */
const privateStage: TerraformResource = {
  type: 'aws_api_gateway_stage',
  name: 'prod',
  address: 'aws_api_gateway_stage.prod',
  values: {
    rest_api_id: 'aws_api_gateway_rest_api.internal',
    stage_name: 'prod',
    deployment_id: 'aws_api_gateway_deployment.main',
  },
} as unknown as TerraformResource;

function run(allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'private-api-project',
    resource: privateStage,
    allResources,
  };
  const adapter: Apigw003Adapter = factory.bind(context);
  return apigw003Control.run(adapter, context);
}

describe('APIGW-003 (Terraform): private-endpoint REST API stages are not exempt from the WAF requirement', () => {
  // Primary behavior owned by APIGW-003: any REST API stage without a web ACL is flagged,
  // regardless of the API's endpoint configuration.
  it('flags a stage of a PRIVATE-endpoint REST API that has no web ACL association', () => {
    const result = run([privateRestApi, privateStage]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
    expect(result?.resourceType).toBe('aws_api_gateway_stage');
    expect(result?.resourceName).toBe('aws_api_gateway_stage.prod');
  });

  // Opposite outcome: identical private-endpoint stage, but a web ACL is associated with it.
  it('does not flag the same PRIVATE-endpoint stage when a web ACL is associated with it', () => {
    const association: TerraformResource = {
      type: 'aws_wafv2_web_acl_association',
      name: 'prod',
      address: 'aws_wafv2_web_acl_association.prod',
      values: {
        // Reference form: HCL wrote `resource_arn = aws_api_gateway_stage.prod.arn`.
        resource_arn: 'aws_api_gateway_stage.prod',
        web_acl_arn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/api-acl/abc',
      },
    } as unknown as TerraformResource;

    const result = run([privateRestApi, privateStage, association]);

    expect(result).toBeNull();
  });
});
