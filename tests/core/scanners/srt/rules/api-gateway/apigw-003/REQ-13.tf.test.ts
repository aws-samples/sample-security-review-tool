import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.tf.js';
import type {
  Apigw003Adapter,
} from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type {
  ScanResult,
  TerraformResource,
  TfContext,
} from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (APIGW-003): A stage belonging to a newer-generation API type (HTTP or
 * WebSocket API) cannot carry a stage-level WAF web ACL association, so it is outside
 * the rule's scope and must PASS even with no association present.
 *
 * The primary "must have a web ACL association" behaviour is owned by the base
 * requirement; it appears here only as the opposite case.
 */

const factory = new Apigw003TfAdapterFactory();

function run(stage: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: stage,
    allResources,
  };
  const adapter = factory.bind(context) as unknown as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

// Reference form: `rest_api_id = aws_apigatewayv2_api.http.id` collapses to the address.
function stageFor(apiAddress: string): TerraformResource {
  return {
    type: 'aws_api_gateway_stage',
    name: 'prod',
    address: 'aws_api_gateway_stage.prod',
    values: {
      rest_api_id: apiAddress,
      stage_name: 'prod',
      deployment_id: 'aws_api_gateway_deployment.main',
    },
  } as unknown as TerraformResource;
}

describe('APIGW-003 REQ-13 (Terraform): newer-generation API stages are out of scope', () => {
  it('passes a stage attached to an HTTP API with no web ACL association', () => {
    const httpApi = {
      type: 'aws_apigatewayv2_api',
      name: 'http',
      address: 'aws_apigatewayv2_api.http',
      values: { name: 'http-api', protocol_type: 'HTTP' },
    } as unknown as TerraformResource;
    const stage = stageFor('aws_apigatewayv2_api.http');

    expect(run(stage, [httpApi, stage])).toBeNull();
  });

  it('passes a stage attached to a WebSocket API with no web ACL association', () => {
    const socketApi = {
      type: 'aws_apigatewayv2_api',
      name: 'socket',
      address: 'aws_apigatewayv2_api.socket',
      values: { name: 'socket-api', protocol_type: 'WEBSOCKET' },
    } as unknown as TerraformResource;
    const stage = stageFor('aws_apigatewayv2_api.socket');

    expect(run(stage, [socketApi, stage])).toBeNull();
  });

  // Opposite outcome: identical shape, but the stage belongs to a REST API, where a
  // stage-level web ACL association IS supported and therefore required.
  it('flags an otherwise identical stage attached to a REST API with no web ACL association', () => {
    const restApi = {
      type: 'aws_api_gateway_rest_api',
      name: 'rest',
      address: 'aws_api_gateway_rest_api.rest',
      values: { name: 'rest-api' },
    } as unknown as TerraformResource;
    const stage = stageFor('aws_api_gateway_rest_api.rest');

    const result = run(stage, [restApi, stage]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });
});
