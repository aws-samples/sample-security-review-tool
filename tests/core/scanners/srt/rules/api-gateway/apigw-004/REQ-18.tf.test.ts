import { describe, it, expect } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004TfAdapterFactory();

function api(protocolType: string): TerraformResource {
  return {
    type: 'aws_apigatewayv2_api',
    name: 'orders',
    address: 'aws_apigatewayv2_api.orders',
    values: { name: 'orders', protocol_type: protocolType, route_selection_expression: '$request.body.action' },
  } as unknown as TerraformResource;
}

function route(routeKey: string, values: Record<string, unknown> = {}): TerraformResource {
  return {
    type: 'aws_apigatewayv2_route',
    name: 'route',
    address: 'aws_apigatewayv2_route.route',
    values: { api_id: 'aws_apigatewayv2_api.orders', route_key: routeKey, ...values },
  } as unknown as TerraformResource;
}

function scan(protocolType: string, routeKey: string, values?: Record<string, unknown>) {
  const resource = route(routeKey, values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [api(protocolType), resource],
  };
  return apigw004Control.run(factory.bind(context), context);
}

describe('APIGW-004 REQ-18 (Terraform): WebSocket routes other than $connect cannot carry authorization', () => {
  it('passes a $disconnect route that declares authorization_type NONE', () => {
    expect(scan('WEBSOCKET', '$disconnect', { authorization_type: 'NONE' })).toBeNull();
  });

  it('passes a $default route with no authorization configured at all', () => {
    expect(scan('WEBSOCKET', '$default')).toBeNull();
  });

  it('passes a custom route that declares authorization_type NONE', () => {
    expect(scan('WEBSOCKET', 'sendmessage', { authorization_type: 'NONE' })).toBeNull();
  });

  // Opposite outcome: $connect is the one WebSocket route that does take an
  // authorizer, so the exclusion must not reach it.
  it('flags a $connect route that declares authorization_type NONE', () => {
    const result = scan('WEBSOCKET', '$connect', { authorization_type: 'NONE' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same
  // unauthenticated $default route on an HTTP API, where any route takes an
  // authorizer.
  it('flags a $default route on an HTTP API', () => {
    const result = scan('HTTP', '$default', { authorization_type: 'NONE' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });

  it('flags a WebSocket route when the API it belongs to is not in the project', () => {
    const resource = route('$default', { api_id: 'aws_apigatewayv2_api.elsewhere', authorization_type: 'NONE' });
    const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };

    const result = apigw004Control.run(factory.bind(context), context);

    expect(result).not.toBeNull();
  });
});
