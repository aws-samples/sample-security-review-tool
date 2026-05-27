import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05: CloudFront distribution is configured to use the default CloudFront
 * certificate (*.cloudfront.net), regardless of any minimum protocol version
 * value set. Expected behavior: the rule passes (returns null).
 *
 * In Terraform, the default CloudFront certificate is indicated by setting
 * cloudfront_default_certificate = true on the viewer_certificate block.
 *
 * Per user-resolved decision: when the SSL certificate is the default
 * CloudFront certificate, this rule passes. AWS forces TLSv1 in this case
 * but the rule defers to the default-certificate scenario as out of scope.
 */

const PROJECT_NAME = 'test-project';

function buildContext(viewerCertificate: Record<string, unknown>): TfContext {
  const resource: TerraformResource = {
    address: 'aws_cloudfront_distribution.test',
    type: 'aws_cloudfront_distribution',
    name: 'test',
    mode: 'managed',
    provider_name: 'registry.terraform.io/hashicorp/aws',
    schema_version: 0,
    values: {
      enabled: true,
      viewer_certificate: [viewerCertificate],
    },
  } as unknown as TerraformResource;

  return {
    projectName: PROJECT_NAME,
    resource,
    allResources: [resource],
  };
}

describe('CF-001 REQ-05 (TF): default CloudFront certificate passes', () => {
  it('returns null when cloudfront_default_certificate is true and no minimum_protocol_version is set', () => {
    const context = buildContext({
      cloudfront_default_certificate: true,
    });
    const adapter = new Cf001TfAdapterFactory().bind(context);

    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('returns null when cloudfront_default_certificate is true even if an insecure minimum_protocol_version is set', () => {
    const context = buildContext({
      cloudfront_default_certificate: true,
      minimum_protocol_version: 'TLSv1',
    });
    const adapter = new Cf001TfAdapterFactory().bind(context);

    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('returns null when cloudfront_default_certificate is true even if a secure minimum_protocol_version is set', () => {
    const context = buildContext({
      cloudfront_default_certificate: true,
      minimum_protocol_version: 'TLSv1.2_2021',
    });
    const adapter = new Cf001TfAdapterFactory().bind(context);

    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
