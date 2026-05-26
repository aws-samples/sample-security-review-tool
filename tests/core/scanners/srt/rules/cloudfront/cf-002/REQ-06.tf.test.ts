import { describe, it, expect } from 'vitest';
import { cf002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.control.js';
import { Cf002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-002 REQ-06 Terraform: distribution associated with WAF web ACL via logical/symbolic reference to a same-config resource', () => {
  it('passes when web_acl_id references another aws_wafv2_web_acl resource in the same configuration', () => {
    // In Terraform plan/state JSON, an HCL reference like
    //   web_acl_id = aws_wafv2_web_acl.my_web_acl.arn
    // is resolved to the concrete ARN string in resource.values.
    // The presence of a non-empty value indicates a valid association to the
    // sibling WAF web ACL resource defined in the same configuration.
    const webAclResource: TerraformResource = {
      address: 'aws_wafv2_web_acl.my_web_acl',
      type: 'aws_wafv2_web_acl',
      name: 'my_web_acl',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        name: 'my-web-acl',
        scope: 'CLOUDFRONT',
        arn: 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/my-web-acl/abcd-1234',
      },
    } as TerraformResource;

    const distributionResource: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        // Resolved value of `aws_wafv2_web_acl.my_web_acl.arn` reference.
        web_acl_id: 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/my-web-acl/abcd-1234',
      },
    } as TerraformResource;

    const factory = new Cf002TfAdapterFactory();
    expect(factory.appliesTo(distributionResource.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: distributionResource,
      allResources: [distributionResource, webAclResource],
    };

    const adapter = factory.bind(context);
    const result = cf002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
