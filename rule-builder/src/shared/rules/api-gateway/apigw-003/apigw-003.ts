import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as wafregional from 'aws-cdk-lib/aws-wafregional';

/**
 * Fixture for APIGW-003: Public-facing API Gateway stages must have an AWS WAF
 * web ACL associated with them.
 *
 * Scenario 1 (missing-web-acl-association): "MissingAclStage" has no web ACL
 * association of any kind.
 *
 * Scenario 2 (legacy-web-acl-association): "LegacyAclStage" is covered only by
 * an end-of-life legacy AWS::WAFRegional::WebACLAssociation, not by a current
 * generation AWS::WAFv2::WebACLAssociation.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Shared REST API (current generation AWS::ApiGateway::RestApi, not a
    // newer-generation HTTP/WebSocket API) with two explicit stages.
    const restApi = new apigateway.CfnRestApi(this, 'RestApi', {
      name: 'fixture-api',
    });

    const deployment = new apigateway.CfnDeployment(this, 'Deployment', {
      restApiId: restApi.ref,
    });

    // --- Scenario: missing-web-acl-association ---
    // No web ACL association targets this stage at all.
    new apigateway.CfnStage(this, 'MissingAclStage', {
      restApiId: restApi.ref,
      deploymentId: deployment.ref,
      stageName: 'missing-acl',
    });

    // --- Scenario: legacy-web-acl-association ---
    // Only an end-of-life AWS::WAFRegional::WebACLAssociation covers this
    // stage; there is no current-generation AWS::WAFv2::WebACLAssociation.
    const legacyStage = new apigateway.CfnStage(this, 'LegacyAclStage', {
      restApiId: restApi.ref,
      deploymentId: deployment.ref,
      stageName: 'legacy-acl',
    });

    new wafregional.CfnWebACLAssociation(this, 'LegacyWebAclAssociation', {
      // Preprocessing resolves Ref to a resource's logical ID, so this
      // literal matches what the rule will see for `Ref: LegacyAclStage`.
      resourceArn: 'LegacyAclStage',
      webAclId: 'legacy-web-acl-id',
    });

    // Ensure the association is created after the stage it targets.
    legacyStage.node.addDependency(deployment);
  }
}
