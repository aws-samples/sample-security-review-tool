import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { hasIntrinsicFunction, containsPattern } from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * ECR1 Rule: ECR image registries are not open to the public unless that is intentional.
 * 
 * Documentation: "A public image registry would allow unauthorized users to download software, code, and binaries. 
 * If the code that is deployed via ECR is proprietary and should not be exposed to the public, 
 * the image registry must not be public."
 * 
 * Note: This rule checks if ECR repositories are configured as public and flags them for review.
 * It's related to Checkov rule CKV_AWS_136 which checks if ECR repositories are encrypted, but
 * this rule specifically focuses on the public accessibility aspect.
 */
export class ECR001Rule extends BaseRule {
  constructor() {
    super(
      'ECR-001',
      'HIGH',
      'ECR repository is configured as public which may expose proprietary code',
      ['AWS::ECR::Repository', 'AWS::ECR::PublicRepository']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Check for public repositories
    if (resource.Type === 'AWS::ECR::PublicRepository') {
      // If there's a tag indicating intentional public access, we'll accept it
      const tags = resource.Properties?.Tags || [];

      // Check if the repository has intentional public access tags
      let hasIntentionalPublicAccess = false;

      // Handle both direct values and intrinsic functions/CDK tokens
      if (hasIntrinsicFunction(tags)) {
        // If tags are defined using intrinsic functions, check if they might contain intentional public access indicators
        const tagsStr = JSON.stringify(tags);
        if (
          tagsStr.includes('Purpose') && tagsStr.includes('Public') ||
          tagsStr.includes('Public') && tagsStr.includes('Intentional') ||
          tagsStr.includes('PublicAccess') && tagsStr.includes('Approved')
        ) {
          // If the tags might contain intentional public access indicators, assume they do
          hasIntentionalPublicAccess = true;
        }
      } else {
        // Handle direct tag values
        hasIntentionalPublicAccess = tags.some((tag: any) => {
          // Handle intrinsic functions in tag keys and values
          if (hasIntrinsicFunction(tag.Key) || hasIntrinsicFunction(tag.Value)) {
            const tagStr = JSON.stringify(tag);
            return (
              (containsPattern(tag.Key, /Purpose/) && containsPattern(tag.Value, /Public/)) ||
              (containsPattern(tag.Key, /Public/) && containsPattern(tag.Value, /Intentional/)) ||
              (containsPattern(tag.Key, /PublicAccess/) && containsPattern(tag.Value, /Approved/))
            );
          }

          // Direct value comparison
          return (
            (tag.Key === 'Purpose' && tag.Value === 'Public') ||
            (tag.Key === 'Public' && tag.Value === 'Intentional') ||
            (tag.Key === 'PublicAccess' && tag.Value === 'Approved')
          );
        });
      }

      if (hasIntentionalPublicAccess) {
        return null;
      }

      // If no intentional public access tags were found, flag it
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Either add a tag indicating intentional public access (e.g., Key='Public', Value='Intentional') or use a private repository instead.`
      );
    }

    // Check for private repositories with potential public access policies
    if (resource.Type === 'AWS::ECR::Repository') {
      const repositoryPolicyText = resource.Properties?.RepositoryPolicyText;

      if (repositoryPolicyText) {
        // Handle intrinsic functions in repository policy
        if (hasIntrinsicFunction(repositoryPolicyText)) {
          // Check if the policy might allow public access by looking for patterns
          const policyStr = JSON.stringify(repositoryPolicyText);

          // For Fn::Sub specifically, we can check the string content directly
          if (repositoryPolicyText['Fn::Sub'] &&
            typeof repositoryPolicyText['Fn::Sub'] === 'string' &&
            (repositoryPolicyText['Fn::Sub'].includes('"Principal":"*"') ||
              repositoryPolicyText['Fn::Sub'].includes('"AWS":"*"'))) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} through potentially overly permissive repository policy defined with intrinsic functions`,
              `Ensure the policy restricts access to specific principals or adds appropriate conditions.`
            );
          }

          // Check for patterns that might indicate public access
          if (
            (policyStr.includes('"Principal"') && policyStr.includes('"*"')) ||
            (policyStr.includes('"Principal"') && policyStr.includes('"AWS"') && policyStr.includes('"*"')) ||
            (policyStr.includes('"Effect"') && policyStr.includes('"Allow"') && !policyStr.includes('"Condition"'))
          ) {
            // If the policy might allow public access, flag it
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} through potentially overly permissive repository policy defined with intrinsic functions`,
              `Ensure the policy restricts access to specific principals or adds appropriate conditions.`
            );
          }

          // If we can't determine for sure, give it the benefit of the doubt
          return null;
        }

        // Handle both string (JSON) and object representations
        let policy: any;
        if (typeof repositoryPolicyText === 'string') {
          try {
            policy = JSON.parse(repositoryPolicyText);
          } catch (e) {
            // If we can't parse it, we can't analyze it properly
            return null;
          }
        } else {
          policy = repositoryPolicyText;
        }

        // Check for potentially public statements in the policy
        if (policy && policy.Statement && Array.isArray(policy.Statement)) {
          for (const statement of policy.Statement) {
            // Handle intrinsic functions in Principal
            if (hasIntrinsicFunction(statement.Principal)) {
              // Check if the principal might be public by looking for patterns
              const principalStr = JSON.stringify(statement.Principal);
              if (principalStr.includes('"*"') && statement.Effect === 'Allow') {
                // Check if there's a condition that might restrict access
                if (!statement.Condition && !hasIntrinsicFunction(statement.Condition)) {
                  return this.createScanResult(
                    resource,
                    stackName,
                    `${this.description} through potentially overly permissive repository policy with intrinsic functions`,
                    `Restrict the repository policy to specific principals or add appropriate conditions.`
                  );
                }
              }
            } else {
              // Handle direct values
              const principal = statement.Principal;

              if (principal === '*' ||
                (typeof principal === 'object' && principal.AWS === '*') ||
                (Array.isArray(principal) && principal.includes('*'))) {

                // Check if Effect is Allow
                if (statement.Effect === 'Allow') {
                  // Check if there's a condition that might restrict access
                  const condition = statement.Condition;
                  if (!condition) {
                    return this.createScanResult(
                      resource,
                      stackName,
                      `${this.description} through overly permissive repository policy`,
                      `Restrict the repository policy to specific principals or add appropriate conditions.`
                    );
                  }
                }
              }
            }
          }
        }
      }
    }

    return null;
  }
}

export default new ECR001Rule();
