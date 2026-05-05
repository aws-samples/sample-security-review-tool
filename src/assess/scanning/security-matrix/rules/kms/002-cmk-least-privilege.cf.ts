import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * KMS-002: Restrict KMS key policies to least-privilege principles
 *
 * Flags overly permissive KMS key policies that use dangerous wildcards.
 *
 * Detects:
 * - kms:* wildcard action (grants full KMS access)
 * - Wildcard principals (* or arn:aws:iam::*:...)
 *
 * Allows:
 * - Root account with kms:* (CDK default for key manageability)
 * - Standard AWS patterns: kms:GenerateDataKey*, kms:ReEncrypt*, kms:GenerateDataKeyPair*
 */
export class KMS002Rule extends BaseRule {
    private static readonly ALLOWED_WILDCARD_ACTIONS = new Set([
        'kms:GenerateDataKey*',
        'kms:ReEncrypt*',
        'kms:GenerateDataKeyPair*'
    ]);

    private static readonly ROOT_ACCOUNT_PATTERN = /^arn:aws:iam::\d{12}:root$/;

    constructor() {
        super(
            'KMS-002',
            'HIGH',
            'KMS key policy grants overly permissive access',
            ['AWS::KMS::Key']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const keyPolicy = resource.Properties?.KeyPolicy;
        if (!keyPolicy?.Statement) return null;

        const statements = Array.isArray(keyPolicy.Statement) ? keyPolicy.Statement : [keyPolicy.Statement];

        for (const statement of statements) {
            if (statement.Effect !== 'Allow') continue;

            const actions = this.normalizeToArray(statement.Action);
            const isRootPrincipal = this.isRootAccountPrincipal(statement.Principal);

            // Skip CDK's root account kms:* pattern (required for key manageability)
            const isCdkRootPattern = isRootPrincipal && actions.length === 1 && actions[0] === 'kms:*';
            if (isCdkRootPattern) continue;

            const overlyPermissiveActions = actions.filter(action =>
                typeof action === 'string' && this.isOverlyPermissiveWildcard(action)
            );

            if (overlyPermissiveActions.length > 0) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    this.buildWildcardActionFix(overlyPermissiveActions)
                );
            }

            // Check for wildcard principals
            const wildcardPrincipal = this.findWildcardPrincipal(statement.Principal);
            if (wildcardPrincipal) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    this.buildWildcardPrincipalFix(wildcardPrincipal)
                );
            }
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }

    private normalizeToArray(value: any): any[] {
        return Array.isArray(value) ? value : [value];
    }

    private isOverlyPermissiveWildcard(action: string): boolean {
        if (!action.includes('*')) return false;
        return !KMS002Rule.ALLOWED_WILDCARD_ACTIONS.has(action);
    }

    private isRootAccountPrincipal(principal: any): boolean {
        if (!principal) return false;

        if (typeof principal.AWS === 'string') {
            return KMS002Rule.ROOT_ACCOUNT_PATTERN.test(principal.AWS);
        }

        if (Array.isArray(principal.AWS) && principal.AWS.length === 1) {
            return KMS002Rule.ROOT_ACCOUNT_PATTERN.test(principal.AWS[0]);
        }

        return false;
    }

    private findWildcardPrincipal(principal: any): string | null {
        if (principal === '*') return '*';

        if (typeof principal?.AWS === 'string' && principal.AWS.includes('*')) {
            return principal.AWS;
        }

        if (Array.isArray(principal?.AWS)) {
            const wildcard = principal.AWS.find((p: string) => typeof p === 'string' && p.includes('*'));
            if (wildcard) return wildcard;
        }

        return null;
    }

    private buildWildcardActionFix(actions: string[]): string {
        return `The key policy grants overly permissive access with wildcard action(s): ${actions.join(', ')}. ` +
            `Replace with specific KMS actions based on the use case. ` +
            `For encryption-only access, use: kms:Encrypt, kms:GenerateDataKey, kms:GenerateDataKeyWithoutPlaintext. ` +
            `For decryption-only access, use: kms:Decrypt, kms:DescribeKey. ` +
            `Standard wildcard patterns like kms:GenerateDataKey* and kms:ReEncrypt* are acceptable.`;
    }

    private buildWildcardPrincipalFix(principal: string): string {
        return `The key policy grants access to wildcard principal "${principal}" which allows any AWS account or identity to use this key. ` +
            `Replace with specific principals: use IAM role ARNs (arn:aws:iam::ACCOUNT_ID:role/RoleName), ` +
            `IAM user ARNs (arn:aws:iam::ACCOUNT_ID:user/UserName), ` +
            `or AWS service principals (e.g., { "Service": "s3.amazonaws.com" }) with appropriate conditions.`;
    }
}

export default new KMS002Rule();
