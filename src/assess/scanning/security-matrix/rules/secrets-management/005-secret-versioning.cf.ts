import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Sec005Rule extends BaseRule {
  constructor() {
    super(
      'SEC-005',
      'MEDIUM',
      'Secret lacks documentation of purpose and ownership',
      ['AWS::SecretsManager::Secret']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::SecretsManager::Secret') {
      // Note: This rule has been repurposed from checking versioning strategy
      // (which is automatically handled by AWS Secrets Manager) to checking
      // for proper documentation of the secret's purpose and ownership.

      // Check if the secret has a description
      const description = resource.Properties?.Description;
      if (!description) {
        return this.createScanResult(
          resource,
          stackName,
          'Secret lacks a description',
          `Add a Description property to document the purpose of the secret.`
        );
      }

      // Check if the description is meaningful (more than just a few characters)
      if (typeof description === 'string' && description.length < 10) {
        return this.createScanResult(
          resource,
          stackName,
          'Secret has a very short description',
          `Provide a more detailed description that explains the purpose of the secret and who owns it.`
        );
      }

      // Check if the description includes ownership information
      const hasOwnershipInfo = this.hasOwnershipInformation(description);

      // Check if the description includes purpose information
      const hasPurposeInfo = this.hasPurposeInformation(description);

      if (!hasOwnershipInfo) {
        return this.createScanResult(
          resource,
          stackName,
          'Secret description lacks ownership information',
          `Update the Description property to include who owns this secret (team, department, etc.).`
        );
      }

      if (!hasPurposeInfo) {
        return this.createScanResult(
          resource,
          stackName,
          'Secret description lacks purpose information',
          `Update the Description property to include what this secret is used for (application, service, etc.).`
        );
      }
    }

    return null;
  }

  /**
   * Checks if a description includes ownership information
   * @param description The description to check
   * @returns True if the description includes ownership information, false otherwise
   */
  private hasOwnershipInformation(description: string | undefined): boolean {
    if (!description) {
      return false;
    }

    const ownershipKeywords = [
      'owner', 'owned', 'owns', 'ownership',
      'team', 'department', 'group',
      'responsible', 'responsibility',
      'managed', 'manager', 'management'
    ];

    // Check if the description contains any ownership keywords
    return ownershipKeywords.some(keyword =>
      description.toLowerCase().includes(keyword)
    );
  }

  /**
   * Checks if a description includes purpose information
   * @param description The description to check
   * @returns True if the description includes purpose information, false otherwise
   */
  private hasPurposeInformation(description: string | undefined): boolean {
    if (!description) {
      return false;
    }

    const purposeKeywords = [
      'purpose', 'used for', 'used by', 'used in',
      'application', 'service', 'function',
      'role', 'access to', 'authenticate',
      'database', 'api', 'endpoint'
    ];

    // Check if the description contains any purpose keywords
    return purposeKeywords.some(keyword =>
      description.toLowerCase().includes(keyword)
    );
  }
}

export default new Sec005Rule();
