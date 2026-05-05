import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class CompLamb016Rule extends BaseRule {
  constructor() {
    super(
      'LAMBDA-016',
      'HIGH',
      'Lambda container images should be periodically scanned for vulnerabilities according to lifecycle policies',
      ['AWS::Lambda::Function']
    );
  }

  // Note: ECR repository scanning checks are now handled by ECR rules
  // This rule focuses only on Lambda functions using container images

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Handle Lambda functions with container images
    if (resource.Type === 'AWS::Lambda::Function') {
      return this.evaluateLambdaFunction(resource, stackName, allResources);
    }

    return null;
  }

  private evaluateLambdaFunction(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const properties = resource.Properties;
    if (!properties) {
      return null;
    }

    // Check if this is a container image-based Lambda function
    if (properties.PackageType === 'Image' || (properties.Code && properties.Code.ImageUri)) {
      const imageUri = properties.Code?.ImageUri;

      // If it's a string, check if it's from ECR
      if (imageUri && typeof imageUri === 'string') {
        // If it's from ECR, try to find the associated repository
        if (this.isFromEcr(imageUri)) {
          // Check if we have associated ECR repository in the template
          const ecrRepo = this.findAssociatedEcrRepo(imageUri, allResources);

          // If we found the repository, check its configuration
          if (ecrRepo) {
            const scanningEnabled = this.hasScanningEnabled(ecrRepo);
            const hasOwnership = this.hasOwnershipTags(ecrRepo);

            if (!scanningEnabled || !hasOwnership) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Ensure the ECR repository for this Lambda function has scan-on-push enabled and ownership tags defined. Periodically scan all AWS Lambda container images for vulnerabilities according to lifecycle policies.`
              );
            }

            // If everything is configured correctly, no issue
            return null;
          }
        }

        // If we can't verify the repository configuration, return a reminder
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Ensure the container image repository has vulnerability scanning enabled and assign an owner to maintain Lambda container images. Periodically scan all AWS Lambda container images for vulnerabilities according to lifecycle policies.`
        );
      }

      // If it's an intrinsic function or other non-string value
      if (imageUri && typeof imageUri === 'object') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Ensure the container image referenced by the intrinsic function is stored in a repository with vulnerability scanning enabled. Assign an owner to maintain Lambda container images.`
        );
      }
    }

    return null;
  }

  // Note: ECR repository scanning checks are now handled by ECR rules

  private isFromEcr(imageUri: string): boolean {
    return imageUri.includes('amazonaws.com') &&
      (imageUri.includes('ecr.') || imageUri.includes('.dkr.ecr.'));
  }

  private findAssociatedEcrRepo(imageUri: string, allResources?: CloudFormationResource[]): CloudFormationResource | null {
    if (!allResources) {
      return null;
    }

    // Extract repository name from ECR URI
    // Format: account.dkr.ecr.region.amazonaws.com/repository:tag
    const match = imageUri.match(/amazonaws\.com\/([^:]+)/);
    if (!match || !match[1]) {
      return null;
    }

    const repoName = match[1];

    // Find ECR repository with matching name
    return allResources.find(res =>
      res.Type === 'AWS::ECR::Repository' &&
      res.Properties?.RepositoryName === repoName
    ) || null;
  }

  private hasScanningEnabled(ecrRepo: CloudFormationResource): boolean {
    // Check if ScanOnPush is enabled
    return ecrRepo.Properties?.ScanOnPush === true;
  }

  private hasOwnershipTags(resource: CloudFormationResource): boolean {
    const tags = resource.Properties?.Tags || [];

    // Check for common ownership tag keys
    const ownershipKeys = ['Owner', 'Maintainer', 'Team', 'Department', 'Project'];

    return tags.some((tag: any) =>
      ownershipKeys.some(key =>
        tag.Key?.toLowerCase() === key.toLowerCase() ||
        tag.key?.toLowerCase() === key.toLowerCase()
      )
    );
  }
}

export default new CompLamb016Rule();
