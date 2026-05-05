import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class CompLamb015Rule extends BaseRule {
  constructor() {
    super(
      'LAMBDA-015',
      'HIGH',
      'Lambda function container image may not be stored in a secure repository',
      ['AWS::Lambda::Function']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::Lambda::Function') {
      return null;
    }

    const properties = resource.Properties;
    if (!properties) {
      return null;
    }

    // Check if this is a container image-based Lambda function
    if (properties.PackageType === 'Image' || (properties.Code && properties.Code.ImageUri)) {
      // Check if the image is from a secure repository
      const imageUri = properties.Code?.ImageUri;

      // Handle intrinsic functions
      if (imageUri && typeof imageUri === 'object') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Ensure the container image referenced by the intrinsic function is stored in a secure repository like AWS ECR.`
        );
      }

      if (imageUri && typeof imageUri === 'string') {
        // Check if the image is from a secure repository
        if (!this.isFromSecureRepository(imageUri)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Store the container image '${imageUri}' in a secure repository like Amazon ECR with vulnerability scanning enabled.`
          );
        }

        // Check for 'latest' tag or no tag
        if (imageUri.endsWith(':latest') || !imageUri.includes(':')) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Use a specific version tag instead of 'latest' for the container image '${imageUri}'.`
          );
        }
      }
    }

    return null;
  }

  private isFromSecureRepository(imageUri: string): boolean {
    // Check if the image is from a known secure repository
    const secureRepoPatterns = [
      'amazonaws.com', // ECR
      'public.ecr.aws', // AWS Public ECR
      'jfrog.io', // JFrog Artifactory
      'azurecr.io', // Azure Container Registry
      'gcr.io', // Google Container Registry
      'registry.gitlab.com', // GitLab Container Registry
      'ghcr.io' // GitHub Container Registry
    ];

    return secureRepoPatterns.some(pattern => imageUri.includes(pattern));
  }
}

export default new CompLamb015Rule();
