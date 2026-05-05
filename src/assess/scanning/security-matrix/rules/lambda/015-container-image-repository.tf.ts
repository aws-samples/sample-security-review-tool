import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda015Rule extends BaseTerraformRule {
  constructor() {
    super(
      'LAMBDA-015',
      'HIGH',
      'Lambda function container image may not be stored in a secure repository',
      ['aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_lambda_function') return null;

    const packageType = resource.values?.package_type;
    const imageUri = resource.values?.image_uri;

    if (packageType !== 'Image' && !imageUri) return null;

    if (imageUri && typeof imageUri === 'string') {
      if (!this.isFromSecureRepository(imageUri)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Store the container image '${imageUri}' in a secure repository like Amazon ECR with vulnerability scanning enabled.`
        );
      }

      if (imageUri.endsWith(':latest') || !imageUri.includes(':')) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Use a specific version tag instead of 'latest' for the container image '${imageUri}'.`
        );
      }
    }

    return null;
  }

  private isFromSecureRepository(imageUri: string): boolean {
    const secureRepoPatterns = [
      'amazonaws.com',
      'public.ecr.aws',
      'jfrog.io',
      'azurecr.io',
      'gcr.io',
      'registry.gitlab.com',
      'ghcr.io'
    ];

    return secureRepoPatterns.some(pattern => imageUri.includes(pattern));
  }
}

export default new TfLambda015Rule();
