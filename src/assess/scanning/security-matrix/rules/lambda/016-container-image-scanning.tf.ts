import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda016Rule extends BaseTerraformRule {
  constructor() {
    super(
      'LAMBDA-016',
      'HIGH',
      'Lambda container images should be periodically scanned for vulnerabilities according to lifecycle policies',
      ['aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_lambda_function') return null;

    const packageType = resource.values?.package_type;
    const imageUri = resource.values?.image_uri;

    if (packageType !== 'Image' && !imageUri) return null;

    if (imageUri && typeof imageUri === 'string') {
      if (this.isFromEcr(imageUri)) {
        const ecrRepo = this.findAssociatedEcrRepo(imageUri, allResources);
        if (ecrRepo) {
          const scanOnPush = ecrRepo.values?.image_scanning_configuration;
          const hasScanning = Array.isArray(scanOnPush)
            ? scanOnPush.some((cfg: any) => cfg.scan_on_push === true)
            : false;

          if (!hasScanning) {
            return this.createScanResult(
              resource,
              projectName,
              this.description,
              'Ensure the ECR repository for this Lambda function has image_scanning_configuration with scan_on_push = true.'
            );
          }
          return null;
        }
      }

      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Ensure the container image repository has vulnerability scanning enabled and assign an owner to maintain Lambda container images.'
      );
    }

    return null;
  }

  private isFromEcr(imageUri: string): boolean {
    return imageUri.includes('amazonaws.com') &&
      (imageUri.includes('ecr.') || imageUri.includes('.dkr.ecr.'));
  }

  private findAssociatedEcrRepo(imageUri: string, allResources: TerraformResource[]): TerraformResource | null {
    const match = imageUri.match(/amazonaws\.com\/([^:]+)/);
    if (!match || !match[1]) return null;

    const repoName = match[1];
    return allResources.find(r =>
      r.type === 'aws_ecr_repository' && r.values?.name === repoName
    ) || null;
  }
}

export default new TfLambda016Rule();
