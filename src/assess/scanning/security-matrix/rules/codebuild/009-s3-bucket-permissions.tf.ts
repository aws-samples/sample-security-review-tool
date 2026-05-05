import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCodeBuild009Rule extends BaseTerraformRule {
  constructor() {
    super('CODEBUILD-009', 'HIGH', 'CodeBuild IAM role missing required S3 bucket permissions', ['aws_codebuild_project']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_codebuild_project') {
      const serviceRole = resource.values?.service_role;
      if (!serviceRole) {
        return this.createScanResult(resource, projectName, this.description, 'Set service_role with an IAM role that includes s3:GetBucketAcl and s3:GetBucketLocation permissions.');
      }
    }

    return null;
  }
}

export default new TfCodeBuild009Rule();
