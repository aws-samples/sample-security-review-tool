import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCodePipeline001Rule extends BaseTerraformRule {
  constructor() {
    super('CODEPIPELINE-001', 'HIGH', 'CodePipeline does not use customer-managed KMS key for S3 artifacts', ['aws_codepipeline']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_codepipeline') {
      const artifactStore = resource.values?.artifact_store;
      if (Array.isArray(artifactStore)) {
        for (const store of artifactStore) {
          if (!store.encryption_key) {
            return this.createScanResult(resource, projectName, this.description, 'Add encryption_key { id = "<kms-key-arn>", type = "KMS" } to artifact_store.');
          }
        }
      } else if (artifactStore && !artifactStore.encryption_key) {
        return this.createScanResult(resource, projectName, this.description, 'Add encryption_key { id = "<kms-key-arn>", type = "KMS" } to artifact_store.');
      }
    }

    return null;
  }
}

export default new TfCodePipeline001Rule();
