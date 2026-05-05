import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCodePipeline002Rule extends BaseTerraformRule {
  constructor() {
    super('CODEPIPELINE-002', 'HIGH', 'CodePipeline contains hardcoded credentials or insecure parameter references', ['aws_codepipeline']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_codepipeline') {
      const stages = resource.values?.stage;
      if (!Array.isArray(stages)) return null;

      for (const stage of stages) {
        const actions = stage.action;
        if (!Array.isArray(actions)) continue;

        for (const action of actions) {
          const configuration = action.configuration || {};
          if (action.provider === 'GitHub' || action.provider === 'Bitbucket') {
            const oauthToken = configuration.OAuthToken;
            if (typeof oauthToken === 'string' && oauthToken.length > 0 && !oauthToken.includes('{{resolve:')) {
              return this.createScanResult(resource, projectName, this.description, 'Use AWS Secrets Manager or a CodeStar Connection instead of hardcoded OAuthToken.');
            }
          }
        }
      }
    }

    return null;
  }
}

export default new TfCodePipeline002Rule();
