import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds012Rule extends BaseTerraformRule {
  private supportedEngines = [
    'mysql', 'postgres', 'postgresql', 'mariadb',
    'aurora', 'aurora-mysql', 'aurora-postgresql'
  ];

  constructor() {
    super(
      'RDS-012',
      'HIGH',
      'RDS database credentials are not stored in AWS Secrets Manager with automatic rotation enabled',
      ['aws_db_instance', 'aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_db_instance' && resource.type !== 'aws_rds_cluster') {
      return null;
    }

    if (resource.values?.manage_master_user_password === true) {
      return null;
    }

    const hasSecretsManagerRef = this.referencesSecretsManager(resource, allResources);
    if (!hasSecretsManagerRef) {
      return this.createScanResult(
        resource,
        projectName,
        'RDS database credentials are not stored in AWS Secrets Manager',
        'Set manage_master_user_password = true or store credentials in AWS Secrets Manager using data sources.'
      );
    }

    const engine = resource.values?.engine;
    if (typeof engine === 'string' && this.isEngineSupported(engine)) {
      const hasRotation = this.hasRotationEnabled(allResources);
      if (!hasRotation) {
        return this.createScanResult(
          resource,
          projectName,
          'RDS database uses Secrets Manager but automatic rotation is not enabled',
          'Enable automatic rotation for the AWS Secrets Manager secret by adding an aws_secretsmanager_secret_rotation resource.'
        );
      }
    }

    return null;
  }

  private isEngineSupported(engine: string): boolean {
    return this.supportedEngines.some(supported =>
      engine.toLowerCase().includes(supported)
    );
  }

  private referencesSecretsManager(resource: TerraformResource, allResources: TerraformResource[]): boolean {
    const hasSecretsManagerSecret = allResources.some(r =>
      r.type === 'aws_secretsmanager_secret' || r.type === 'aws_secretsmanager_secret_version'
    );
    return hasSecretsManagerSecret;
  }

  private hasRotationEnabled(allResources: TerraformResource[]): boolean {
    return allResources.some(r =>
      r.type === 'aws_secretsmanager_secret_rotation'
    );
  }
}

export default new TfRds012Rule();
