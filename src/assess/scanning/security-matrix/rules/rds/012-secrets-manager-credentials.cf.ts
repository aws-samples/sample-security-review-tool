import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds012Rule extends BaseRule {
  // Supported RDS database types for automatic rotation
  private supportedEngines = [
    'mysql',
    'postgres',
    'postgresql',
    'mariadb',
    'aurora',
    'aurora-mysql',
    'aurora-postgresql'
  ];

  constructor() {
    super(
      'RDS-012',
      'HIGH',
      'RDS database credentials are not stored in AWS Secrets Manager with automatic rotation enabled',
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is one of our target RDS resource types
    if (!this.appliesTo(resource.Type) || !resource.Properties) {
      return null;
    }

    // If we don't have access to all resources, we can't check for Secrets Manager references
    if (!allResources) {
      return null;
    }

    // Check if credentials are stored in Secrets Manager (required for ALL engines)
    const hasSecretManagerCredentials = this.hasSecretsManagerCredentials(resource);
    if (!hasSecretManagerCredentials) {
      return this.createScanResult(
        resource,
        stackName,
        `RDS database credentials are not stored in AWS Secrets Manager`,
        `Store RDS credentials in AWS Secrets Manager using references like '{{resolve:secretsmanager:MySecret:SecretString:username}}' and '{{resolve:secretsmanager:MySecret:SecretString:password}}'.`
      );
    }

    // Check if the engine supports automatic rotation
    const engine = this.getEngineType(resource);
    const engineSupportsRotation = engine && this.isEngineSupported(engine);

    // For supported engines, also check if rotation is enabled
    if (engineSupportsRotation) {
      const hasRotationEnabled = this.hasRotationEnabled(allResources);
      if (!hasRotationEnabled) {
        return this.createScanResult(
          resource,
          stackName,
          `RDS database uses Secrets Manager but automatic rotation is not enabled`,
          `Enable automatic rotation for the AWS Secrets Manager secret by adding a rotation configuration with 'AutomaticallyAfterDays' property.`
        );
      }
    }

    // For unsupported engines, having Secrets Manager is sufficient
    return null;
  }

  /**
   * Get the engine type from the resource
   */
  private getEngineType(resource: CloudFormationResource): string | null {
    if (!resource.Properties) {
      return null;
    }

    const engine = resource.Properties.Engine;
    if (!engine || typeof engine !== 'string') {
      return null;
    }

    return engine.toLowerCase();
  }

  /**
   * Check if the engine is supported for automatic rotation
   */
  private isEngineSupported(engine: string): boolean {
    return this.supportedEngines.some(supportedEngine =>
      engine.toLowerCase().includes(supportedEngine)
    );
  }

  private hasSecretsManagerCredentials(resource: CloudFormationResource): boolean {
    if (!resource.Properties) {
      return false;
    }

    // Check if ManageMasterUserPassword is enabled (AWS manages everything)
    if (resource.Properties.ManageMasterUserPassword === true) {
      return true;
    }

    // Check if username or password references Secrets Manager
    const credentials = [
      resource.Properties.MasterUsername,
      resource.Properties.MasterUserPassword
    ];

    return credentials.some(credential => this.referencesSecretsManager(credential));
  }

  private referencesSecretsManager(value: any): boolean {
    const valueStr = JSON.stringify(value || '').toLowerCase();
    return valueStr.includes('{{resolve:secretsmanager:') ||
      (valueStr.includes('secretsmanager') && valueStr.includes('"ref"'));
  }

  private hasRotationEnabled(allResources: CloudFormationResource[]): boolean {
    // Check for AWS::SecretsManager::RotationSchedule resources
    const rotationSchedules = allResources.filter(r => r.Type === 'AWS::SecretsManager::RotationSchedule');
    if (rotationSchedules.length > 0) {
      return true;
    }

    // Check for secrets with rotation rules
    const secretsWithRotation = allResources.filter(r =>
      r.Type === 'AWS::SecretsManager::Secret' &&
      r.Properties &&
      r.Properties.RotationRules &&
      r.Properties.RotationRules.AutomaticallyAfterDays
    );

    return secretsWithRotation.length > 0;
  }
}

export default new Rds012Rule();