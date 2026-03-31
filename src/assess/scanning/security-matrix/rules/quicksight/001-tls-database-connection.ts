import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * QS1 Rule: I confirm that the TLS protocol is used to connect to databases from QuickSight.
 * 
 * Documentation: "Use TLS to connect to your databases, especially if you are using public networks. 
 * Using TLS with Amazon QuickSight requires the use of certificates signed by a publicly-recognized certificate authority (CA)."
 */
export class QS001Rule extends BaseRule {
  constructor() {
    super(
      'QS-001',
      'HIGH',
      'QuickSight data source does not have TLS enabled for database connections',
      ['AWS::QuickSight::DataSource']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::QuickSight::DataSource') {
      return null;
    }

    // QS1: Is TLS protocol used to connect to databases from QuickSight?
    const dataSourceParameters = resource.Properties?.DataSourceParameters;
    
    if (!dataSourceParameters) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add DataSourceParameters with SSL/TLS configuration for secure database connections.`
      );
    }

    // Check database parameters for SSL/TLS configuration
    const databaseParams = [
      dataSourceParameters.AmazonElasticsearchParameters,
      dataSourceParameters.AmazonOpenSearchParameters,
      dataSourceParameters.AuroraParameters,
      dataSourceParameters.AuroraPostgreSqlParameters,
      dataSourceParameters.DatabricksParameters,
      dataSourceParameters.MariaDbParameters,
      dataSourceParameters.MySqlParameters,
      dataSourceParameters.OracleParameters,
      dataSourceParameters.PostgreSqlParameters,
      dataSourceParameters.PrestoParameters,
      dataSourceParameters.RdsParameters,
      dataSourceParameters.RedshiftParameters,
      dataSourceParameters.SnowflakeParameters,
      dataSourceParameters.SparkParameters,
      dataSourceParameters.SqlServerParameters,
      dataSourceParameters.StarburstParameters,
      dataSourceParameters.TeradataParameters,
      dataSourceParameters.TrinoParameters
    ].find(param => param);

    if (databaseParams) {
      return this.validateDatabaseParameters(resource, stackName, databaseParams);
    }

    // Non-database sources (S3Parameters, AthenaParameters) don't require explicit TLS validation
    return null;
  }

  private validateDatabaseParameters(resource: CloudFormationResource, stackName: string, dbParams: any): ScanResult | null {
    if (!dbParams.Database && !dbParams.Catalog) {
      return null; // No database specified
    }

    if (!this.hasTlsConfiguration(resource, dbParams)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable SSL/TLS by setting SslProperties configuration for database connection.`
      );
    }

    return null;
  }

  private hasTlsConfiguration(resource: CloudFormationResource, params: any): boolean {
    const topLevelSslProperties = resource.Properties?.SslProperties;
    
    // Check if SSL is explicitly disabled
    if (topLevelSslProperties?.DisableSsl === true || params.SslProperties?.DisableSsl === true) {
      return false;
    }
    
    // Require explicit SSL configuration for non-AWS managed services
    const host = params.Host || '';
    const isAWSManaged = host.includes('.amazonaws.com') || host.includes('.rds.');
    
    if (!isAWSManaged) {
      // For external databases, require explicit SslProperties
      return !!(topLevelSslProperties || params.SslProperties);
    }
    
    return true; // AWS managed services have SSL by default
  }
}

export default new QS001Rule();