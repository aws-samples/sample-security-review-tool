import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * QS2 Rule: Is encryption in transit enabled for databases to SPICE?
 * 
 * Documentation: "Amazon QuickSight supports encryption for all data transfers. This includes transfers 
 * from the data source to SPICE, or from SPICE to the user interface."
 */
export class QS002Rule extends BaseRule {
  constructor() {
    super(
      'QS-002',
      'HIGH',
      'QuickSight data set does not have encryption in transit enabled for SPICE',
      ['AWS::QuickSight::DataSet']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::QuickSight::DataSet') {
      return null;
    }

    // QS2: Is encryption in transit enabled for databases to SPICE?
    const importMode = resource.Properties?.ImportMode;
    
    // Only validate SPICE datasets (SPICE mode)
    if (importMode !== 'SPICE') {
      return null; // DirectQuery mode doesn't use SPICE
    }

    // Check if dataset has proper data source configuration
    const physicalTableMap = resource.Properties?.PhysicalTableMap;
    if (!physicalTableMap) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add PhysicalTableMap with secure data source configuration for SPICE encryption in transit.`
      );
    }

    // Validate each physical table for secure data source
    for (const [tableId, tableConfig] of Object.entries(physicalTableMap)) {
      const result = this.validatePhysicalTable(resource, stackName, tableId, tableConfig);
      if (result) {
        return result; // Return first issue found
      }
    }

    // SPICE encryption in transit is enabled - QS2 requirement satisfied
    return null;
  }

  private validatePhysicalTable(resource: CloudFormationResource, stackName: string, tableId: string, tableConfig: any): ScanResult | null {
    // Check relational table (database sources)
    if (tableConfig.RelationalTable) {
      return this.validateRelationalTable(resource, stackName, tableConfig.RelationalTable);
    }

    // Check custom SQL (database sources)
    if (tableConfig.CustomSql) {
      return this.validateCustomSql(resource, stackName, tableConfig.CustomSql);
    }

    // S3Source requires DataSourceArn (uses HTTPS by default for encryption in transit)
    if (tableConfig.S3Source) {
      return this.validateS3Source(resource, stackName, tableConfig.S3Source);
    }

    return null;
  }

  private validateRelationalTable(resource: CloudFormationResource, stackName: string, relationalTable: any): ScanResult | null {
    const dataSourceArn = relationalTable.DataSourceArn;
    
    if (!dataSourceArn) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Specify DataSourceArn in RelationalTable to ensure secure connection for SPICE data transfer.`
      );
    }

    // The data source should be configured with TLS (validated by QS1 rule)
    // Here we ensure the dataset references a proper data source
    return null;
  }

  private validateCustomSql(resource: CloudFormationResource, stackName: string, customSql: any): ScanResult | null {
    const dataSourceArn = customSql.DataSourceArn;
    
    if (!dataSourceArn) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Specify DataSourceArn in CustomSql to ensure secure connection for SPICE data transfer.`
      );
    }

    // The data source should be configured with TLS (validated by QS1 rule)
    return null;
  }

  private validateS3Source(resource: CloudFormationResource, stackName: string, s3Source: any): ScanResult | null {
    const dataSourceArn = s3Source.DataSourceArn;
    
    if (!dataSourceArn) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Specify DataSourceArn in S3Source to ensure secure connection for SPICE data transfer.`
      );
    }

    // S3 uses HTTPS by default for encryption in transit
    return null;
  }
}

export default new QS002Rule();