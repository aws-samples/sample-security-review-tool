import { describe, it, expect } from 'vitest';
import QS002Rule from '../../../../../../src/assess/scanning/security-matrix/rules/quicksight/002-spice-encryption-transit.cf.js';
import { CloudFormationResource } from "../../../../../../src/assess/scanning/security-matrix/security-rule-base";
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner.js';

describe('QS-002: QuickSight SPICE encryption in transit rule', () => {
  const stackName = 'test-stack';

  function createDataSet(props: any = {}): CloudFormationResource {
    return {
      Type: 'AWS::QuickSight::DataSet',
      LogicalId: 'TestDataSet',
      Properties: {
        Name: 'test-dataset',
        AwsAccountId: '123456789012',
        DataSetId: 'test-dataset-id',
        ImportMode: 'SPICE',
        ...props
      }
    };
  }

  it('passes when SPICE dataset has proper RelationalTable with DataSourceArn', () => {
    const resource = createDataSet({
      PhysicalTableMap: {
        'table1': {
          RelationalTable: {
            DataSourceArn: 'arn:aws:quicksight:us-east-1:123456789012:datasource/test-datasource',
            Name: 'test-table',
            InputColumns: [
              {
                Name: 'id',
                Type: 'INTEGER'
              }
            ]
          }
        }
      }
    });

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when SPICE dataset has proper CustomSql with DataSourceArn', () => {
    const resource = createDataSet({
      PhysicalTableMap: {
        'table1': {
          CustomSql: {
            DataSourceArn: 'arn:aws:quicksight:us-east-1:123456789012:datasource/test-datasource',
            Name: 'custom-query',
            SqlQuery: 'SELECT * FROM test_table',
            Columns: [
              {
                Name: 'id',
                Type: 'INTEGER'
              }
            ]
          }
        }
      }
    });

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when SPICE dataset uses S3Source', () => {
    const resource = createDataSet({
      PhysicalTableMap: {
        'table1': {
          S3Source: {
            DataSourceArn: 'arn:aws:quicksight:us-east-1:123456789012:datasource/s3-datasource',
            InputColumns: [
              {
                Name: 'id',
                Type: 'INTEGER'
              }
            ]
          }
        }
      }
    });

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('passes when dataset uses DirectQuery mode', () => {
    const resource = createDataSet({
      ImportMode: 'DIRECT_QUERY',
      PhysicalTableMap: {
        'table1': {
          RelationalTable: {
            Name: 'test-table',
            InputColumns: [
              {
                Name: 'id',
                Type: 'INTEGER'
              }
            ]
          }
        }
      }
    });

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('fails when SPICE dataset has no PhysicalTableMap', () => {
    const resource = createDataSet();

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('QuickSight data set does not have encryption in transit enabled for SPICE');
    expect((result as ScanResult).fix).toContain('Add PhysicalTableMap with secure data source configuration');
  });

  it('fails when SPICE dataset RelationalTable has no DataSourceArn', () => {
    const resource = createDataSet({
      PhysicalTableMap: {
        'table1': {
          RelationalTable: {
            Name: 'test-table',
            InputColumns: [
              {
                Name: 'id',
                Type: 'INTEGER'
              }
            ]
          }
        }
      }
    });

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('QuickSight data set does not have encryption in transit enabled for SPICE');
    expect((result as ScanResult).fix).toContain('Specify DataSourceArn in RelationalTable');
  });

  it('fails when SPICE dataset CustomSql has no DataSourceArn', () => {
    const resource = createDataSet({
      PhysicalTableMap: {
        'table1': {
          CustomSql: {
            Name: 'custom-query',
            SqlQuery: 'SELECT * FROM test_table',
            Columns: [
              {
                Name: 'id',
                Type: 'INTEGER'
              }
            ]
          }
        }
      }
    });

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('QuickSight data set does not have encryption in transit enabled for SPICE');
    expect((result as ScanResult).fix).toContain('Specify DataSourceArn in CustomSql');
  });

  it('validates multiple physical tables and returns first issue', () => {
    const resource = createDataSet({
      PhysicalTableMap: {
        'table1': {
          RelationalTable: {
            DataSourceArn: 'arn:aws:quicksight:us-east-1:123456789012:datasource/test-datasource',
            Name: 'test-table1',
            InputColumns: [{ Name: 'id', Type: 'INTEGER' }]
          }
        },
        'table2': {
          RelationalTable: {
            Name: 'test-table2',  // Missing DataSourceArn
            InputColumns: [{ Name: 'id', Type: 'INTEGER' }]
          }
        }
      }
    });

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).fix).toContain('Specify DataSourceArn in RelationalTable');
  });

  it('ignores non-QuickSight DataSet resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::QuickSight::DataSource',
      LogicalId: 'TestDataSource',
      Properties: {
        Name: 'test-data-source'
      }
    };

    const result = QS002Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });
});