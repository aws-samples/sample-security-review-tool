import { describe, it, expect } from 'vitest';
import QS001Rule from '../../../../../../src/assess/scanning/security-matrix/rules/quicksight/001-tls-database-connection.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { ScanResult } from '../../../../../../src/core/scanners/base-scanner.js';


describe('QS-001: QuickSight TLS database connection rule', () => {
  const stackName = 'test-stack';

  function createDataSource(dataSourceParameters: any): CloudFormationResource {
    return {
      Type: 'AWS::QuickSight::DataSource',
      LogicalId: 'TestDataSource',
      Properties: {
        Name: 'test-data-source',
        Type: 'MYSQL',
        DataSourceParameters: dataSourceParameters
      }
    };
  }

  describe('RDS Parameters', () => {
    it('passes when RDS uses AWS managed endpoint', () => {
      const resource = createDataSource({
        RdsParameters: {
          InstanceId: 'test-instance',
          Database: 'testdb',
          Host: 'test-instance.abc123.us-east-1.rds.amazonaws.com'
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('fails when RDS has SSL in hostname but no explicit SSL configuration', () => {
      const resource = createDataSource({
        RdsParameters: {
          InstanceId: 'test-instance',
          Database: 'testdb',
          Host: 'ssl-enabled-db.example.com'
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).issue).toContain('QuickSight data source does not have TLS enabled');
      expect((result as ScanResult).fix).toContain('Enable SSL/TLS by setting SslProperties configuration');
    });

    it('fails when RDS uses non-SSL external host', () => {
      const resource = createDataSource({
        RdsParameters: {
          InstanceId: 'test-instance',
          Database: 'testdb',
          Host: 'external-db.example.com'
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).issue).toContain('QuickSight data source does not have TLS enabled');
      expect((result as ScanResult).fix).toContain('Enable SSL/TLS by setting SslProperties configuration');
    });
  });

  describe('Aurora Parameters', () => {
    it('passes when Aurora uses AWS managed endpoint', () => {
      const resource = createDataSource({
        AuroraParameters: {
          Database: 'testdb',
          Host: 'test-cluster.cluster-abc123.us-east-1.rds.amazonaws.com'
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('fails when Aurora uses non-SSL external host', () => {
      const resource = createDataSource({
        AuroraParameters: {
          Database: 'testdb',
          Host: 'external-aurora.example.com'
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).fix).toContain('Enable SSL/TLS by setting SslProperties configuration');
    });
  });

  describe('Redshift Parameters', () => {
    it('passes when Redshift uses AWS managed endpoint', () => {
      const resource = createDataSource({
        RedshiftParameters: {
          Database: 'testdb',
          Host: 'test-cluster.abc123.us-east-1.redshift.amazonaws.com',
          ClusterId: 'test-cluster'
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('fails when Redshift uses non-SSL external host', () => {
      const resource = createDataSource({
        RedshiftParameters: {
          Database: 'testdb',
          Host: 'external-redshift.example.com',
          ClusterId: 'test-cluster'
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).fix).toContain('Enable SSL/TLS by setting SslProperties configuration');
    });
  });

  describe('PostgreSQL Parameters', () => {
    it('passes when PostgreSQL has explicit SSL configuration', () => {
      const resource = createDataSource({
        PostgreSqlParameters: {
          Database: 'testdb',
          Host: 'postgres.example.com',
          Port: 5432,
          SslProperties: {
            Mode: 'require'
          }
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('fails when PostgreSQL has no SSL configuration', () => {
      const resource = createDataSource({
        PostgreSqlParameters: {
          Database: 'testdb',
          Host: 'postgres.example.com',
          Port: 5432
        }
      });

      const result = QS001Rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect((result as ScanResult).fix).toContain('Enable SSL/TLS by setting SslProperties configuration');
    });
  });

  it('fails when data source has no DataSourceParameters', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::QuickSight::DataSource',
      LogicalId: 'TestDataSource',
      Properties: {
        Name: 'test-data-source',
        Type: 'MYSQL'
      }
    };

    const result = QS001Rule.evaluate(resource, stackName);
    expect(result).not.toBeNull();
    expect((result as ScanResult).issue).toContain('QuickSight data source does not have TLS enabled');
    expect((result as ScanResult).fix).toContain('Add DataSourceParameters with SSL/TLS configuration');
  });

  it('passes when data source uses non-database type', () => {
    const resource = createDataSource({
      S3Parameters: {
        ManifestFileLocation: {
          Bucket: 'test-bucket',
          Key: 'manifest.json'
        }
      }
    });

    const result = QS001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });

  it('ignores non-QuickSight resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::RDS::DBInstance',
      LogicalId: 'TestDB',
      Properties: {
        DBInstanceClass: 'db.t3.micro'
      }
    };

    const result = QS001Rule.evaluate(resource, stackName);
    expect(result).toBeNull();
  });
});