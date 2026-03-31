import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * KDF2 Rule: I confirm that encryption have been enable at the delivery stream destination?
 * 
 * Documentation: "Kinesis Firehose delivery stream data records are encrypted at destination (i.e., Amazon S3)."
 */
export class KDF002Rule extends BaseRule {
  constructor() {
    super(
      'KDF-002',
      'HIGH',
      'Kinesis Data Firehose delivery stream destination does not have encryption enabled',
      ['AWS::KinesisFirehose::DeliveryStream']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::KinesisFirehose::DeliveryStream') {
      return null;
    }

    // KDF2: Is encryption enabled at the delivery stream destination?
    const s3Config = resource.Properties?.S3DestinationConfiguration || 
                    resource.Properties?.ExtendedS3DestinationConfiguration;
    
    if (s3Config) {
      return this.evaluateS3Destination(resource, stackName, s3Config);
    }

    const redshiftConfig = resource.Properties?.RedshiftDestinationConfiguration;
    if (redshiftConfig) {
      return this.evaluateRedshiftDestination(resource, stackName, redshiftConfig);
    }

    const elasticsearchConfig = resource.Properties?.ElasticsearchDestinationConfiguration;
    if (elasticsearchConfig) {
      return this.evaluateElasticsearchDestination(resource, stackName, elasticsearchConfig);
    }

    // No supported destination found - pass (other destinations may have different encryption requirements)
    return null;
  }

  private evaluateS3Destination(resource: CloudFormationResource, stackName: string, s3Config: any): ScanResult | null {
    const encryptionConfiguration = s3Config.EncryptionConfiguration;
    
    if (!encryptionConfiguration) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add EncryptionConfiguration to S3DestinationConfiguration with KMSEncryptionConfig or NoEncryptionConfig.`
      );
    }

    // Check if encryption is explicitly disabled
    if (encryptionConfiguration.NoEncryptionConfig) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Remove NoEncryptionConfig and add KMSEncryptionConfig to enable S3 destination encryption.`
      );
    }

    // KMS encryption should be configured
    if (!encryptionConfiguration.KMSEncryptionConfig) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add KMSEncryptionConfig with AWSKMSKeyARN to enable S3 destination encryption.`
      );
    }

    return null;
  }

  private evaluateRedshiftDestination(resource: CloudFormationResource, stackName: string, redshiftConfig: any): ScanResult | null {
    const s3Config = redshiftConfig.S3Configuration;
    if (s3Config) {
      return this.evaluateS3Destination(resource, stackName, s3Config);
    }
    return null;
  }

  private evaluateElasticsearchDestination(resource: CloudFormationResource, stackName: string, elasticsearchConfig: any): ScanResult | null {
    const s3Config = elasticsearchConfig.S3Configuration;
    if (s3Config) {
      return this.evaluateS3Destination(resource, stackName, s3Config);
    }
    return null;
  }
}

export default new KDF002Rule();