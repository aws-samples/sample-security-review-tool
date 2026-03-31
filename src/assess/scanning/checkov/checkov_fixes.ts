interface PolicyInfo {
    policy: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'CRITICAL' | 'INFO';
    fix: string;
}

const CheckovPolicies: Record<string, PolicyInfo> = {
    // **** GENERAL POLICIES ****
    "CKV_AWS_343": {
        policy: "Amazon Redshift clusters do not have automatic snapshots enabled",
        severity: "HIGH",
        fix: "Enable automatic snapshots in AWS::Redshift::Cluster resource by setting the 'AutomatedSnapshotRetentionPeriod' property to a positive integer value (number of days to retain snapshots). Example: AutomatedSnapshotRetentionPeriod: 1. This ensures point-in-time recovery capabilities and data protection against accidental deletion or corruption."
    },
    "CKV_AWS_308": {
        policy: "API Gateway method setting is not set to encrypted caching",
        severity: "HIGH",
        fix: "Configure API Gateway method settings to use encrypted caching by setting 'CacheDataEncrypted: true' in the Settings property of AWS::ApiGateway::Stage resource. This protects sensitive data stored in the cache from unauthorized access."
    },
    "CKV_AWS_3": {
        policy: "AWS EBS volumes are not encrypted",
        severity: "HIGH",
        fix: "Enable EBS volume encryption by setting 'Encrypted: true' in the AWS::EC2::Volume resource. This ensures data at rest is protected using AWS KMS encryption, reducing risk of data exposure if volumes are accidentally exposed."
    },
    "CKV_AWS_79": {
        policy: "AWS EC2 instance not configured with Instance Metadata Service v2 (IMDSv2)",
        severity: "HIGH",
        fix: "Configure EC2 instances to use IMDSv2 by setting MetadataOptions property with 'HttpTokens: required' and 'HttpEndpoint: enabled' in AWS::EC2::Instance or AWS::EC2::LaunchTemplate resource. IMDSv2 uses session-oriented requests that provide better protection against SSRF vulnerabilities and misconfigurations compared to IMDSv1."
    },
    "CKV_AWS_99": {
        policy: "AWS Glue security configuration encryption is not enabled",
        severity: "HIGH",
        fix: "Enable encryption in AWS::Glue::SecurityConfiguration resource by configuring EncryptionConfiguration property with appropriate settings for S3Encryptions, CloudWatchEncryption, and JobBookmarksEncryption using AWS KMS keys to protect sensitive data processing workflows."
    },
    "CKV_AWS_272": {
        policy: "AWS Lambda function is not configured to validate code-signing",
        severity: "HIGH",
        fix: "Configure Lambda function code signing by creating an AWS::Lambda::CodeSigningConfig resource and associating it with the Lambda function using 'CodeSigningConfigArn' property in AWS::Lambda::Function. This ensures only trusted code signed by authorized sources can be deployed."
    },
    "CKV_AWS_103": {
        policy: "AWS Load Balancer is not using TLS 1.2",
        severity: "HIGH",
        fix: "Configure Application Load Balancer listeners to use TLS 1.2 or higher by setting appropriate 'SslPolicy' (e.g., 'ELBSecurityPolicy-TLS-1-2-2017-01') in the AWS::ElasticLoadBalancingV2::Listener resource. This ensures secure communication using modern encryption protocols."
    },
    "N/A": {
        policy: "AWS provisioned resources are manually modified",
        severity: "HIGH",
        fix: "Prevent manual modifications to AWS provisioned resources by implementing proper Infrastructure as Code practices with CloudFormation, using AWS Config rules to detect drift, enabling CloudTrail for audit logging, and establishing change management processes that require all infrastructure changes to go through CloudFormation templates and automated deployment pipelines."
    },
    "CKV_AWS_98": {
        policy: "AWS SageMaker endpoint data encryption at rest not configured",
        severity: "HIGH",
        fix: "Enable SageMaker endpoint encryption at rest by setting 'KmsKeyId' property in the AWS::SageMaker::EndpointConfig resource. Use a customer-managed KMS key to encrypt data stored by the endpoint, protecting sensitive ML model data."
    },
    "CKV_AWS_311": {
        policy: "CodeBuild S3 logs are not encrypted",
        severity: "HIGH",
        fix: "Enable CodeBuild S3 log encryption by configuring the 'LogsConfig' property in AWS::CodeBuild::Project with S3Logs settings including 'EncryptionDisabled: false' and specifying a KMS key. This protects build logs containing potentially sensitive information."
    },
    "CKV_AWS_267": {
        policy: "Comprehend Entity Recognizer's model is not encrypted by KMS using a customer managed Key (CMK)",
        severity: "HIGH",
        fix: "Configure Comprehend Entity Recognizer to use customer-managed KMS key for model encryption by setting 'ModelKmsKeyId' property in AWS::Comprehend::EntityRecognizer resource. This provides better control over encryption keys and enhanced security for ML models."
    },
    "CKV_AWS_268": {
        policy: "Comprehend Entity Recognizer's volume is not encrypted by KMS using a customer managed Key (CMK)",
        severity: "HIGH",
        fix: "Enable customer-managed KMS encryption for Comprehend Entity Recognizer volumes by setting 'VolumeKmsKeyId' property in the VpcConfig of AWS::Comprehend::EntityRecognizer resource. This encrypts temporary storage used during model training."
    },
    "CKV_AWS_295": {
        policy: "DataSync Location Object Storage exposes secrets",
        severity: "HIGH",
        fix: "Secure DataSync Object Storage location by using AWS Secrets Manager or encrypted parameters instead of hardcoding credentials. Configure the AWS::DataSync::LocationObjectStorage resource to reference secrets through SecretKey property rather than exposing them in plain text configuration."
    },
    "CKV_AWS_296": {
        policy: "DMS endpoint is not using a Customer Managed Key (CMK)",
        severity: "HIGH",
        fix: "Configure DMS endpoint to use customer-managed KMS key by setting 'KmsKeyId' property in AWS::DMS::Endpoint resource. This provides enhanced control over encryption keys and better security for database migration data."
    },
    "CKV_AWS_292": {
        policy: "DocDB Global Cluster is not encrypted at rest",
        severity: "HIGH",
        fix: "Enable DocumentDB Global Cluster encryption at rest by setting 'StorageEncrypted: true' in AWS::DocDB::DBCluster resource. Optionally specify a customer-managed KMS key using 'KmsKeyId' property for enhanced security control."
    },
    "CKV_AWS_28": {
        policy: "DynamoDB PITR is disabled",
        severity: "HIGH",
        fix: "Enable DynamoDB Point-in-Time Recovery by setting 'PointInTimeRecoveryEnabled: true' in the PointInTimeRecoverySpecification property of AWS::DynamoDB::Table resource."
    },
    "CKV_AWS_271": {
        policy: "DynamoDB table replica does not use CMK KMS encryption",
        severity: "HIGH",
        fix: "Configure DynamoDB table replicas to use customer-managed KMS keys by setting appropriate KMS key ARNs in the Replicas property of AWS::DynamoDB::GlobalTable resource. This ensures consistent encryption across all table replicas."
    },
    "CKV_AWS_163": {
        policy: "ECR image scan on push is not enabled",
        severity: "HIGH",
        fix: "Enable ECR image scanning on push by setting 'ScanOnPush: true' in the ImageScanningConfiguration property of AWS::ECR::Repository resource. This automatically scans container images for vulnerabilities when they are pushed to the repository, enhancing container security."
    },
    "CKV_AWS_329": {
        policy: "EFS Access Points are not enforcing a root directory",
        severity: "HIGH",
        fix: "Configure EFS Access Points to enforce root directory restrictions by setting 'RootDirectory' property with appropriate Path and CreationInfo in AWS::EFS::AccessPoint resource. This limits file system access to specific directories and enhances security isolation."
    },
    "CKV_AWS_97": {
        policy: "EFS volumes in ECS task definitions do not have encryption in transit enabled",
        severity: "HIGH",
        fix: "Enable EFS encryption in transit for ECS task definitions by setting 'TransitEncryption: ENABLED' in the EFSVolumeConfiguration of AWS::ECS::TaskDefinition resource. This encrypts data flowing between ECS tasks and EFS file systems."
    },
    "CKV_AWS_312": {
        policy: "Elastic Beanstalk environments do not have enhanced health reporting enabled",
        severity: "HIGH",
        fix: "Enable Elastic Beanstalk enhanced health reporting by adding OptionSettings in AWS::ElasticBeanstalk::Environment with Namespace 'aws:elasticbeanstalk:healthreporting:system' and OptionName 'SystemType' set to 'enhanced'. This provides detailed health metrics and faster failure detection."
    },
    "CKV_AWS_127": {
        policy: "Elastic load balancers do not use SSL Certificates provided by AWS Certificate Manager",
        severity: "HIGH",
        fix: "Configure ELB to use SSL certificates from AWS Certificate Manager by setting 'CertificateArn' property in the Certificates of AWS::ElasticLoadBalancingV2::Listener resource. This ensures proper SSL/TLS termination with managed certificate lifecycle."
    },
    "CKV_AWS_297": {
        policy: "EventBridge Scheduler Schedule is not using a Customer Managed Key (CMK)",
        severity: "HIGH",
        fix: "Configure EventBridge Scheduler to use customer-managed KMS key by setting 'KmsKeyArn' property in AWS::Scheduler::Schedule resource. This encrypts schedule data using keys under your control, providing enhanced security and compliance."
    },
    "CKV_AWS_94": {
        policy: "Glue Data Catalog encryption is not enabled",
        severity: "HIGH",
        fix: "Enable Glue Data Catalog encryption by configuring AWS::Glue::DataCatalogEncryptionSettings resource with EncryptionAtRest and ConnectionPasswordEncryption properties using appropriate KMS keys for both metadata and connection passwords."
    },
    "CKV_AWS_278": {
        policy: "MemoryDB snapshot is not encrypted by KMS using a customer managed Key (CMK)",
        severity: "HIGH",
        fix: "Configure MemoryDB snapshot encryption using customer-managed KMS key by setting 'KmsKeyId' property in AWS::MemoryDB::Snapshot resource. This ensures snapshot data is encrypted with keys under your control."
    },
    "CKV_AWS_102": {
        policy: "Neptune cluster instance is publicly available",
        severity: "HIGH",
        fix: "Ensure Neptune cluster instances are not publicly accessible by setting 'PubliclyAccessible: false' in AWS::Neptune::DBInstance resource. Deploy Neptune instances within a VPC with appropriate security group configurations for controlled access."
    },
    "CKV_AWS_347": {
        policy: "Neptune is not encrypted with KMS using a customer managed Key (CMK)",
        severity: "HIGH",
        fix: "Configure Neptune cluster encryption using customer-managed KMS key by setting 'KmsKeyId' and 'StorageEncrypted: true' properties in AWS::Neptune::DBCluster resource. This provides enhanced control over encryption keys for graph database data."
    },
    "CKV_AWS_280": {
        policy: "Neptune snapshot is encrypted by KMS using a customer managed Key (CMK)",
        severity: "HIGH",
        fix: "Ensure Neptune snapshots use customer-managed KMS keys for encryption. When creating snapshots from encrypted clusters, verify the snapshot inherits proper encryption settings or explicitly specify 'KmsKeyId' in AWS::Neptune::DBClusterSnapshot resource."
    },
    "CKV_AWS_279": {
        policy: "Neptune snapshot is not securely encrypted",
        severity: "HIGH",
        fix: "Enable Neptune snapshot encryption by ensuring the source cluster has 'StorageEncrypted: true' configured in AWS::Neptune::DBCluster. Snapshots automatically inherit encryption from the source cluster. For manual snapshots, verify encryption settings are properly configured."
    },
    "CKV_AWS_345": {
        policy: "Network firewall encryption does not use a CMK",
        severity: "HIGH",
        fix: "Configure Network Firewall to use customer-managed KMS key for encryption by setting 'EncryptionConfiguration' property with appropriate KeyId in AWS::NetworkFirewall::Firewall resource. This encrypts firewall configuration and logs with your managed keys."
    },
    "CKV_AWS_346": {
        policy: "Network Firewall Policy does not define an encryption configuration that uses a CMK",
        severity: "HIGH",
        fix: "Configure Network Firewall Policy with customer-managed KMS encryption by defining appropriate encryption settings in the policy configuration of AWS::NetworkFirewall::FirewallPolicy resource. Set appropriate KMS key references for encrypting policy data and associated resources."
    },
    "CKV_AWS_344": {
        policy: "Network firewalls do not have deletion protection enabled",
        severity: "HIGH",
        fix: "Enable Network Firewall deletion protection by setting 'DeleteProtection: true' property in AWS::NetworkFirewall::Firewall resource. This prevents accidental deletion of critical network security infrastructure."
    },
    "CKV_AWS_96": {
        policy: "Not all data stored in Aurora is securely encrypted at rest",
        severity: "HIGH",
        fix: "Enable Aurora cluster encryption at rest by setting 'StorageEncrypted: true' in AWS::RDS::DBCluster resource. Optionally specify 'KmsKeyId' property to use a customer-managed KMS key for enhanced control over encryption keys."
    },
    "CKV_AWS_354": {
        policy: "RDS Performance Insights are not encrypted using KMS CMKs",
        severity: "HIGH",
        fix: "Configure RDS Performance Insights encryption using customer-managed KMS key by setting 'PerformanceInsightsKMSKeyId' property in AWS::RDS::DBInstance resource when 'EnablePerformanceInsights: true'. This encrypts performance data with your managed keys."
    },
    "CKV_AWS_282": {
        policy: "Redshift Serverless namespace is not encrypted by KMS using a customer managed key (CMK)",
        severity: "HIGH",
        fix: "Configure Redshift Serverless namespace encryption using customer-managed KMS key by setting 'KmsKeyId' property in AWS::RedshiftServerless::Namespace resource. This encrypts serverless data warehouse data with keys under your control."
    },
    "CKV_AWS_281": {
        policy: "RedShift snapshot copy is not encrypted by KMS using a customer managed Key (CMK)",
        severity: "HIGH",
        fix: "Configure Redshift snapshot copy encryption using customer-managed KMS key by setting 'KmsKeyId' property in AWS::Redshift::ClusterParameterGroup and ensure the snapshot copy operation references appropriate KMS grants for proper encryption."
    },
    "CKV_AWS_304": {
        policy: "Secrets Manager secrets are not rotated within 90 days",
        severity: "HIGH",
        fix: "Configure automatic rotation for Secrets Manager secrets by setting 'RotationRules' property with 'AutomaticallyAfterDays' <= 90 in AWS::SecretsManager::Secret resource. Implement rotation Lambda function using AWS::SecretsManager::RotationSchedule to ensure regular credential updates."
    },
    "CKV_AWS_350": {
        policy: "Security configuration of the EMR Cluster does not ensure the encryption of EBS disks",
        severity: "HIGH",
        fix: "Configure EMR security configuration to encrypt EBS volumes by setting appropriate encryption settings in AWS::EMR::SecurityConfiguration resource, then reference this configuration using 'SecurityConfiguration' property in AWS::EMR::Cluster resource."
    },
    "CKV_AWS_168": {
        policy: "SQS queue policy is public and access is not restricted to specific services or principals",
        severity: "HIGH",
        fix: "Restrict SQS queue access by configuring queue policy to allow only specific principals or services. Replace wildcard principals (*) with specific AWS account IDs, service principals, or IAM roles in the PolicyDocument of AWS::SQS::QueuePolicy resource."
    },
    "CKV_AWS_337": {
        policy: "SSM parameters are not utilizing KMS CMK",
        severity: "HIGH",
        fix: "Configure SSM parameters to use customer-managed KMS keys by setting 'Type: SecureString' and 'KeyId' property to your KMS key ARN in AWS::SSM::Parameter resource. This provides enhanced control over parameter encryption keys."
    },
    "CKV_AWS_270": {
        policy: "The Connect Instance S3 Storage Configuration utilizes Customer Managed Key",
        severity: "HIGH",
        fix: "Configure Amazon Connect instance S3 storage to use customer-managed KMS key by setting 'KmsKeyId' property in the StorageConfig of AWS::Connect::Instance resource. This encrypts stored call recordings and other data with your managed keys."
    },
    "CKV_AWS_298": {
        policy: "The DMS S3 does not use a Customer Managed Key (CMK)",
        severity: "HIGH",
        fix: "Configure DMS S3 endpoint to use customer-managed KMS key by setting 'ServerSideEncryptionKmsKeyId' property in the S3Settings of AWS::DMS::Endpoint resource. This encrypts data migration files stored in S3 with keys under your control."
    },
    "CKV_AWS_357": {
        policy: "Transfer server does not force secure protocols",
        severity: "HIGH",
        fix: "Configure AWS Transfer server to enforce secure protocols by setting 'Protocols' property to only include secure options like 'SFTP' or 'FTPS', excluding insecure 'FTP' protocol in AWS::Transfer::Server resource. Enable proper security policies for secure file transfer."
    },
    "CKV_AWS_77": {
        policy: "Athena Database is not encrypted at rest",
        severity: "MEDIUM",
        fix: "Configure Athena database encryption at rest by setting 'EncryptionConfiguration' property with 'EncryptionOption' (SSE_S3, SSE_KMS, or CSE_KMS) and 'KmsKey' if using KMS encryption in AWS::Athena::DataCatalog resource. This protects query results stored in S3 from unauthorized access."
    },
    "CKV_AWS_82": {
        policy: "Athena workgroup does not prevent disabling encryption",
        severity: "MEDIUM",
        fix: "Configure Athena workgroup to enforce encryption by setting 'EnforceWorkGroupConfiguration: true' and defining encryption settings in the 'WorkGroupConfiguration' property of AWS::Athena::WorkGroup resource. This prevents users from disabling encryption for query results."
    },
    "CKV_AWS_159": {
        policy: "Athena Workgroup is not encrypted",
        severity: "MEDIUM",
        fix: "Enable Athena workgroup encryption by configuring 'ResultConfiguration' property with 'EncryptionConfiguration' specifying 'EncryptionOption' and appropriate KMS key in AWS::Athena::WorkGroup resource. This ensures all query results are encrypted at rest."
    },
    "CKV_AWS_341": {
        policy: "AWS Auto Scaling group launch configuration configured with Instance Metadata Service hop count greater than 1",
        severity: "MEDIUM",
        fix: "Configure Auto Scaling group launch template with 'HttpPutResponseHopLimit: 1' in MetadataOptions property of AWS::EC2::LaunchTemplate resource. This restricts IMDS access to the instance itself, preventing potential SSRF attacks through network intermediaries."
    },
    "CKV2_AWS_47": {
        policy: "AWS CloudFront attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability",
        severity: "MEDIUM",
        fix: "Configure CloudFront distribution's associated WAFv2 WebACL with AWS Managed Rules (AMR) that include Log4j vulnerability protection. Add appropriate managed rule groups in AWS::WAFv2::WebACL resource to detect and block Log4j exploit attempts."
    },
    "CKV_AWS_305": {
        policy: "AWS CloudFront distributions does not have a default root object configured",
        severity: "MEDIUM",
        fix: "Configure CloudFront distribution with a default root object by setting 'DefaultRootObject' property (e.g., 'index.html') in AWS::CloudFront::Distribution resource. This ensures proper handling of root path requests."
    },
    "CKV_AWS_316": {
        policy: "AWS CodeBuild project environment privileged mode is enabled",
        severity: "MEDIUM",
        fix: "Disable CodeBuild privileged mode by setting 'PrivilegedMode: false' in the Environment property of AWS::CodeBuild::Project resource unless Docker-in-Docker functionality is specifically required. This reduces the attack surface of build environments."
    },
    "CKV_AWS_293": {
        policy: "AWS database instances do not have deletion protection enabled",
        severity: "MEDIUM",
        fix: "Enable RDS instance deletion protection by setting 'DeletionProtection: true' property in AWS::RDS::DBInstance resource. This prevents accidental deletion of critical database instances through API calls or console actions."
    },
    "CKV_AWS_334": {
        policy: "AWS ECS task definition elevated privileges enabled",
        severity: "MEDIUM",
        fix: "Disable ECS container privileged mode by setting 'Privileged: false' in ContainerDefinitions of AWS::ECS::TaskDefinition resource unless elevated privileges are specifically required. This follows the principle of least privilege."
    },
    "CKV_AWS_258": {
        policy: "AWS Lambda function URL AuthType set to NONE",
        severity: "MEDIUM",
        fix: "Configure Lambda function URL with proper authentication by setting 'AuthType: AWS_IAM' in AWS::Lambda::Url resource instead of 'NONE'. This ensures only authenticated requests can invoke the function."
    },
    "CKV_AWS_81": {
        policy: "AWS MSK cluster encryption in transit is not enabled",
        severity: "MEDIUM",
        fix: "Enable MSK cluster encryption in transit by configuring 'EncryptionInfo' property with 'EncryptionInTransit' settings in AWS::MSK::Cluster resource. Set appropriate TLS encryption options for client-broker and inter-broker communication."
    },
    "CKV_AWS_250": {
        policy: "AWS RDS PostgreSQL exposed to local file read vulnerability",
        severity: "MEDIUM",
        fix: "Secure RDS PostgreSQL instances by ensuring log_fdw extension is not enabled or is properly configured with restricted access. Review and limit database extensions in AWS::RDS::DBParameterGroup that can access local files to prevent unauthorized file system access."
    },
    "CKV_AWS_302": {
        policy: "AWS RDS snapshots are accessible to public",
        severity: "MEDIUM",
        fix: "Ensure RDS snapshots are private by not setting public access parameters in AWS::RDS::DBSnapshot resource. Review snapshot sharing settings to ensure they're only shared with authorized accounts using specific AWS account IDs."
    },
    "CKV_AWS_371": {
        policy: "AWS SageMaker Notebook Instance allows for IMDSv1",
        severity: "MEDIUM",
        fix: "Configure SageMaker notebook instance to use IMDSv2 by ensuring the underlying instance is configured with appropriate metadata service settings. Set InstanceMetadataServiceConfiguration properties for enhanced security."
    },
    "CKV_AWS_26": {
        policy: "AWS SNS topic has SSE disabled",
        severity: "MEDIUM",
        fix: "Enable SNS topic server-side encryption by setting 'KmsMasterKeyId' property in AWS::SNS::Topic resource. Use either AWS managed keys or customer-managed KMS keys to encrypt messages at rest."
    },
    "CKV_AWS_303": {
        policy: "AWS SSM documents are public",
        severity: "MEDIUM",
        fix: "Restrict SSM document access by setting 'DocumentType' and 'Permissions' properties appropriately in AWS::SSM::Document resource. Ensure documents are not publicly accessible unless specifically required for your use case."
    },
    "CKV_AWS_166": {
        policy: "Backup Vault is not encrypted at rest using KMS CMK",
        severity: "MEDIUM",
        fix: "Configure AWS Backup vault encryption using customer-managed KMS key by setting 'EncryptionKeyArn' property in AWS::Backup::BackupVault resource. This ensures backup data is encrypted with keys under your control."
    },
    "CKV_AWS_373": {
        policy: "Bedrock Agent not encrypted with Customer Master Key (CMK)",
        severity: "MEDIUM",
        fix: "Configure Bedrock Agent encryption using customer-managed KMS key by setting appropriate KMS key references in AWS::Bedrock::Agent resource. This ensures AI agent data is encrypted with keys under your control."
    },
    "CKV_AWS_310": {
        policy: "CloudFront distributions do not have origin failover configured",
        severity: "MEDIUM",
        fix: "Configure CloudFront distribution with origin failover by setting up 'OriginGroups' with primary and failover origins in AWS::CloudFront::Distribution resource. This ensures high availability and automatic failover capabilities."
    },
    "CKV_AWS_319": {
        policy: "CloudWatch alarm actions are not enabled",
        severity: "MEDIUM",
        fix: "Enable CloudWatch alarm actions by configuring 'AlarmActions', 'OKActions', and 'InsufficientDataActions' properties in AWS::CloudWatch::Alarm resource. This ensures automated responses to alarm state changes for proper incident management."
    },
    "CKV_AWS_78": {
        policy: "CodeBuild project encryption is disabled",
        severity: "MEDIUM",
        fix: "Enable CodeBuild project encryption by setting 'EncryptionKey' property in the Artifacts configuration of AWS::CodeBuild::Project resource. This encrypts build artifacts stored in S3 with specified KMS key for enhanced security."
    },
    "CKV_AWS_147": {
        policy: "CodeBuild projects are not encrypted",
        severity: "MEDIUM",
        fix: "Configure CodeBuild project encryption by enabling encryption for artifacts, cache, and logs. Set appropriate KMS keys in LogsConfig and Artifacts properties of AWS::CodeBuild::Project resource."
    },
    "CKV_AWS_269": {
        policy: "Connect Instance Kinesis Video Stream Storage Config is not using CMK for encryption",
        severity: "MEDIUM",
        fix: "Configure Amazon Connect instance Kinesis Video Stream storage to use customer-managed KMS key by setting appropriate encryption configuration in the InstanceStorageConfig of AWS::Connect::Instance resource. This ensures video call recordings are encrypted with keys under your control."
    },
    "CKV_AWS_113": {
        policy: "Session Manager data is not encrypted in transit / Deletion protection disabled for load balancer",
        severity: "MEDIUM",
        fix: "For Session Manager: Enable encryption in transit by configuring appropriate encryption settings in AWS::SSM::Document for Session Manager preferences. For Load Balancer: Enable deletion protection by setting 'DeletionProtection: true' in AWS::ElasticLoadBalancingV2::LoadBalancer resource."
    },
    "CKV_AWS_74": {
        policy: "DocumentDB is not encrypted at rest",
        severity: "MEDIUM",
        fix: "Enable DocumentDB cluster encryption at rest by setting 'StorageEncrypted: true' in AWS::DocDB::DBCluster resource. Optionally specify 'KmsKeyId' property to use customer-managed KMS key for enhanced control."
    },
    "CKV_AWS_165": {
        policy: "Dynamodb point in time recovery is not enabled for global tables",
        severity: "MEDIUM",
        fix: "Enable Point-in-Time Recovery for DynamoDB global tables by setting 'PointInTimeRecoveryEnabled: true' in the PointInTimeRecoverySpecification of AWS::DynamoDB::GlobalTable resource for all regions where the global table exists."
    },
    "CKV_AWS_315": {
        policy: "EC2 Auto Scaling groups are not utilizing EC2 launch templates",
        severity: "MEDIUM",
        fix: "Configure Auto Scaling groups to use launch templates instead of launch configurations by setting 'LaunchTemplate' property in AWS::AutoScaling::AutoScalingGroup resource. Launch templates provide more features and better versioning capabilities."
    },
    "CKV_AWS_332": {
        policy: "ECS Fargate services are not ensured to run on the latest Fargate platform version",
        severity: "MEDIUM",
        fix: "Configure ECS Fargate services to use latest platform version by setting 'PlatformVersion: LATEST' or specifying the most recent platform version in AWS::ECS::Service resource for enhanced security and features."
    },
    "CKV_AWS_335": {
        policy: "ECS task definitions have their own unique process namespace or share the host's process namespace",
        severity: "MEDIUM",
        fix: "Configure ECS task definitions with proper process namespace isolation by setting 'PidMode' property appropriately in AWS::ECS::TaskDefinition. Avoid 'host' mode unless specifically required, and ensure proper container isolation."
    },
    "CKV_AWS_318": {
        policy: "Elasticsearch domains are not configured with a minimum of three dedicated master nodes",
        severity: "MEDIUM",
        fix: "Configure Elasticsearch domain with dedicated master nodes by setting 'DedicatedMasterEnabled: true' and 'DedicatedMasterCount' >= 3 in ElasticsearchClusterConfig of AWS::Elasticsearch::Domain resource for high availability."
    },
    "CKV_AWS_167": {
        policy: "Glacier Vault access policy is public and not restricted to specific services or principals",
        severity: "MEDIUM",
        fix: "Restrict Glacier vault access by configuring vault access policy to allow only specific principals instead of wildcard (*) access. Use appropriate AccessPolicy in AWS::Glacier::Vault resource with properly scoped permissions."
    },
    "CKV_AWS_384": {
        policy: "Hard-coded secrets found in Parameter Store values",
        severity: "MEDIUM",
        fix: "Remove hard-coded secrets from Parameter Store values and use proper secret management. Reference secrets from AWS Secrets Manager or use dynamic parameter generation in AWS::SSM::Parameter resource. Avoid storing plaintext secrets in CloudFormation templates."
    },
    "CKV_AWS_44": {
        policy: "Neptune storage is not securely encrypted",
        severity: "MEDIUM",
        fix: "Enable Neptune cluster storage encryption by setting 'StorageEncrypted: true' in AWS::Neptune::DBCluster resource. This encrypts the underlying storage volumes protecting data at rest."
    },
    "CKV_AWS_CUSTOM_3": {
        policy: "Not all data stored in the EBS snapshot is securely encrypted",
        severity: "MEDIUM",
        fix: "Ensure EBS snapshots are encrypted by creating snapshots from encrypted EBS volumes or by encrypting existing snapshots. Set 'Encrypted: true' when creating AWS::EC2::Snapshot resource or copy unencrypted snapshots with encryption enabled."
    },
    "CKV_AWS_170": {
        policy: "QLDB ledger permissions mode is not set to STANDARD",
        severity: "MEDIUM",
        fix: "Configure QLDB ledger with STANDARD permissions mode by setting 'PermissionsMode: STANDARD' in AWS::QLDB::Ledger resource. This provides proper access control and follows security best practices."
    },
    "CKV_AWS_326": {
        policy: "RDS Aurora Clusters do not have backtracking enabled",
        severity: "MEDIUM",
        fix: "Enable Aurora cluster backtracking by setting 'BacktrackWindow' property to a value greater than 0 (up to 259200 seconds/72 hours) in AWS::RDS::DBCluster resource. This allows point-in-time recovery without using snapshots."
    },
    "CKV_AWS_321": {
        policy: "Redshift clusters are not using enhanced VPC routing",
        severity: "MEDIUM",
        fix: "Enable Redshift enhanced VPC routing by setting 'EnhancedVpcRouting: true' in AWS::Redshift::Cluster resource. This forces all traffic between cluster and data repositories through your VPC for better network control."
    },
    "CKV_AWS_320": {
        policy: "Redshift clusters are not using the default database name",
        severity: "MEDIUM",
        fix: "Configure Redshift cluster with explicit database name by setting 'DBName' property in AWS::Redshift::Cluster resource instead of relying on defaults. This provides better clarity and intentional configuration."
    },
    "CKV2_AWS_23": {
        policy: "Route53 A Record does not have Attached Resource",
        severity: "MEDIUM",
        fix: "Ensure Route53 A records point to valid AWS resources by configuring proper 'AliasTarget' or valid IP addresses in AWS::Route53::RecordSet resource. Avoid creating orphaned DNS records that don't resolve to actual resources."
    },
    "CKV_AWS_363": {
        policy: "Runtime of Lambda is deprecated",
        severity: "MEDIUM",
        fix: "Update Lambda function runtime to a supported version by changing 'Runtime' property in AWS::Lambda::Function resource to a current runtime (e.g., python3.9, nodejs18.x, java17, etc.). Deprecated runtimes pose security risks."
    },
    "CKV_AWS_300": {
        policy: "S3 lifecycle configuration does not set a period for aborting failed uploads",
        severity: "MEDIUM",
        fix: "Configure S3 bucket lifecycle to abort incomplete multipart uploads by adding 'AbortIncompleteMultipartUpload' rule in AWS::S3::Bucket LifecycleConfiguration. This prevents storage costs from failed uploads."
    },
    "CKV_AWS_112": {
        policy: "Session Manager data is not encrypted in transit",
        severity: "MEDIUM",
        fix: "Enable Session Manager encryption in transit by configuring appropriate encryption settings with proper KMS key settings in AWS::SSM::Document resource for Session Manager logging preferences."
    },
    "CKV_AWS_169": {
        policy: "SNS topic policy is public and access is not restricted to specific services or principals",
        severity: "MEDIUM",
        fix: "Restrict SNS topic access by configuring topic policy to allow only specific principals instead of wildcard (*) access. Use appropriate PolicyDocument in AWS::SNS::TopicPolicy resource with properly scoped permissions for authorized entities only."
    },
    "CKV_AWS_160": {
        policy: "Timestream database is not encrypted with KMS CMK",
        severity: "MEDIUM",
        fix: "Configure Timestream database encryption using customer-managed KMS key by setting 'KmsKeyId' property in AWS::Timestream::Database resource. This provides enhanced control over encryption keys for time-series data."
    },
    "CKV_AWS_330": {
        policy: "User identity should be enforced by EFS access points",
        severity: "MEDIUM",
        fix: "Configure EFS access points to enforce user identity by setting 'PosixUser' property with specific Uid and Gid in AWS::EFS::AccessPoint resource. This ensures consistent user identity enforcement across EFS access."
    },
    "CKV_AWS_156": {
        policy: "Workspace root volumes are not encrypted",
        severity: "MEDIUM",
        fix: "Enable WorkSpace root volume encryption by setting 'RootVolumeEncryptionEnabled: true' in AWS::WorkSpaces::Workspace resource. This encrypts the operating system and installed applications data."
    },
    "CKV_AWS_155": {
        policy: "Workspace user volumes are not encrypted",
        severity: "MEDIUM",
        fix: "Enable WorkSpace user volume encryption by setting 'UserVolumeEncryptionEnabled: true' in AWS::WorkSpaces::Workspace resource. This encrypts user data and documents stored on the workspace."
    },
    "CKV_ALI_41": {
        policy: "Alibaba Cloud MongoDB is not deployed inside a VPC",
        severity: "LOW",
        fix: "Deploy MongoDB instance inside a VPC by setting the 'VpcId' property in AWS::DocDB::DBCluster or ensure proper network isolation. Configure the DBSubnetGroupName to reference a subnet group within your VPC to protect your database from unauthorized access."
    },
    "CKV2_AWS_18": {
        policy: "Amazon EFS does not have an AWS Backup backup plan",
        severity: "LOW",
        fix: "Create an AWS Backup plan and associate it with your EFS file system using AWS::Backup::BackupPlan and AWS::Backup::BackupSelection resources. Configure backup frequency, retention period, and lifecycle policies to ensure data protection and recovery capabilities."
    },
    "CKV_AWS_153": {
        policy: "Autoscaling groups did not supply tags to launch configurations",
        severity: "LOW",
        fix: "Configure tag propagation in AWS::AutoScaling::AutoScalingGroup by setting 'PropagateAtLaunch: true' in the Tags property. This enables tag-based access control through IAM policies and helps with resource organization and management."
    },
    "CKV_AWS_234": {
        policy: "AWS ACM certificates does not have logging preference",
        severity: "LOW",
        fix: "Enable certificate transparency logging in AWS::CertificateManager::Certificate by setting 'CertificateTransparencyLoggingPreference: ENABLED' in the Options property. This ensures certificates are recorded in public transparency logs for security monitoring."
    },
    "CKV_AWS_247": {
        policy: "AWS all data stored in the Elasticsearch domain is not encrypted using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::Elasticsearch::Domain with customer-managed KMS encryption by setting 'KMSKeyId' property in the EncryptionAtRestOptions. Reference an AWS::KMS::Key resource to maintain full control over encryption keys and data access."
    },
    "CKV_AWS_236": {
        policy: "AWS AMI copying does not use a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "When copying AMIs, specify a customer-managed KMS key in the copy operation. Use the 'KmsKeyId' parameter when calling CopyImage API or configure AMI copying tools to use customer-managed keys instead of default AWS-managed keys for enhanced security control."
    },
    "CKV_AWS_205": {
        policy: "AWS AMI launch permissions are not limited",
        severity: "LOW",
        fix: "Restrict AMI launch permissions by removing overly permissive launch permissions. Use AWS::EC2::AMI resource with limited LaunchPermissions or remove aws_ami_launch_permission resources that grant broad access to prevent unauthorized AMI usage across accounts."
    },
    "CKV_AWS_204": {
        policy: "AWS AMIs are not encrypted by Key Management Service (KMS) using Customer Managed Keys (CMKs)",
        severity: "LOW",
        fix: "Ensure AMI block devices are encrypted with customer-managed KMS keys in AWS::EC2::Instance or AWS::ImageBuilder::ImageRecipe. Set 'Encrypted: true' and 'KmsKeyId' properties in EBS block device mappings to use customer-managed keys instead of default encryption."
    },
    "CKV_AWS_217": {
        policy: "AWS API deployments do not enable Create before Destroy",
        severity: "LOW",
        fix: "Configure AWS::ApiGateway::Deployment with create-before-destroy lifecycle management. While CloudFormation handles this automatically, ensure deployment recreation doesn't cause service interruption by properly managing stage dependencies and deployment timing."
    },
    "CKV_AWS_120": {
        policy: "AWS API Gateway caching is disabled",
        severity: "LOW",
        fix: "Enable API Gateway caching in AWS::ApiGateway::Stage by setting 'CacheClusterEnabled: true' and configuring appropriate 'CacheClusterSize'. This improves API performance, reduces backend load, and can lower costs by serving cached responses."
    },
    "CKV_AWS_206": {
        policy: "AWS API Gateway Domain does not use a modern security policy",
        severity: "LOW",
        fix: "Configure AWS::ApiGateway::DomainName with a modern TLS security policy by setting 'SecurityPolicy' to 'TLS_1_2' or higher. This ensures secure communication and prevents use of vulnerable older TLS versions that expose security risks."
    },
    "CKV2_AWS_51": {
        policy: "AWS API Gateway endpoints without client certificate authentication",
        severity: "LOW",
        fix: "Enable client certificate authentication in AWS::ApiGateway::Stage by setting 'ClientCertificateId' property. Create an AWS::ApiGateway::ClientCertificate resource and reference it to provide additional authentication layer and enhanced security for API access."
    },
    "CKV_AWS_225": {
        policy: "AWS API Gateway method settings do not enable caching",
        severity: "LOW",
        fix: "Configure caching in AWS::ApiGateway::MethodSettings by setting 'CachingEnabled: true' and 'CacheDataEncrypted: true'. Specify appropriate TTL values and cache key parameters to improve API performance while ensuring cached data is encrypted."
    },
    "CKV2_AWS_53": {
        policy: "AWS API gateway request parameter is not validated",
        severity: "LOW",
        fix: "Enable request validation in AWS::ApiGateway::Method by setting 'RequestValidatorId' property. Create an AWS::ApiGateway::RequestValidator resource to validate request parameters and body, preventing malformed requests from reaching your backend."
    },
    "CKV_AWS_264": {
        policy: "AWS App Flow connector profile does not use Customer Managed Keys (CMKs)",
        severity: "LOW",
        fix: "Configure AWS::AppFlow::ConnectorProfile with customer-managed KMS encryption by setting 'KMSArn' property to reference an AWS::KMS::Key resource. This provides full control over encryption keys used for data in transit and at rest."
    },
    "CKV_AWS_263": {
        policy: "AWS App Flow flow does not use Customer Managed Keys (CMKs)",
        severity: "LOW",
        fix: "Configure AWS::AppFlow::Flow with customer-managed KMS encryption by setting 'KMSArn' property to reference an AWS::KMS::Key resource. This ensures all data processed by the flow is encrypted using keys under your control."
    },
    "CKV_AWS_214": {
        policy: "AWS Appsync API Cache is not encrypted at rest",
        severity: "LOW",
        fix: "Enable at-rest encryption for AWS::AppSync::ApiCache by setting 'AtRestEncryptionEnabled: true'. This protects cached GraphQL query results and resolver data using AWS KMS encryption when stored in the cache layer."
    },
    "CKV_AWS_215": {
        policy: "AWS Appsync API Cache is not encrypted in transit",
        severity: "LOW",
        fix: "Enable in-transit encryption for AWS::AppSync::ApiCache by setting 'TransitEncryptionEnabled: true'. This ensures all communication between AppSync and the cache layer is encrypted using TLS to protect data during transmission."
    },
    "CKV2_AWS_33": {
        policy: "AWS AppSync is not protected by WAF",
        severity: "LOW",
        fix: "Associate AWS::AppSync::GraphQLApi with AWS::WAFv2::WebACL using AWS::WAFv2::WebACLAssociation resource. Configure the WebACL with appropriate rules to protect against common web attacks, DDoS, and malicious requests to your GraphQL API."
    },
    "CKV_AWS_193": {
        policy: "AWS AppSync's logging is disabled",
        severity: "LOW",
        fix: "Enable logging for AWS::AppSync::GraphQLApi by configuring the LogConfig property with 'CloudWatchLogsRoleArn' and 'FieldLogLevel'. Create an IAM role with CloudWatch Logs permissions to capture API activity for monitoring and troubleshooting."
    },
    "CKV_AWS_210": {
        policy: "AWS Batch Job is defined as a privileged container",
        severity: "LOW",
        fix: "Configure AWS::Batch::JobDefinition container properties to set 'privileged: false' in the ContainerProperties. Remove unnecessary privileged access to reduce security risks and follow principle of least privilege for batch job containers."
    },
    "CKV_AWS_383": {
        policy: "AWS Bedrock agent is not associated with Bedrock guardrails",
        severity: "LOW",
        fix: "Associate AWS::Bedrock::Agent with guardrails by configuring GuardrailConfiguration property with a valid GuardrailIdentifier. This ensures responsible AI usage and prevents harmful or inappropriate content generation."
    },
    "CKV_AWS_216": {
        policy: "AWS Cloudfront distribution is disabled",
        severity: "LOW",
        fix: "Enable AWS::CloudFront::Distribution by setting 'Enabled: true' in the DistributionConfig. Ensure the distribution is actively serving content and not incurring unnecessary costs while remaining disabled."
    },
    "CKV_AWS_259": {
        policy: "AWS CloudFront response header policy does not enforce Strict Transport Security",
        severity: "LOW",
        fix: "Configure AWS::CloudFront::ResponseHeadersPolicy with Strict Transport Security by setting 'StrictTransportSecurity' in SecurityHeadersConfig. Include 'AccessControlMaxAgeSec', 'IncludeSubdomains: true', and 'Override: true' to enforce HTTPS-only communication."
    },
    "CKV_AWS_220": {
        policy: "AWS Cloudsearch does not use HTTPs",
        severity: "LOW",
        fix: "Configure AWS::CloudSearch::Domain to enforce HTTPS by setting 'EnforceHTTPS: true' in the DomainEndpointOptions. This encrypts all search requests and responses, protecting data in transit from interception."
    },
    "CKV_AWS_218": {
        policy: "AWS Cloudsearch does not use the latest (Transport Layer Security) TLS",
        severity: "LOW",
        fix: "Configure AWS::CloudSearch::Domain with modern TLS policy by setting 'TLSSecurityPolicy' to 'Policy-Min-TLS-1-2-2019-07' or later in DomainEndpointOptions. This ensures secure communication using modern encryption standards."
    },
    "CKV_AWS_252": {
        policy: "AWS CloudTrail does not define an SNS Topic",
        severity: "LOW",
        fix: "Configure AWS::CloudTrail::Trail with 'SnsTopicName' property referencing an AWS::SNS::Topic resource. This enables real-time notifications for CloudTrail events, improving monitoring and incident response capabilities."
    },
    "CKV_AWS_158": {
        policy: "AWS CloudWatch Log groups encrypted using default encryption key instead of KMS CMK",
        severity: "LOW",
        fix: "Configure AWS::Logs::LogGroup with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This provides full control over log encryption and access management."
    },
    "CKV_AWS_224": {
        policy: "AWS cluster logging is not enabled or client to container communication not encrypted using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::ECS::Cluster with encrypted logging by setting ExecuteCommandConfiguration with 'KmsKeyId' property referencing a customer-managed KMS key. Enable LogConfiguration with encrypted CloudWatch logs or S3 bucket encryption."
    },
    "CKV_AWS_221": {
        policy: "AWS Code Artifact Domain is not encrypted by KMS using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::CodeArtifact::Domain with customer-managed KMS encryption by setting 'EncryptionKey' property to reference an AWS::KMS::Key resource. This ensures all artifacts and metadata are encrypted using keys under your control."
    },
    "CKV_AWS_257": {
        policy: "AWS Codecommit branch changes has less than 2 approvals",
        severity: "LOW",
        fix: "Configure AWS::CodeCommit::Repository with approval rule template requiring minimum 2 approvals. Create an approval rule with 'NumberOfApprovalsNeeded: 2' in the rule content to enforce code review standards and improve code quality."
    },
    "CKV2_AWS_37": {
        policy: "AWS Codecommit is not associated with an approval rule",
        severity: "LOW",
        fix: "Associate AWS::CodeCommit::Repository with approval rules by creating AWS::CodeCommit::ApprovalRuleTemplate and linking it to the repository. This enforces code review processes and ensures changes meet quality standards before merging."
    },
    "CKV_AWS_381": {
        policy: "AWS CodeGuru Reviewer repository association does not use a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::CodeGuruReviewer::RepositoryAssociation with customer-managed KMS encryption by setting appropriate KMS key properties. This ensures code analysis results and associated data are encrypted using keys under your control."
    },
    "CKV_AWS_219": {
        policy: "AWS CodePipeline artifactStore is not encrypted by Key Management Service (KMS) using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::CodePipeline::Pipeline ArtifactStore with customer-managed KMS encryption by setting 'EncryptionKey' with 'Id' and 'Type: KMS' properties. Reference an AWS::KMS::Key resource to encrypt pipeline artifacts using customer-managed keys."
    },
    "CKV_AWS_235": {
        policy: "AWS copied AMIs are not encrypted",
        severity: "LOW",
        fix: "Ensure AMI copies are encrypted by setting 'Encrypted: true' when using CopyImage API or AMI copying operations. Configure KmsKeyId parameter to use customer-managed keys for enhanced security control over copied AMI encryption."
    },
    "CKV_AWS_239": {
        policy: "AWS DAX cluster endpoint does not use TLS (Transport Layer Security)",
        severity: "LOW",
        fix: "Configure AWS::DAX::Cluster to use TLS encryption by setting 'SSESpecification' with 'SSEEnabled: true' and appropriate encryption settings. This ensures all client-to-cluster communication is encrypted using TLS protocols."
    },
    "CKV_AWS_226": {
        policy: "AWS DB instance does not get all minor upgrades automatically",
        severity: "LOW",
        fix: "Enable automatic minor version upgrades in AWS::RDS::DBInstance by setting 'AutoMinorVersionUpgrade: true'. This ensures the database receives security patches and bug fixes automatically during maintenance windows."
    },
    "CKV_AWS_253": {
        policy: "AWS DLM cross-region events are not encrypted",
        severity: "LOW",
        fix: "Configure AWS::DLM::LifecyclePolicy with cross-region encryption by setting 'Encrypted: true' in the CrossRegionCopyRule. This ensures snapshot copies to other regions are encrypted for data protection during replication."
    },
    "CKV_AWS_254": {
        policy: "AWS DLM cross-region events are not encrypted with a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::DLM::LifecyclePolicy CrossRegionCopyRule with customer-managed KMS encryption by setting 'CmkArn' property to reference an AWS::KMS::Key resource. This provides full control over encryption keys used for cross-region snapshot copies."
    },
    "CKV_AWS_256": {
        policy: "AWS DLM cross-region schedules are not encrypted using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::DLM::LifecyclePolicy schedule with customer-managed KMS encryption by setting 'CmkArn' in CrossRegionCopyRule. Reference an AWS::KMS::Key resource to ensure snapshot scheduling data is encrypted using customer-controlled keys."
    },
    "CKV_AWS_255": {
        policy: "AWS DLM-cross region schedules are not encrypted",
        severity: "LOW",
        fix: "Enable encryption for AWS::DLM::LifecyclePolicy cross-region schedules by setting 'Encrypted: true' in the CrossRegionCopyRule. This protects scheduled snapshot operations and associated metadata during cross-region replication."
    },
    "CKV_AWS_222": {
        policy: "AWS DMS replication instance automatic version upgrade disabled",
        severity: "LOW",
        fix: "Enable automatic minor version upgrades in AWS::DMS::ReplicationInstance by setting 'AutoMinorVersionUpgrade: true'. This ensures the replication instance receives security patches and bug fixes automatically."
    },
    "CKV_AWS_182": {
        policy: "AWS Doc DB not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::DocDB::DBCluster with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This provides full control over database encryption keys and access management."
    },
    "CKV_AWS_360": {
        policy: "AWS DocumentDB clusters have backup retention period less than 7 days",
        severity: "LOW",
        fix: "Configure AWS::DocDB::DBCluster with adequate backup retention by setting 'BackupRetentionPeriod' to 7 or higher (up to 35 days). This ensures sufficient point-in-time recovery capabilities for data protection and compliance requirements."
    },
    "CKV_AWS_183": {
        policy: "AWS EBS Snapshot Copy not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Ensure EBS snapshot copies use customer-managed KMS encryption by specifying 'KmsKeyId' parameter when copying snapshots. Reference an AWS::KMS::Key resource to maintain control over encryption keys used for snapshot copies."
    },
    "CKV_AWS_212": {
        policy: "AWS EBS Volume is not encrypted by Key Management Service (KMS) using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::EC2::Volume with customer-managed KMS encryption by setting 'Encrypted: true' and 'KmsKeyId' property to reference an AWS::KMS::Key resource. This ensures EBS volumes use customer-controlled encryption keys."
    },
    "CKV_AWS_189": {
        policy: "AWS EBS Volume not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::EC2::Volume with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource instead of using default AWS-managed keys. This provides enhanced control over data encryption."
    },
    "CKV_AWS_106": {
        policy: "AWS EBS volume region with encryption is disabled",
        severity: "LOW",
        fix: "Enable EBS default encryption for the region using AWS CLI or console. Configure the account to encrypt all new EBS volumes by default using 'aws ec2 enable-ebs-encryption-by-default' or enable it in the EC2 console settings."
    },
    "CKV_AWS_223": {
        policy: "AWS ECS Cluster does not enable logging of ECS Exec",
        severity: "LOW",
        fix: "Configure AWS::ECS::Cluster with ECS Exec logging by setting ExecuteCommandConfiguration with LogConfiguration. Specify CloudWatch log group or S3 bucket for audit trail of execute command sessions for security monitoring."
    },
    "CKV_AWS_184": {
        policy: "AWS Elastic File System (EFS) is not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::EFS::FileSystem with customer-managed KMS encryption by setting 'KmsKeyId' property in EncryptionConfiguration to reference an AWS::KMS::Key resource. This provides full control over file system encryption keys."
    },
    "CKV_AWS_42": {
        policy: "AWS Elastic File System (EFS) with encryption for data at rest is disabled",
        severity: "LOW",
        fix: "Enable encryption at rest for AWS::EFS::FileSystem by setting 'Encrypted: true' in the EncryptionConfiguration property. This protects stored file data using AWS KMS encryption to prevent unauthorized access."
    },
    "CKV_AWS_150": {
        policy: "AWS Elastic Load Balancer v2 with deletion protection feature disabled",
        severity: "LOW",
        fix: "Enable deletion protection for AWS::ElasticLoadBalancingV2::LoadBalancer by setting 'DeletionProtection: true' in the LoadBalancerAttributes. This prevents accidental deletion of critical load balancers."
    },
    "CKV_AWS_29": {
        policy: "AWS ElastiCache Redis cluster with encryption for data at rest disabled",
        severity: "LOW",
        fix: "Enable at-rest encryption for AWS::ElastiCache::ReplicationGroup by setting 'AtRestEncryptionEnabled: true'. This protects cached data using AWS KMS encryption when stored on disk."
    },
    "CKV_AWS_30": {
        policy: "AWS ElastiCache Redis cluster with in-transit encryption disabled (Replication group)",
        severity: "LOW",
        fix: "Enable in-transit encryption for AWS::ElastiCache::ReplicationGroup by setting 'TransitEncryptionEnabled: true'. This encrypts all communication between clients and the Redis cluster using TLS."
    },
    "CKV_AWS_31": {
        policy: "AWS ElastiCache Redis cluster with Redis AUTH feature disabled",
        severity: "LOW",
        fix: "Enable Redis AUTH for AWS::ElastiCache::ReplicationGroup by setting 'AuthToken' property with a secure token. This requires clients to authenticate before accessing the Redis cluster, enhancing access control."
    },
    "CKV_AWS_191": {
        policy: "AWS Elasticache replication group not configured with CMK key",
        severity: "LOW",
        fix: "Configure AWS::ElastiCache::ReplicationGroup with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource for both at-rest and in-transit encryption configurations."
    },
    "CKV_AWS_228": {
        policy: "AWS Elasticsearch domain does not use an updated TLS policy",
        severity: "LOW",
        fix: "Configure AWS::Elasticsearch::Domain with modern TLS policy by setting 'TLSSecurityPolicy' to 'Policy-Min-TLS-1-2-2019-07' or later in DomainEndpointOptions. This ensures secure communication using current encryption standards."
    },
    "CKV2_AWS_59": {
        policy: "AWS Elasticsearch domain has Dedicated master set to disabled",
        severity: "LOW",
        fix: "Enable dedicated master nodes for AWS::Elasticsearch::Domain by setting 'DedicatedMasterEnabled: true' and 'DedicatedMasterCount: 3' (minimum) in ElasticsearchClusterConfig. This improves cluster stability and performance."
    },
    "CKV_AWS_114": {
        policy: "AWS EMR cluster is not configured with Kerberos Authentication",
        severity: "LOW",
        fix: "Configure AWS::EMR::Cluster with Kerberos authentication by setting KerberosAttributes in the cluster configuration. Include 'Realm', 'KdcAdminPassword', and appropriate Kerberos settings to enhance cluster security."
    },
    "CKV_AWS_171": {
        policy: "AWS EMR cluster is not configured with SSE KMS for data at rest encryption (Amazon S3 with EMRFS)",
        severity: "LOW",
        fix: "Configure AWS::EMR::SecurityConfiguration with S3 encryption using SSE-KMS. Set EncryptionConfiguration for S3 with 'EncryptionMode: SSE-KMS' and specify a KMS key to encrypt data stored in S3 through EMRFS."
    },
    "CKV_AWS_351": {
        policy: "AWS EMR cluster is not enabled with data encryption in transit",
        severity: "LOW",
        fix: "Configure AWS::EMR::SecurityConfiguration with in-transit encryption by setting EncryptionConfiguration with 'EnableInTransitEncryption: true'. This encrypts data movement between EMR cluster nodes and services."
    },
    "CKV_AWS_349": {
        policy: "AWS EMR cluster is not enabled with local disk encryption",
        severity: "LOW",
        fix: "Configure AWS::EMR::SecurityConfiguration with local disk encryption by setting EncryptionConfiguration with 'EnableAtRestEncryption: true' for LocalDiskEncryptionConfiguration. This encrypts data stored on cluster instance local disks."
    },
    "CKV_AWS_203": {
        policy: "AWS FSX openzfs is not encrypted by AWS' Key Management Service (KMS) using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::FSx::FileSystem (OpenZFS) with customer-managed KMS encryption by setting 'KmsKeyId' property in the OpenZFSConfiguration to reference an AWS::KMS::Key resource. This provides control over file system encryption keys."
    },
    "CKV_AWS_179": {
        policy: "AWS FSX Windows filesystem not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::FSx::FileSystem (Windows) with customer-managed KMS encryption by setting 'KmsKeyId' property in WindowsConfiguration to reference an AWS::KMS::Key resource. This ensures Windows file system data is encrypted with customer-controlled keys."
    },
    "CKV_AWS_178": {
        policy: "AWS fx ontap file system not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::FSx::FileSystem (ONTAP) with customer-managed KMS encryption by setting 'KmsKeyId' property in OntapConfiguration to reference an AWS::KMS::Key resource. This provides control over NetApp ONTAP file system encryption."
    },
    "CKV_AWS_195": {
        policy: "AWS Glue component is not associated with a security configuration",
        severity: "LOW",
        fix: "Associate AWS::Glue::Job, AWS::Glue::Crawler, or AWS::Glue::DevEndpoint with a security configuration by setting 'SecurityConfiguration' property to reference an AWS::Glue::SecurityConfiguration resource for encryption and security settings."
    },
    "CKV_AWS_261": {
        policy: "AWS HTTP and HTTPS target groups do not define health check",
        severity: "LOW",
        fix: "Configure health checks for AWS::ElasticLoadBalancingV2::TargetGroup by setting HealthCheckProtocol, HealthCheckPath, HealthCheckIntervalSeconds, HealthCheckTimeoutSeconds, and HealthyThresholdCount properties to ensure target health monitoring."
    },
    "CKV_AWS_180": {
        policy: "AWS Image Builder component not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::ImageBuilder::Component with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This ensures component artifacts and build processes use customer-controlled encryption."
    },
    "CKV_AWS_199": {
        policy: "AWS Image Builder Distribution Configuration is not encrypting AMI by Key Management Service (KMS) using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::ImageBuilder::DistributionConfiguration AmiDistributionConfiguration with customer-managed KMS encryption by setting 'KmsKeyId' in AmiDistributionConfiguration to reference an AWS::KMS::Key resource."
    },
    "CKV_AWS_200": {
        policy: "AWS Image Recipe EBS Disk are not encrypted using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::ImageBuilder::ImageRecipe BlockDeviceMappings with customer-managed KMS encryption by setting 'KmsKeyId' property in Ebs configuration to reference an AWS::KMS::Key resource for encrypted EBS volumes."
    },
    "CKV_AWS_262": {
        policy: "AWS Kendra index Server side encryption does not use Customer Managed Keys (CMKs)",
        severity: "LOW",
        fix: "Configure AWS::Kendra::Index with customer-managed KMS encryption by setting 'ServerSideEncryptionConfiguration' with 'KmsKeyId' property referencing an AWS::KMS::Key resource. This ensures search index data is encrypted with customer-controlled keys."
    },
    "CKV_AWS_227": {
        policy: "AWS Key Management Service (KMS) key is disabled",
        severity: "LOW",
        fix: "Enable AWS::KMS::Key by setting 'Enabled: true' in the key properties or ensure the key is not disabled. Verify key status and re-enable if necessary to maintain encryption capabilities for dependent services."
    },
    "CKV_AWS_265": {
        policy: "AWS Keyspace Table does not use Customer Managed Keys (CMKs)",
        severity: "LOW",
        fix: "Configure AWS::Cassandra::Table with customer-managed KMS encryption by setting 'KmsKeyId' property in EncryptionSpecification to reference an AWS::KMS::Key resource. This provides control over Keyspace table encryption keys."
    },
    "CKV_AWS_241": {
        policy: "AWS Kinesis Firehose Delivery Streams are not encrypted with CMK",
        severity: "LOW",
        fix: "Configure AWS::KinesisFirehose::DeliveryStream with customer-managed KMS encryption by setting 'KMSEncryptionConfig' with 'AWSKMSKeyARN' property referencing an AWS::KMS::Key resource for delivery stream encryption."
    },
    "CKV_AWS_240": {
        policy: "AWS Kinesis Firehose's delivery stream is not encrypted",
        severity: "LOW",
        fix: "Enable encryption for AWS::KinesisFirehose::DeliveryStream by configuring DeliveryStreamEncryptionConfigurationInput with 'KeyType: CUSTOMER_MANAGED_CMK' and 'KeyARN' referencing an AWS::KMS::Key resource to encrypt data in transit."
    },
    "CKV_AWS_43": {
        policy: "AWS Kinesis streams are not encrypted using Server Side Encryption",
        severity: "LOW",
        fix: "Enable server-side encryption for AWS::Kinesis::Stream by setting 'ShardLevelMetrics' and 'StreamEncryption' with 'EncryptionType: KMS' and 'KeyId' referencing an AWS::KMS::Key resource to encrypt stream data at rest."
    },
    "CKV_AWS_185": {
        policy: "AWS Kinesis streams encryption is using default KMS keys instead of Customer's Managed Master Keys",
        severity: "LOW",
        fix: "Configure AWS::Kinesis::Stream with customer-managed KMS encryption by setting 'StreamEncryption' with 'KeyId' property referencing an AWS::KMS::Key resource instead of using default AWS-managed keys for enhanced control."
    },
    "CKV_AWS_177": {
        policy: "AWS Kinesis Video Stream not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::KinesisVideo::Stream with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This ensures video stream data is encrypted using customer-controlled keys."
    },
    "CKV_AWS_117": {
        policy: "AWS Lambda Function is not assigned to access within VPC",
        severity: "LOW",
        fix: "Configure AWS::Lambda::Function to run within VPC by setting 'VpcConfig' with 'SubnetIds' and 'SecurityGroupIds' properties. This provides network isolation and enables access to VPC-only resources like RDS instances."
    },
    "CKV_AWS_116": {
        policy: "AWS Lambda function is not configured for a DLQ",
        severity: "LOW",
        fix: "Configure AWS::Lambda::Function with Dead Letter Queue by setting 'DeadLetterConfig' with 'TargetArn' referencing an AWS::SQS::Queue or AWS::SNS::Topic resource. This captures failed function invocations for debugging and reprocessing."
    },
    "CKV_AWS_115": {
        policy: "AWS Lambda function is not configured for function-level concurrent execution Limit",
        severity: "LOW",
        fix: "Configure AWS::Lambda::Function with concurrent execution limit by setting 'ReservedConcurrencyLimit' property to an appropriate value. This prevents the function from consuming all available concurrent executions in your account."
    },
    "CKV_AWS_301": {
        policy: "AWS Lambda Function resource-based policy is overly permissive",
        severity: "LOW",
        fix: "Review and restrict AWS::Lambda::Permission resources by limiting 'Principal' to specific services or accounts instead of using wildcards. Remove overly broad permissions and implement least-privilege access control for function invocations."
    },
    "CKV_AWS_190": {
        policy: "AWS lustre file system not configured with CMK key",
        severity: "LOW",
        fix: "Configure AWS::FSx::FileSystem (Lustre) with customer-managed KMS encryption by setting 'KmsKeyId' property in LustreConfiguration to reference an AWS::KMS::Key resource for file system encryption."
    },
    "CKV_AWS_202": {
        policy: "AWS MemoryDB data is not encrypted in transit",
        severity: "LOW",
        fix: "Enable in-transit encryption for AWS::MemoryDB::Cluster by setting 'TLSEnabled: true'. This encrypts all client-to-cluster and node-to-node communication using TLS protocols to protect data during transmission."
    },
    "CKV_AWS_201": {
        policy: "AWS MemoryDB is not encrypted at rest by AWS' Key Management Service KMS using CMKs",
        severity: "LOW",
        fix: "Configure AWS::MemoryDB::Cluster with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This ensures in-memory data is encrypted using customer-controlled keys."
    },
    "CKV_AWS_209": {
        policy: "AWS MQ Broker is not encrypted by Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::AmazonMQ::Broker with customer-managed KMS encryption by setting 'KmsKeyId' property in EncryptionOptions to reference an AWS::KMS::Key resource for message encryption."
    },
    "CKV_AWS_197": {
        policy: "AWS MQBroker audit logging is disabled",
        severity: "LOW",
        fix: "Enable audit logging for AWS::AmazonMQ::Broker by setting 'Audit: true' in the Logs configuration. This captures broker activity for security monitoring and compliance requirements."
    },
    "CKV_AWS_208": {
        policy: "AWS MQBroker version is not up to date",
        severity: "LOW",
        fix: "Update AWS::AmazonMQ::Broker to use the latest version by setting 'EngineVersion' property to the most recent supported version for your engine type. This ensures security patches and feature updates are applied."
    },
    "CKV_AWS_207": {
        policy: "AWS MQBroker's minor version updates are disabled",
        severity: "LOW",
        fix: "Enable automatic minor version updates for AWS::AmazonMQ::Broker by setting 'AutoMinorVersionUpgrade: true'. This ensures the broker receives security patches and bug fixes automatically."
    },
    "CKV_AWS_242": {
        policy: "AWS MWAA environment has scheduler logs disabled",
        severity: "LOW",
        fix: "Enable scheduler logging for AWS::MWAA::Environment by setting 'SchedulerLogsConfiguration' with 'Enabled: true' and appropriate 'LogLevel'. This captures Airflow scheduler activity for monitoring and troubleshooting."
    },
    "CKV_AWS_244": {
        policy: "AWS MWAA environment has webserver logs disabled",
        severity: "LOW",
        fix: "Enable webserver logging for AWS::MWAA::Environment by setting 'WebserverLogsConfiguration' with 'Enabled: true' and appropriate 'LogLevel'. This captures Airflow webserver activity for monitoring and debugging."
    },
    "CKV_AWS_243": {
        policy: "AWS MWAA environment has worker logs disabled",
        severity: "LOW",
        fix: "Enable worker logging for AWS::MWAA::Environment by setting 'WorkerLogsConfiguration' with 'Enabled: true' and appropriate 'LogLevel'. This captures Airflow worker task execution logs for monitoring and troubleshooting."
    },
    "CKV2_AWS_30": {
        policy: "AWS Postgres RDS have Query Logging disabled",
        severity: "LOW",
        fix: "Enable query logging for PostgreSQL AWS::RDS::DBInstance by setting appropriate database parameters in AWS::RDS::DBParameterGroup. Configure 'log_statement: all' and 'log_min_duration_statement: 0' to capture SQL query activity."
    },
    "CKV_AWS_172": {
        policy: "AWS QLDB ledger has deletion protection is disabled",
        severity: "LOW",
        fix: "Enable deletion protection for AWS::QLDB::Ledger by setting 'DeletionProtection: true'. This prevents accidental deletion of the quantum ledger database and its immutable transaction history."
    },
    "CKV_AWS_246": {
        policy: "AWS RDS Cluster activity streams are not encrypted by Key Management Service (KMS) using Customer Managed Keys (CMKs)",
        severity: "LOW",
        fix: "Configure AWS::RDS::DBClusterActivityStream with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This encrypts database activity stream data using customer-controlled keys."
    },
    "CKV_AWS_16": {
        policy: "AWS RDS DB cluster encryption is disabled",
        severity: "LOW",
        fix: "Enable encryption for AWS::RDS::DBCluster by setting 'StorageEncrypted: true' and optionally 'KmsKeyId' to reference an AWS::KMS::Key resource. This encrypts the database cluster storage to protect data at rest."
    },
    "CKV_AWS_266": {
        policy: "AWS RDS DB snapshot does not use Customer Managed Keys (CMKs)",
        severity: "LOW",
        fix: "Configure AWS::RDS::DBClusterSnapshot with customer-managed KMS encryption by ensuring the source cluster uses customer-managed keys, or specify 'KmsKeyId' when creating manual snapshots to use customer-controlled encryption keys."
    },
    "CKV_AWS_146": {
        policy: "AWS RDS DB snapshot is not encrypted",
        severity: "LOW",
        fix: "Ensure AWS::RDS::DBClusterSnapshot is encrypted by creating snapshots from encrypted database clusters or enabling encryption on the source cluster with 'StorageEncrypted: true' to automatically encrypt all snapshots."
    },
    "CKV_AWS_211": {
        policy: "AWS RDS does not use a modern CaCert",
        severity: "LOW",
        fix: "Update AWS::RDS::DBInstance to use a modern CA certificate by setting 'CACertificateIdentifier' to a recent certificate bundle like 'rds-ca-2019' or later. This ensures secure SSL/TLS connections using current certificate authorities."
    },
    "CKV_AWS_133": {
        policy: "AWS RDS instance without Automatic Backup setting",
        severity: "LOW",
        fix: "Enable automatic backups for AWS::RDS::DBInstance by setting 'BackupRetentionPeriod' to 1 or higher (up to 35 days). This ensures point-in-time recovery capabilities and automated backup management."
    },
    "CKV_AWS_105": {
        policy: "AWS Redshift does not have require_ssl configured",
        severity: "LOW",
        fix: "Configure AWS::Redshift::Cluster to require SSL by creating an AWS::Redshift::ClusterParameterGroup with 'require_ssl: true' parameter and associating it with the cluster using 'ClusterParameterGroupName' property."
    },
    "CKV_AWS_64": {
        policy: "AWS Redshift instances are not encrypted",
        severity: "LOW",
        fix: "Enable encryption for AWS::Redshift::Cluster by setting 'Encrypted: true' and optionally 'KmsKeyId' to reference an AWS::KMS::Key resource. This encrypts the cluster storage to protect data at rest using KMS encryption."
    },
    "CKV_AWS_245": {
        policy: "AWS replicated backups are not encrypted at rest by Key Management Service (KMS) using a Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::RDS::DBInstance automated backups with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This ensures backup encryption uses customer-controlled keys."
    },
    "CKV_AWS_CUSTOM_1": {
        policy: "AWS resources that support tags do not have Tags",
        severity: "LOW",
        fix: "Add appropriate tags to AWS resources using the 'Tags' property. Include tags for resource identification, cost allocation, access control, and compliance. Common tags include Environment, Owner, Project, and CostCenter for better resource management."
    },
    "CKV2_AWS_65": {
        policy: "AWS S3 bucket access control lists (ACLs) in use",
        severity: "LOW",
        fix: "Disable S3 bucket ACLs in AWS::S3::Bucket by setting 'OwnershipControls' with 'BucketOwnerEnforced' rule. Use bucket policies and IAM policies instead of ACLs for more secure and manageable access control."
    },
    "CKV_AWS_186": {
        policy: "AWS S3 bucket Object not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::S3::Bucket server-side encryption with customer-managed KMS keys by setting 'BucketEncryption' with 'SSEAlgorithm: aws:kms' and 'KMSMasterKeyID' referencing an AWS::KMS::Key resource for object encryption."
    },
    "CKV_AWS_181": {
        policy: "AWS S3 Object Copy not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Ensure S3 object copies use customer-managed KMS encryption by configuring source and destination buckets with customer-managed keys, or specify SSE-KMS parameters with customer-managed key ARN during copy operations."
    },
    "CKV_AWS_369": {
        policy: "AWS Sagemaker Data Quality Job not encrypting communications between instances used for monitoring jobs",
        severity: "LOW",
        fix: "Configure AWS::SageMaker::DataQualityJobDefinition with inter-container traffic encryption by setting 'EnableInterContainerTrafficEncryption: true' in NetworkConfig. This encrypts communication between monitoring job instances."
    },
    "CKV_AWS_367": {
        policy: "AWS Sagemaker data quality job not encrypting model artifacts with KMS",
        severity: "LOW",
        fix: "Configure AWS::SageMaker::DataQualityJobDefinition with KMS encryption for model artifacts by setting 'KmsKeyId' property in DataQualityJobOutputConfig to reference an AWS::KMS::Key resource for output encryption."
    },
    "CKV_AWS_368": {
        policy: "AWS Sagemaker Data Quality Job not using KMS to encrypt data on attached storage volume",
        severity: "LOW",
        fix: "Configure AWS::SageMaker::DataQualityJobDefinition with storage volume encryption by setting 'VolumeKmsKeyId' property in DataQualityJobResources to reference an AWS::KMS::Key resource for attached EBS volume encryption."
    },
    "CKV_AWS_187": {
        policy: "AWS Sagemaker domain not encrypted using Customer Managed Key",
        severity: "LOW",
        fix: "Configure AWS::SageMaker::Domain with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This ensures SageMaker domain storage and user profiles are encrypted with customer-controlled keys."
    },
    "CKV_AWS_372": {
        policy: "AWS SageMaker Flow Definition does not use KMS for output configurations",
        severity: "LOW",
        fix: "Configure AWS::SageMaker::FlowDefinition with KMS encryption for outputs by setting 'KmsKeyId' property in OutputConfig to reference an AWS::KMS::Key resource. This encrypts human review workflow outputs and results."
    },
    "CKV_AWS_22": {
        policy: "AWS SageMaker notebook instance not configured with data encryption at rest using KMS key",
        severity: "LOW",
        fix: "Configure AWS::SageMaker::NotebookInstance with KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This encrypts the notebook instance storage volume to protect data at rest."
    },
    "CKV2_AWS_57": {
        policy: "AWS Secret Manager Automatic Key Rotation is not enabled",
        severity: "LOW",
        fix: "Enable automatic rotation for AWS::SecretsManager::Secret by configuring AWS::SecretsManager::RotationSchedule with appropriate 'RotationRules' including 'AutomaticallyAfterDays' property to regularly rotate secret values."
    },
    "CKV_AWS_149": {
        policy: "AWS Secrets Manager secret not encrypted by Customer Managed Key (CMK)",
        severity: "LOW",
        fix: "Configure AWS::SecretsManager::Secret with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This provides full control over secret encryption keys and access management."
    },
    "CKV_AWS_27": {
        policy: "AWS SQS Queue not configured with server side encryption",
        severity: "LOW",
        fix: "Enable server-side encryption for AWS::SQS::Queue by setting 'KmsMasterKeyId' property to reference an AWS::KMS::Key resource or use 'SqsManagedSseEnabled: true' for SQS-managed encryption to protect queue messages."
    },
    "CKV2_AWS_34": {
        policy: "AWS SSM Parameter is not encrypted",
        severity: "LOW",
        fix: "Configure AWS::SSM::Parameter with encryption by setting 'Type: SecureString' and optionally 'KeyId' to reference an AWS::KMS::Key resource. This encrypts parameter values using KMS to protect sensitive configuration data."
    },
    "CKV2_AWS_36": {
        policy: "AWS Terraform sends SSM secrets to untrusted domains over HTTP",
        severity: "LOW",
        fix: "Ensure SSM parameters containing secrets are only accessed over HTTPS endpoints. Review data source configurations and external integrations to prevent transmission of sensitive parameter values over unencrypted HTTP connections."
    },
    "CKV_AWS_331": {
        policy: "AWS Transit Gateway auto accept vpc attachment is enabled",
        severity: "LOW",
        fix: "Disable auto-accept for AWS::EC2::TransitGateway by setting 'AutoAcceptSharedAttachments: disable' and 'DefaultRouteTableAssociation: disable'. Manually review and approve VPC attachments to maintain network security boundaries."
    },
    "CKV_AWS_362": {
        policy: "Clusters of Neptune DB do not replicate tags to snapshots",
        severity: "LOW",
        fix: "Enable tag copying for AWS::Neptune::DBCluster by setting 'CopyTagsToSnapshot: true'. This ensures cluster tags are automatically applied to snapshots for consistent resource management and cost allocation."
    },
    "CKV_AWS_104": {
        policy: "DocDB does not have audit logs enabled",
        severity: "LOW",
        fix: "Enable audit logging for AWS::DocDB::DBCluster by setting 'EnableCloudwatchLogsExports' to include 'audit' in the list. This captures database activity for security monitoring and compliance auditing."
    },
    "CKV2_AWS_9": {
        policy: "EBS does not have an AWS Backup backup plan",
        severity: "LOW",
        fix: "Create AWS::Backup::BackupPlan and associate EBS volumes using AWS::Backup::BackupSelection with appropriate resource selection criteria. Configure backup frequency, retention, and lifecycle policies for EBS volume protection."
    },
    "CKV_AWS_135": {
        policy: "EC2 EBS is not optimized",
        severity: "LOW",
        fix: "Enable EBS optimization for AWS::EC2::Instance by setting 'EbsOptimized: true'. This provides dedicated bandwidth for EBS I/O operations, improving storage performance for instances that support this feature."
    },
    "CKV_AWS_51": {
        policy: "ECR image tags are not immutable",
        severity: "LOW",
        fix: "Configure AWS::ECR::Repository with immutable tags by setting 'ImageTagMutability: IMMUTABLE'. This prevents image tag overwriting, ensuring container image integrity and preventing accidental deployment of modified images."
    },
    "CKV_AWS_237": {
        policy: "Ensure AWS API gateway enables Create before Destroy",
        severity: "LOW",
        fix: "Configure AWS::ApiGateway::RestApi with create-before-destroy behavior. While CloudFormation handles this automatically, ensure proper deployment sequencing and avoid breaking changes that could cause API unavailability during updates."
    },
    "CKV2_AWS_3": {
        policy: "GuardDuty is not enabled to specific org/region",
        severity: "LOW",
        fix: "Enable AWS::GuardDuty::Detector by setting 'Enable: true' for the region. Configure FindingPublishingFrequency and enable appropriate data sources (S3Logs, KubernetesLogs, MalwareProtection) for comprehensive threat detection."
    },
    "CKV2_AWS_2": {
        policy: "Not only encrypted EBS volumes are attached to EC2 instances",
        severity: "LOW",
        fix: "Ensure all EBS volumes attached to AWS::EC2::Instance are encrypted by setting 'Encrypted: true' in AWS::EC2::Volume resources or EBS block device mappings. Use KMS keys for encryption to protect data at rest."
    },
    "CKV_AWS_313": {
        policy: "RDS cluster is not configured to copy tags to snapshots",
        severity: "LOW",
        fix: "Enable tag copying for AWS::RDS::DBCluster by setting 'CopyTagsToSnapshot: true'. This ensures cluster tags are automatically applied to snapshots for consistent resource management and cost tracking."
    },
    "CKV2_AWS_8": {
        policy: "RDS clusters do not have an AWS Backup backup plan",
        severity: "LOW",
        fix: "Create AWS::Backup::BackupPlan and associate RDS clusters using AWS::Backup::BackupSelection with appropriate resource ARN patterns. Configure backup schedules, retention policies, and cross-region copying for comprehensive database protection."
    },
    "CKV_AWS_157": {
        policy: "RDS instances do not have Multi-AZ enabled",
        severity: "LOW",
        fix: "Enable Multi-AZ deployment for AWS::RDS::DBInstance by setting 'MultiAZ: true'. This provides high availability, automatic failover capabilities, and enhanced data durability across multiple Availability Zones."
    },
    "CKV_AWS_141": {
        policy: "Redshift clusters version upgrade is not default",
        severity: "LOW",
        fix: "Enable automatic version upgrades for AWS::Redshift::Cluster by setting 'AllowVersionUpgrade: true'. This ensures the cluster receives security patches, performance improvements, and new features automatically."
    },
    "CKV_AWS_144": {
        policy: "S3 bucket cross-region replication disabled",
        severity: "LOW",
        fix: "Configure cross-region replication for AWS::S3::Bucket by setting 'ReplicationConfiguration' with appropriate rules, destination bucket, and IAM role. This provides data redundancy and disaster recovery capabilities across regions."
    },
    "CKV_AWS_143": {
        policy: "S3 bucket lock configuration disabled",
        severity: "LOW",
        fix: "Enable Object Lock for AWS::S3::Bucket by setting 'ObjectLockEnabled: true' and configuring ObjectLockConfiguration with appropriate retention rules. This prevents object deletion or modification for compliance and data protection."
    },
    "CKV_AWS_145": {
        policy: "S3 buckets are not encrypted with KMS",
        severity: "LOW",
        fix: "Configure AWS::S3::Bucket server-side encryption by setting 'BucketEncryption' with SSEAlgorithm: 'aws:kms' and 'KMSMasterKeyID' referencing an AWS::KMS::Key resource to encrypt objects using customer-managed keys."
    },
    "CKV_AWS_136": {
        policy: "Unencrypted ECR repositories",
        severity: "LOW",
        fix: "Enable encryption for AWS::ECR::Repository by setting 'EncryptionConfiguration' with 'EncryptionType: KMS' and optionally 'KmsKey' to reference an AWS::KMS::Key resource. This encrypts container images at rest in the registry."
    },
    "CKV_AWS_140": {
        policy: "Unencrypted RDS global clusters",
        severity: "LOW",
        fix: "Enable encryption for AWS::RDS::GlobalCluster by setting 'StorageEncrypted: true' when creating the global cluster. Ensure all regional clusters in the global cluster are also encrypted for comprehensive data protection."
    },
    "CKV_AWS_342": {
        policy: "WAF rule does not have any actions",
        severity: "LOW",
        fix: "Configure AWS::WAFv2::WebACL rules with appropriate actions by setting 'Action' property to 'Allow', 'Block', or 'Count'. Ensure each rule has a defined action to properly handle matching requests and provide effective web application protection."
    },
    "CKV_AWS_194": {
        policy: "AWS AppSync has field-level logging disabled",
        severity: "INFO",
        fix: "Enable field-level logging for AWS::AppSync::GraphQLApi by configuring LogConfig with 'CloudWatchLogsRoleArn' and setting 'FieldLogLevel: ALL'. This captures detailed GraphQL field resolver execution for monitoring, debugging, and security analysis."
    },
    "CKV_AWS_68": {
        policy: "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled",
        severity: "INFO",
        fix: "Associate AWS::CloudFront::Distribution with AWS::WAFv2::WebACL by setting 'WebACLId' property in DistributionConfig to reference a WebACL ARN. This protects your CDN against common web attacks, SQL injection, and cross-site scripting."
    },
    "CKV_AWS_251": {
        policy: "AWS CloudTrail logging is disabled",
        severity: "INFO",
        fix: "Enable logging for AWS::CloudTrail::Trail by setting 'IsLogging: true'. This ensures API activity tracking is active and events are being recorded for security monitoring, compliance, and audit trail purposes."
    },
    "CKV2_AWS_48": {
        policy: "AWS Config must record all possible resources",
        severity: "INFO",
        fix: "Configure AWS::Config::ConfigurationRecorder to record all supported resources by setting RecordingGroup with 'AllSupported: true' and 'IncludeGlobalResourceTypes: true'. Enable AWS::Config::ConfigurationRecorderStatus with 'IsEnabled: true' for comprehensive resource tracking."
    },
    "CKV2_AWS_45": {
        policy: "AWS Config Recording is disabled",
        severity: "INFO",
        fix: "Enable AWS Config recording by creating AWS::Config::ConfigurationRecorder and AWS::Config::ConfigurationRecorderStatus with 'IsEnabled: true'. This provides configuration history and change tracking for AWS resources in your account."
    },
    "CKV_AWS_47": {
        policy: "AWS DAX cluster not configured with encryption at rest",
        severity: "INFO",
        fix: "Enable encryption at rest for AWS::DAX::Cluster by setting 'SSESpecification' with 'SSEEnabled: true'. This encrypts cached DynamoDB data using AWS KMS with 256-bit AES encryption to protect data stored on disk."
    },
    "CKV_AWS_119": {
        policy: "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK",
        severity: "INFO",
        fix: "Configure AWS::DynamoDB::Table with customer-managed KMS encryption by setting 'SSESpecification' with 'SSEEnabled: true' and 'KMSMasterKeyId' referencing an AWS::KMS::Key resource instead of using default AWS-owned keys for enhanced control."
    },
    "CKV2_AWS_16": {
        policy: "AWS DynamoDB table Auto Scaling not enabled",
        severity: "INFO",
        fix: "Enable auto scaling for AWS::DynamoDB::Table by creating AWS::ApplicationAutoScaling::ScalableTarget and AWS::ApplicationAutoScaling::ScalingPolicy resources for read/write capacity. Configure target tracking policies to automatically adjust capacity based on utilization metrics."
    },
    "CKV_AWS_8": {
        policy: "AWS EC2 Auto Scaling Launch Configuration is not using encrypted EBS volumes",
        severity: "INFO",
        fix: "Configure AWS::AutoScaling::LaunchConfiguration with encrypted EBS volumes by setting 'Encrypted: true' in BlockDeviceMappings Ebs properties. This ensures all EBS volumes attached to Auto Scaling instances are encrypted for data protection."
    },
    "CKV_AWS_336": {
        policy: "AWS ECS task definition is not configured with read-only access to container root filesystems",
        severity: "INFO",
        fix: "Configure AWS::ECS::TaskDefinition containers with read-only root filesystem by setting 'readonlyRootFilesystem: true' in ContainerDefinitions. This prevents containers from modifying the root filesystem, reducing security risks from compromised containers."
    },
    "CKV_AWS_340": {
        policy: "AWS Elastic Beanstalk environment managed platform updates are not enabled",
        severity: "INFO",
        fix: "Enable managed platform updates for AWS::ElasticBeanstalk::Environment by configuring OptionSettings with namespace 'aws:elasticbeanstalk:managedactions' and setting 'ManagedActionsEnabled: true'. This ensures automatic platform updates and security patches."
    },
    "CKV_AWS_322": {
        policy: "AWS ElastiCache Redis cluster automatic version upgrade disabled",
        severity: "INFO",
        fix: "Enable automatic minor version upgrades for AWS::ElastiCache::CacheCluster by setting 'AutoMinorVersionUpgrade: true'. This ensures the cluster receives security patches and bug fixes automatically during maintenance windows."
    },
    "CKV_AWS_134": {
        policy: "AWS ElastiCache Redis cluster is not configured with automatic backup",
        severity: "INFO",
        fix: "Enable automatic backups for AWS::ElastiCache::CacheCluster by setting 'SnapshotRetentionLimit' to a value greater than 0 (up to 35 days). This creates daily automated backups for data recovery and cluster restoration capabilities."
    },
    "CKV2_AWS_50": {
        policy: "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled",
        severity: "INFO",
        fix: "Enable Multi-AZ automatic failover for AWS::ElastiCache::ReplicationGroup by setting 'AutomaticFailoverEnabled: true' and 'NumCacheClusters' to at least 2. Configure 'PreferredCacheClusterAZs' across multiple availability zones for high availability."
    },
    "CKV2_AWS_55": {
        policy: "AWS EMR cluster is not configured with security configuration",
        severity: "INFO",
        fix: "Associate AWS::EMR::Cluster with a security configuration by setting 'SecurityConfiguration' property to reference an AWS::EMR::SecurityConfiguration resource. This applies encryption, authentication, and authorization settings to the cluster."
    },
    "CKV_AWS_238": {
        policy: "AWS GuardDuty detector is not enabled",
        severity: "INFO",
        fix: "Enable AWS::GuardDuty::Detector by setting 'Enable: true'. Configure FindingPublishingFrequency and enable data sources like S3Logs, KubernetesLogs, and MalwareProtection for comprehensive threat detection across your AWS environment."
    },
    "CKV2_AWS_58": {
        policy: "AWS Neptune cluster deletion protection is disabled",
        severity: "INFO",
        fix: "Enable deletion protection for AWS::Neptune::DBCluster by setting 'DeletionProtection: true'. This prevents accidental deletion of the Neptune database cluster and protects against data loss from unintended cluster removal."
    },
    "CKV_AWS_361": {
        policy: "AWS Neptune DB clusters have backup retention period less than 7 days",
        severity: "INFO",
        fix: "Configure AWS::Neptune::DBCluster with adequate backup retention by setting 'BackupRetentionPeriod' to 7 or higher (up to 35 days). This ensures sufficient point-in-time recovery capabilities for data protection and compliance requirements."
    },
    "CKV_AWS_139": {
        policy: "AWS RDS cluster delete protection is disabled",
        severity: "INFO",
        fix: "Enable deletion protection for AWS::RDS::DBCluster by setting 'DeletionProtection: true'. This prevents accidental deletion of the RDS cluster and protects against data loss from unintended cluster removal operations."
    },
    "CKV_AWS_327": {
        policy: "AWS RDS DB cluster is encrypted using default KMS key instead of CMK",
        severity: "INFO",
        fix: "Configure AWS::RDS::DBCluster with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource instead of using default AWS-managed keys for enhanced encryption control and key management."
    },
    "CKV2_AWS_60": {
        policy: "AWS RDS instance with copy tags to snapshots disabled",
        severity: "INFO",
        fix: "Enable tag copying for AWS::RDS::DBInstance by setting 'CopyTagsToSnapshot: true'. This ensures instance tags are automatically applied to automated and manual snapshots for consistent resource management and cost allocation tracking."
    },
    "CKV2_AWS_27": {
        policy: "AWS RDS Postgres Cluster does not have query logging enabled",
        severity: "INFO",
        fix: "Enable PostgreSQL query logging for AWS::RDS::DBCluster by creating AWS::RDS::DBClusterParameterGroup with 'log_statement: all' and 'log_min_duration_statement: 1' parameters. Associate the parameter group with the cluster using 'DBClusterParameterGroupName' property."
    },
    "CKV_AWS_142": {
        policy: "AWS Redshift Cluster not encrypted using Customer Managed Key",
        severity: "INFO",
        fix: "Configure AWS::Redshift::Cluster with customer-managed KMS encryption by setting 'KmsKeyId' property to reference an AWS::KMS::Key resource. This provides full control over cluster encryption keys and enables detailed audit capabilities."
    },
    "CKV_AWS_307": {
        policy: "AWS SageMaker notebook instance with root access enabled",
        severity: "INFO",
        fix: "Disable root access for AWS::SageMaker::NotebookInstance by setting 'RootAccess: Disabled'. This follows the principle of least privilege and prevents unauthorized system-level modifications that could compromise security."
    },
    "CKV_AWS_387": {
        policy: "AWS SQS queue access policy is overly permissive",
        severity: "INFO",
        fix: "Restrict AWS::SQS::Queue access policy by replacing wildcard principals ('*') with specific IAM principals, accounts, or services. Use condition statements to further limit access based on IP addresses, time, or other security criteria for least-privilege access."
    },
    "CKV2_AWS_73": {
        policy: "AWS SQS queue encryption using default KMS key instead of CMK",
        severity: "INFO",
        fix: "Configure AWS::SQS::Queue with customer-managed KMS encryption by setting 'KmsMasterKeyId' property to reference an AWS::KMS::Key resource ARN instead of using default AWS-managed keys for enhanced encryption control and key management."
    },
    "CKV_AWS_294": {
        policy: "CloudTrail Event Data Store does not use Customer Managed Keys (CMKs)",
        severity: "INFO",
        fix: "Configure AWS::CloudTrail::EventDataStore with customer-managed KMS encryption by setting 'KMSKeyId' property to reference an AWS::KMS::Key resource. This provides full control over encryption keys used for storing CloudTrail event data."
    },
    // **** IAM POLICIES ****
    "CKV_AWS_62": {
        policy: "AWS IAM policies that allow full \"*-*\" administrative privileges are created",
        severity: "CRITICAL",
        fix: "Avoid creating IAM policies with full administrative privileges. Instead of using wildcard \"*\" for both Action and Resource in PolicyDocument, scope down permissions to specific actions and resources. For example, in AWS::IAM::Policy resource, replace \"Action\": \"*\" and \"Resource\": \"*\" with specific actions like \"s3:GetObject\" and specific resources like \"arn:aws:s3:::mybucket/*\". Follow the principle of least privilege by granting only the minimum permissions required."
    },
    "CKV_AWS_348": {
        policy: "AWS Access key enabled on root account",
        severity: "HIGH",
        fix: "Remove access keys from the root account and avoid creating AWS::IAM::AccessKey resources for the root user. Root account access keys pose significant security risks. Instead, create dedicated IAM users with specific permissions using AWS::IAM::User resource and associate access keys only with those users, not the root account."
    },
    "CKV_AWS_274": {
        policy: "AWS AdministratorAccess policy is used by IAM roles, users, or groups",
        severity: "HIGH",
        fix: "Avoid attaching the AWS managed 'AdministratorAccess' policy to IAM entities. Instead of using \"arn:aws:iam::aws:policy/AdministratorAccess\" in ManagedPolicyArns of AWS::IAM::Role, AWS::IAM::User, or AWS::IAM::Group, create custom policies with specific permissions tailored to the entity's actual needs using AWS::IAM::Policy with scoped PolicyDocument."
    },
    "CKV_AWS_358": {
        policy: "AWS GitHub Actions OIDC authorization policies allow for unsafe claims or claim order",
        severity: "HIGH",
        fix: "Configure GitHub Actions OIDC trust policies with secure claim conditions in AWS::IAM::Role AssumeRolePolicyDocument. Use specific conditions like 'StringEquals' for 'token.actions.githubusercontent.com:sub' to match exact repository and branch patterns. Avoid overly broad conditions that could allow unauthorized GitHub repositories to assume the role."
    },
    "CKV_AWS_13": {
        policy: "AWS IAM password policy does allow password reuse",
        severity: "HIGH",
        fix: "Configure IAM account password policy to prevent password reuse by setting 'PasswordReusePrevention' property to 24 (or desired number) in AWS::IAM::AccountPasswordPolicy resource. This ensures users cannot reuse their previous passwords, enhancing security against brute force attacks."
    },
    "CKV_AWS_61": {
        policy: "AWS IAM policy allows all principals used by any AWS service from target account to assume role",
        severity: "HIGH",
        fix: "Restrict IAM role trust policies to specific principals instead of allowing all AWS services from an account. In the AssumeRolePolicyDocument of AWS::IAM::Role, replace broad principal patterns like \"AWS\": \"arn:aws:iam::ACCOUNT-ID:*\" with specific service principals or roles, such as \"Service\": \"lambda.amazonaws.com\" or specific role ARNs."
    },
    "CKV_AWS_63": {
        policy: "AWS IAM policy documents allow * (asterisk) as a statement's action",
        severity: "HIGH",
        fix: "Replace wildcard actions (*) in IAM policy statements with specific actions. In the PolicyDocument of AWS::IAM::Policy, AWS::IAM::Role, AWS::IAM::User, or AWS::IAM::Group, instead of \"Action\": \"*\", use specific actions like [\"s3:GetObject\", \"s3:PutObject\"] to follow the principle of least privilege."
    },
    "CKV_AWS_49": {
        policy: "AWS IAM policy documents do not allow * (asterisk) as a statement's action",
        severity: "HIGH",
        fix: "Remove wildcard actions (*) from IAM policy documents. In PolicyDocument statements of AWS::IAM::Policy and related resources, replace \"Action\": \"*\" with specific actions relevant to the use case, such as \"Action\": [\"ec2:DescribeInstances\", \"ec2:StartInstances\"] to limit permissions appropriately."
    },
    "CKV_AWS_60": {
        policy: "AWS IAM role allows all services or principals to be assumed",
        severity: "HIGH",
        fix: "Restrict IAM role assume role policies to specific trusted entities. In the AssumeRolePolicyDocument of AWS::IAM::Role, replace overly broad principals like \"Principal\": \"*\" with specific service principals like \"Service\": \"lambda.amazonaws.com\" or specific AWS account principals to prevent unauthorized access."
    },
    "CKV_AWS_356": {
        policy: "Data source IAM policy document allows all resources with restricted actions",
        severity: "HIGH",
        fix: "Scope IAM policy resources to specific ARNs instead of using wildcards. In PolicyDocument statements, replace \"Resource\": \"*\" with specific resource ARNs like \"arn:aws:s3:::mybucket/*\" or \"arn:aws:dynamodb:region:account:table/mytable\" to limit the scope of permitted actions."
    },
    "CKV_AWS_288": {
        policy: "IAM policies allow data exfiltration",
        severity: "HIGH",
        fix: "Review and restrict IAM policies that permit data exfiltration actions. Remove or constrain permissions for actions like 's3:GetObject', 'dynamodb:Scan', 'rds:DescribeDBSnapshots' in PolicyDocument of AWS::IAM::Policy. Add resource constraints and condition blocks to limit when these actions can be performed."
    },
    "CKV_AWS_287": {
        policy: "IAM policies allow exposure of credentials",
        severity: "HIGH",
        fix: "Remove or restrict IAM policy actions that can expose credentials. In PolicyDocument, avoid or constrain actions like 'iam:GetUser', 'iam:ListAccessKeys', 'secretsmanager:GetSecretValue', 'ssm:GetParameter'. If required, add specific resource constraints and condition blocks to limit exposure."
    },
    "CKV_AWS_289": {
        policy: "IAM policies allow permissions management or resource exposure without constraints",
        severity: "HIGH",
        fix: "Restrict IAM policies that allow permissions management actions. In PolicyDocument, constrain or remove actions like 'iam:AttachUserPolicy', 'iam:PutRolePolicy', 'iam:CreateRole' unless specifically required. Add resource constraints and condition blocks to limit the scope of permissions management capabilities."
    },
    "CKV_AWS_290": {
        policy: "IAM policies allow write access without constraints",
        severity: "HIGH",
        fix: "Add constraints to IAM policies with broad write permissions. In PolicyDocument, replace unrestricted write actions with resource-specific permissions. For example, instead of \"s3:*\" action with \"*\" resource, use specific actions like \"s3:PutObject\" with specific bucket ARNs like \"arn:aws:s3:::mybucket/*\"."
    },
    "CKV_AWS_283": {
        policy: "IAM Policy Document Allows All or Any AWS Principal Permissions to Resources",
        severity: "HIGH",
        fix: "Replace overly broad principal permissions in IAM policy documents. In PolicyDocument of resource-based policies, replace \"Principal\": \"*\" or \"Principal\": {\"AWS\": \"*\"} with specific principal ARNs, account IDs, or service principals to prevent unauthorized access from any AWS account."
    },
    "CKV_AWS_355": {
        policy: "IAM policy document allows all resources with restricted actions",
        severity: "HIGH",
        fix: "Scope IAM policy resources to specific ARNs instead of wildcards. In PolicyDocument statements of AWS::IAM::Policy, replace \"Resource\": \"*\" with specific resource ARNs that align with the intended actions, such as \"arn:aws:s3:::specific-bucket/*\" for S3 operations."
    },
    "CKV_AWS_275": {
        policy: "IAM policy uses the AWS AdministratorAccess policy",
        severity: "HIGH",
        fix: "Replace AWS managed AdministratorAccess policy with custom policies. Instead of referencing \"arn:aws:iam::aws:policy/AdministratorAccess\" in ManagedPolicyArns, create AWS::IAM::Policy resources with specific permissions tailored to actual requirements, following the principle of least privilege."
    },
    "CKV_AWS_364": {
        policy: "Permissions delegated to AWS services for AWS Lambda functions are not limited by SourceArn or SourceAccount",
        severity: "HIGH",
        fix: "Add SourceArn or SourceAccount constraints to Lambda permissions. In AWS::Lambda::Permission resource, include 'SourceArn' property to specify the exact ARN of the service invoking the function, or 'SourceAccount' to limit access to a specific AWS account. This prevents unauthorized services from invoking your Lambda functions."
    },
    "CKV2_AWS_56": {
        policy: "The AWS Managed IAMFullAccess IAM policy should not be used",
        severity: "HIGH",
        fix: "Avoid using the AWS managed 'IAMFullAccess' policy. Instead of attaching \"arn:aws:iam::aws:policy/IAMFullAccess\" to IAM entities, create custom IAM policies with specific IAM permissions required for the use case using AWS::IAM::Policy with scoped PolicyDocument that grants only necessary IAM actions."
    },
    "CKV2_AWS_64": {
        policy: "A Policy is not Defined for KMS Key",
        severity: "MEDIUM",
        fix: "Define an explicit key policy for KMS keys using the 'Policy' property in AWS::KMS::Key resource. Avoid relying on default key policies. Create a PolicyDocument that specifies which principals can perform which actions on the key, including key administration and usage permissions."
    },
    "CKV_AWS_309": {
        policy: "Authorization type for API GatewayV2 routes is not specified",
        severity: "MEDIUM",
        fix: "Specify authorization type for API Gateway V2 routes by setting the 'AuthorizationType' property in AWS::ApiGatewayV2::Route resource. Use values like 'AWS_IAM', 'JWT', or 'CUSTOM' instead of leaving it unspecified. This ensures proper access control for your API endpoints."
    },
    "CKV_AWS_366": {
        policy: "AWS Cognito identity pool allows unauthenticated guest access",
        severity: "MEDIUM",
        fix: "Disable unauthenticated access in Cognito identity pools by setting 'AllowUnauthenticatedIdentities: false' in AWS::Cognito::IdentityPool resource. If guest access is required, implement proper restrictions and monitoring for unauthenticated user actions."
    },
    "CKV2_AWS_40": {
        policy: "AWS IAM policy allows full administrative privileges",
        severity: "MEDIUM",
        fix: "Avoid creating IAM policies with full administrative privileges. In PolicyDocument of AWS::IAM::Policy, replace statements with \"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\" with specific actions and resources. Grant only the minimum permissions required for the intended functionality."
    },
    "CKV_AWS_286": {
        policy: "AWS IAM Policy permission may cause privilege escalation",
        severity: "MEDIUM",
        fix: "Review and restrict IAM policies that may enable privilege escalation. Remove or constrain dangerous action combinations like 'iam:AttachUserPolicy' + 'iam:CreatePolicy', or 'iam:UpdateAssumeRolePolicy' + 'sts:AssumeRole' in PolicyDocument. Add resource constraints and condition blocks to prevent unauthorized privilege escalation."
    },
    "CKV_AWS_33": {
        policy: "AWS KMS Key policy overly permissive",
        severity: "MEDIUM",
        fix: "Restrict KMS key policies to avoid wildcard principals. In the Policy property of AWS::KMS::Key resource, replace \"Principal\": \"*\" with specific principal ARNs, account IDs, or service principals. Use conditions to further restrict access based on request context like source IP or MFA status."
    },
    "CKV2_AWS_43": {
        policy: "AWS S3 buckets are accessible to any authenticated user",
        severity: "MEDIUM",
        fix: "Restrict S3 bucket policies to avoid access by any authenticated user. In bucket policy PolicyDocument, replace \"Principal\": {\"AWS\": \"*\"} with specific principal ARNs or account IDs. Use bucket-level access controls and avoid granting broad access to authenticated users."
    },
    "CKV_AWS_110": {
        policy: "IAM policies allow privilege escalation",
        severity: "MEDIUM",
        fix: "Remove or constrain IAM policy actions that enable privilege escalation. In PolicyDocument, review action combinations that could allow users to escalate their privileges, such as 'iam:CreateRole' + 'iam:AttachRolePolicy'. Add resource constraints and conditions to limit privilege escalation possibilities."
    },
    "CKV2_AWS_22": {
        policy: "IAM User has access to the console",
        severity: "MEDIUM",
        fix: "Restrict console access for service accounts and automated users. Avoid creating AWS::IAM::LoginProfile resources for users that should only have programmatic access. If console access is required, implement strong password policies and MFA requirements using AWS::IAM::AccountPasswordPolicy and appropriate conditions."
    },
    "CKV_AWS_161": {
        policy: "RDS database does not have IAM authentication enabled",
        severity: "MEDIUM",
        fix: "Enable IAM database authentication for RDS instances by setting 'EnableIAMDatabaseAuthentication: true' in AWS::RDS::DBInstance resource. This allows users to authenticate to the database using IAM credentials instead of database passwords, improving security and enabling centralized access management."
    },
    "CKV_AWS_273": {
        policy: "Access is not controlled through Single Sign-On (SSO)",
        severity: "LOW",
        fix: "Implement AWS SSO for centralized access management instead of individual IAM users. Minimize the use of AWS::IAM::User resources for human access and instead configure AWS SSO with appropriate permission sets. This provides better governance and reduces the complexity of managing individual user access."
    },
    "CKV2_AWS_46": {
        policy: "AWS Cloudfront Distribution with S3 have Origin Access set to disabled",
        severity: "LOW",
        fix: "Configure CloudFront distributions to use Origin Access Control (OAC) or Origin Access Identity (OAI) for S3 origins. In AWS::CloudFront::Distribution resource, set up OriginAccessControlId in the Origin configuration and update the S3 bucket policy to allow access only from CloudFront, preventing direct S3 access."
    },
    "CKV_AWS_249": {
        policy: "AWS Execution Role ARN and Task Role ARN are different in ECS Task definitions",
        severity: "LOW",
        fix: "Ensure ECS task definitions use separate execution and task roles for better security isolation. In AWS::ECS::TaskDefinition resource, set different IAM roles for 'ExecutionRoleArn' (for ECS agent operations) and 'TaskRoleArn' (for application permissions). This follows the principle of separation of duties."
    },
    "CKV_AWS_12": {
        policy: "AWS IAM password policy does not have a number",
        severity: "LOW",
        fix: "Configure IAM password policy to require numbers by setting 'RequireNumbers: true' in AWS::IAM::AccountPasswordPolicy resource. This enhances password strength by ensuring passwords contain at least one numeric character."
    },
    "CKV_AWS_1": {
        policy: "AWS IAM policies that allow full administrative privileges are created",
        severity: "LOW",
        fix: "Avoid creating serverless function policies with full administrative privileges. Instead of granting broad permissions, scope IAM roles for Lambda functions to specific actions and resources they need. Use AWS::IAM::Role with PolicyDocument containing only necessary permissions for the function's intended operations."
    },
    "CKV_AWS_40": {
        policy: "AWS IAM policy attached to users",
        severity: "LOW",
        fix: "Attach IAM policies to groups or roles instead of directly to users. Avoid using the 'Users' property in AWS::IAM::Policy or 'Policies' property in AWS::IAM::User. Instead, create AWS::IAM::Group resources, attach policies to groups, and add users to groups using 'Groups' property in AWS::IAM::User for better access management."
    },
    "CKV_AWS_359": {
        policy: "AWS Neptune Cluster not configured with IAM authentication",
        severity: "LOW",
        fix: "Enable IAM database authentication for Neptune clusters by setting 'IamAuthEnabled: true' in AWS::Neptune::DBCluster resource. This allows applications to authenticate to Neptune using IAM credentials, providing better security and centralized access control."
    },
    "CKV2_AWS_52": {
        policy: "AWS OpenSearch Fine-grained access control is disabled",
        severity: "LOW",
        fix: "Enable fine-grained access control for OpenSearch domains by configuring 'AdvancedSecurityOptions' with 'Enabled: true' in AWS::OpenSearchService::Domain resource. Set up internal user database or SAML authentication and define appropriate access policies for enhanced security."
    },
    "CKV_AWS_162": {
        policy: "AWS RDS cluster not configured with IAM authentication",
        severity: "LOW",
        fix: "Enable IAM database authentication for RDS clusters by setting 'EnableIAMDatabaseAuthentication: true' in AWS::RDS::DBCluster resource. This allows applications to authenticate using IAM credentials instead of database passwords, improving security and access management."
    },
    "CKV_AWS_107": {
        policy: "Credentials exposure actions return credentials in an API response",
        severity: "LOW",
        fix: "Review and restrict IAM policy actions that can expose credentials in API responses. In PolicyDocument, carefully evaluate actions like 'iam:GetUser', 'secretsmanager:GetSecretValue', 'ssm:GetParameter' and add appropriate resource constraints and conditions to prevent unauthorized credential exposure."
    },
    "CKV_AWS_108": {
        policy: "Data exfiltration allowed without resource constraints",
        severity: "LOW",
        fix: "Add resource constraints to IAM policies that allow data access actions. In PolicyDocument, scope actions like 's3:GetObject', 'dynamodb:Scan', 'rds:CreateDBSnapshot' to specific resources using resource ARNs instead of wildcards. Implement conditions to limit when these actions can be performed."
    },
    "CKV_AWS_128": {
        policy: "IAM authentication for Amazon RDS clusters is disabled",
        severity: "LOW",
        fix: "Enable IAM database authentication for RDS clusters by setting 'EnableIAMDatabaseAuthentication: true' in AWS::RDS::DBCluster resource. Configure database users to use IAM authentication and update application code to use IAM credentials for database connections."
    },
    "CKV2_AWS_21": {
        policy: "Not all IAM users are members of at least one IAM group",
        severity: "LOW",
        fix: "Ensure all IAM users belong to at least one IAM group by adding 'Groups' property to AWS::IAM::User resources. Create AWS::IAM::Group resources with appropriate policies and assign users to these groups instead of attaching policies directly to users for better access management."
    },
    "CKV_AWS_109": {
        policy: "Resource exposure allows modification of policies and exposes resources",
        severity: "LOW",
        fix: "Add constraints to IAM policies that allow policy modification actions. In PolicyDocument, scope actions like 'iam:PutUserPolicy', 'iam:AttachRolePolicy', 's3:PutBucketPolicy' to specific resources and add conditions to prevent unauthorized resource exposure or policy modifications."
    },
    "CKV_AWS_129": {
        policy: "Respective logs of Amazon RDS are disabled",
        severity: "LOW",
        fix: "Enable appropriate database logging for RDS instances by setting 'EnableCloudwatchLogsExports' property in AWS::RDS::DBInstance resource. Include relevant log types such as 'error', 'general', 'slow-query' for MySQL, or 'postgresql' for PostgreSQL to ensure proper audit logging and monitoring."
    },
    "CKV_AWS_111": {
        policy: "Write access allowed without constraint",
        severity: "LOW",
        fix: "Add resource constraints to IAM policies with write permissions. In PolicyDocument, scope write actions to specific resources instead of using wildcards. For example, replace \"s3:PutObject\" with \"*\" resource with specific bucket ARNs like \"arn:aws:s3:::mybucket/*\" to limit write access scope."
    },
    "CKV2_AWS_41": {
        policy: "AWS EC2 Instance IAM Role not enabled",
        severity: "INFO",
        fix: "Attach IAM roles to EC2 instances for secure AWS API access by setting 'IamInstanceProfile' property in AWS::EC2::Instance resource. Create AWS::IAM::InstanceProfile and AWS::IAM::Role resources with appropriate permissions instead of using hardcoded credentials or access keys on EC2 instances."
    },
    "CKV2_AWS_14": {
        policy: "AWS IAM group not in use",
        severity: "INFO",
        fix: "Ensure IAM groups have at least one user member or remove unused groups. Either add users to AWS::IAM::Group by setting 'GroupName' in AWS::IAM::UserToGroupAddition resource, or remove unused AWS::IAM::Group resources to maintain clean IAM configuration and avoid confusion."
    },
    "CKV_AWS_9": {
        policy: "AWS IAM password policy does not expire in 90 days",
        severity: "INFO",
        fix: "Configure IAM password policy to require password expiration by setting 'MaxPasswordAge' property to 90 (or desired number of days) in AWS::IAM::AccountPasswordPolicy resource. This ensures regular password rotation and reduces the risk of compromised credentials."
    },
    "CKV_AWS_11": {
        policy: "AWS IAM password policy does not have a lowercase character",
        severity: "INFO",
        fix: "Configure IAM password policy to require lowercase characters by setting 'RequireLowercaseCharacters: true' in AWS::IAM::AccountPasswordPolicy resource. This enhances password complexity and security."
    },
    "CKV_AWS_10": {
        policy: "AWS IAM password policy does not have a minimum of 14 characters",
        severity: "INFO",
        fix: "Configure IAM password policy with minimum length by setting 'MinimumPasswordLength' property to 14 (or higher) in AWS::IAM::AccountPasswordPolicy resource. Longer passwords provide better protection against brute force attacks."
    },
    "CKV_AWS_14": {
        policy: "AWS IAM password policy does not have a symbol",
        severity: "INFO",
        fix: "Configure IAM password policy to require symbols by setting 'RequireSymbols: true' in AWS::IAM::AccountPasswordPolicy resource. This increases password complexity and enhances security against password attacks."
    },
    "CKV_AWS_15": {
        policy: "AWS IAM password policy does not have an uppercase character",
        severity: "INFO",
        fix: "Configure IAM password policy to require uppercase characters by setting 'RequireUppercaseCharacters: true' in AWS::IAM::AccountPasswordPolicy resource. This enhances password strength by ensuring character diversity."
    },
    "CKV_AWS_72": {
        policy: "SQS policy allows all actions",
        severity: "INFO",
        fix: "Restrict SQS queue policies to specific actions instead of allowing all actions. In the PolicyDocument of AWS::SQS::QueuePolicy resource, replace \"Action\": \"sqs:*\" with specific actions like [\"sqs:SendMessage\", \"sqs:ReceiveMessage\"] that align with the intended use case. Add appropriate resource and condition constraints."
    },
    // **** KUBERNETES POLICIES ****
    "CKV_AWS_100": {
        policy: "AWS EKS node group have implicit SSH access from 0.0.0.0/0",
        severity: "HIGH",
        fix: "Restrict SSH access to EKS node groups by configuring the RemoteAccess property in AWS::EKS::Nodegroup resource. Either remove the RemoteAccess configuration entirely to disable SSH access, or if SSH access is required, specify 'SourceSecurityGroups' with specific security group IDs instead of allowing access from 0.0.0.0/0. This prevents unauthorized internet-based SSH access to your EKS worker nodes."
    },
    "CKV_AWS_339": {
        policy: "EKS clusters are not running on a supported Kubernetes version",
        severity: "HIGH",
        fix: "Update EKS cluster to a supported Kubernetes version by setting the 'Version' property in AWS::EKS::Cluster resource to a currently supported version (e.g., '1.28', '1.27', '1.26'). AWS regularly deprecates older Kubernetes versions, so ensure you're running on a version that receives security updates and support. Plan regular upgrades to stay current with supported versions."
    },
    "CKV_AWS_58": {
        policy: "AWS EKS cluster does not have secrets encryption enabled",
        severity: "MEDIUM",
        fix: "Enable secrets encryption for EKS cluster by configuring the 'EncryptionConfig' property in AWS::EKS::Cluster resource. Set 'Resources' to include 'secrets' and specify a 'Provider' with a KMS key ARN. This encrypts Kubernetes secrets stored in etcd using AWS KMS, protecting sensitive information like passwords and API keys from unauthorized access."
    },
    "CKV_AWS_39": {
        policy: "AWS EKS cluster endpoint access publicly enabled",
        severity: "LOW",
        fix: "Restrict EKS cluster endpoint access by configuring 'ResourcesVpcConfig' property in AWS::EKS::Cluster resource. Set 'EndpointConfigPublic' to false to disable public access, or if public access is required, use 'PublicAccessCidrs' to specify allowed IP ranges instead of 0.0.0.0/0. Consider enabling private endpoint access with 'EndpointConfigPrivate: true' for internal cluster communication."
    },
    "CKV_AWS_38": {
        policy: "AWS EKS cluster security group overly permissive to all traffic",
        severity: "LOW",
        fix: "Configure EKS cluster with restricted public access CIDR blocks by setting 'PublicAccessCidrs' property in the ResourcesVpcConfig of AWS::EKS::Cluster resource. Replace overly broad ranges like '0.0.0.0/0' with specific IP ranges or CIDR blocks that represent your organization's networks. This limits which networks can access the EKS API server endpoint."
    },
    "CKV_AWS_37": {
        policy: "AWS EKS control plane logging disabled",
        severity: "INFO",
        fix: "Enable EKS control plane logging by configuring the 'Logging' property in AWS::EKS::Cluster resource. Set 'ClusterLogging' with 'Types' array containing relevant log types such as ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'] and 'Enabled: true'. This provides valuable diagnostic information for troubleshooting, security auditing, and monitoring cluster activities."
    },
    // **** LOGGING POLICIES ****
    "CKV_AWS_101": {
        policy: "Neptune logging is not enabled",
        severity: "HIGH",
        fix: "Enable Neptune cluster logging by setting 'EnableCloudwatchLogsExports' property to ['audit'] in AWS::Neptune::DBCluster resource. This captures database activities for auditing, monitoring, and compliance requirements, providing visibility into database operations and access patterns."
    },
    "CKV_AWS_48": {
        policy: "Amazon MQ Broker logging is not enabled",
        severity: "MEDIUM",
        fix: "Enable MQ broker logging by configuring 'Logs' property in AWS::AmazonMQ::Broker resource. Set 'Audit: true' and 'General: true' to enable audit and general logging respectively. This provides visibility into broker activities, message flows, and security events for monitoring and compliance purposes."
    },
    "CKV_AWS_80": {
        policy: "Amazon MSK cluster logging is not enabled",
        severity: "MEDIUM",
        fix: "Enable MSK cluster logging by configuring 'LoggingInfo' property in AWS::MSK::Cluster resource. Set 'BrokerLogs' with destinations like CloudWatchLogs (Enabled: true, LogGroup), Firehose (Enabled: true, DeliveryStream), or S3 (Enabled: true, Bucket, Prefix) to capture broker logs for monitoring and troubleshooting."
    },
    "CKV2_AWS_61": {
        policy: "An S3 bucket must have a lifecycle configuration",
        severity: "MEDIUM",
        fix: "Configure S3 bucket lifecycle policy by adding 'LifecycleConfiguration' property in AWS::S3::Bucket resource. Define rules for transitioning objects to different storage classes or expiring old objects. This helps manage storage costs and ensures proper data retention practices."
    },
    "CKV_AWS_121": {
        policy: "AWS config is not enabled in all regions",
        severity: "MEDIUM",
        fix: "Enable AWS Config in all regions by creating AWS::Config::ConfigurationAggregator resource with 'AllAwsRegions: true' in AccountAggregationSources, or specify individual regions in AwsRegions. This provides centralized compliance monitoring across all AWS regions."
    },
    "CKV_AWS_85": {
        policy: "AWS DocumentDB logging is not enabled",
        severity: "MEDIUM",
        fix: "Enable DocumentDB logging by setting 'EnableCloudwatchLogsExports' property to ['audit', 'profiler'] in AWS::DocDB::DBCluster resource. This enables audit logging for security monitoring and profiler logging for performance analysis and troubleshooting."
    },
    "CKV_AWS_126": {
        policy: "AWS EC2 instance detailed monitoring disabled",
        severity: "MEDIUM",
        fix: "Enable EC2 detailed monitoring by setting 'Monitoring: true' property in AWS::EC2::Instance resource. This provides CloudWatch metrics at 1-minute intervals instead of the default 5-minute intervals, enabling faster detection of performance issues and more granular monitoring."
    },
    "CKV_AWS_317": {
        policy: "Elasticsearch Domain Audit Logging is disabled",
        severity: "MEDIUM",
        fix: "Enable Elasticsearch audit logging by configuring 'LogPublishingOptions' property in AWS::Elasticsearch::Domain resource. Add 'AUDIT_LOGS' with 'CloudWatchLogsLogGroupArn' and 'Enabled: true' to capture user authentication, authorization, and index operations for security monitoring."
    },
    "CKV_AWS_285": {
        policy: "Execution history logging is not enabled on the State Machine",
        severity: "MEDIUM",
        fix: "Enable Step Functions execution history logging by configuring 'LoggingConfiguration' property in AWS::StepFunctions::StateMachine resource. Set 'Level' to 'ALL' or 'ERROR', 'IncludeExecutionData: true', and specify 'Destinations' with CloudWatch Logs group ARN for comprehensive execution monitoring."
    },
    "CKV_AWS_324": {
        policy: "RDS Cluster log capture is disabled",
        severity: "MEDIUM",
        fix: "Enable RDS cluster log exports by setting 'EnableCloudwatchLogsExports' property in AWS::RDS::DBCluster resource. Include relevant log types such as ['audit', 'error', 'general', 'slowquery'] for MySQL or ['postgresql'] for PostgreSQL to capture database activities and performance data."
    },
    "CKV_AWS_76": {
        policy: "API Gateway does not have access logging enabled",
        severity: "LOW",
        fix: "Enable API Gateway access logging by configuring 'AccessLogSetting' property in AWS::ApiGateway::Stage resource. Set 'DestinationArn' to a CloudWatch Logs group ARN and define 'Format' with desired log format including request ID, IP, user agent, and response metrics for API monitoring and analytics."
    },
    "CKV_AWS_73": {
        policy: "API Gateway does not have X-Ray tracing enabled",
        severity: "LOW",
        fix: "Enable API Gateway X-Ray tracing by setting 'TracingEnabled: true' property in AWS::ApiGateway::Stage resource. This provides distributed tracing capabilities to analyze request flows, identify performance bottlenecks, and troubleshoot issues across your API and downstream services."
    },
    "CKV2_AWS_4": {
        policy: "API Gateway stage does not have logging level defined appropriately",
        severity: "LOW",
        fix: "Configure appropriate API Gateway logging levels by setting 'MethodSettings' property in AWS::ApiGateway::Stage resource. Define 'LoggingLevel' as 'ERROR' or 'INFO' and 'DataTraceEnabled: true' for comprehensive API request and response logging to aid in debugging and monitoring."
    },
    "CKV_AWS_118": {
        policy: "AWS Amazon RDS instances Enhanced Monitoring is disabled",
        severity: "LOW",
        fix: "Enable RDS Enhanced Monitoring by setting 'MonitoringInterval' property to a value between 1-60 seconds and 'MonitoringRoleArn' to an appropriate IAM role in AWS::RDS::DBInstance resource. This provides real-time operating system metrics for detailed performance monitoring."
    },
    "CKV_AWS_95": {
        policy: "AWS API Gateway V2 has Access Logging is disabled",
        severity: "LOW",
        fix: "Enable API Gateway V2 access logging by configuring 'AccessLogSettings' property in AWS::ApiGatewayV2::Stage resource. Set 'DestinationArn' to a CloudWatch Logs group and define 'Format' with request details like requestId, ip, requestTime, and status for comprehensive API monitoring."
    },
    "CKV_AWS_124": {
        policy: "AWS CloudFormation stack configured without SNS topic",
        severity: "LOW",
        fix: "Configure CloudFormation stack notifications by setting 'NotificationARNs' property in AWS::CloudFormation::Stack resource with SNS topic ARNs. This enables notifications for stack events like creation, updates, and failures for better operational awareness and incident response."
    },
    "CKV_AWS_36": {
        policy: "AWS CloudTrail log validation is not enabled in all regions",
        severity: "LOW",
        fix: "Enable CloudTrail log file validation by setting 'EnableLogFileValidation: true' property in AWS::CloudTrail::Trail resource. This enables log file integrity validation using cryptographic hash to detect tampering or corruption of CloudTrail log files."
    },
    "CKV_AWS_66": {
        policy: "AWS CloudWatch Log groups not configured with definite retention days",
        severity: "LOW",
        fix: "Configure CloudWatch Log Group retention by setting 'RetentionInDays' property in AWS::Logs::LogGroup resource to a specific value (e.g., 30, 90, 365, 3653) instead of indefinite retention. This helps manage storage costs and ensures compliance with data retention policies."
    },
    "CKV_AWS_65": {
        policy: "AWS ECS cluster with container insights feature disabled",
        severity: "LOW",
        fix: "Enable ECS Container Insights by adding 'ClusterSettings' property in AWS::ECS::Cluster resource with 'Name: containerInsights' and 'Value: enabled'. This provides enhanced monitoring metrics and logs for containers, tasks, and services for better observability."
    },
    "CKV_AWS_333": {
        policy: "AWS ECS services have automatic public IP address assignment enabled",
        severity: "LOW",
        fix: "Disable automatic public IP assignment for ECS services by setting 'AssignPublicIp: DISABLED' in NetworkConfiguration of AWS::ECS::Service resource. This improves security by preventing direct internet access to ECS tasks unless explicitly required."
    },
    "CKV_AWS_176": {
        policy: "AWS WAF Web Access Control Lists logging is disabled",
        severity: "LOW",
        fix: "Enable WAF Classic logging by creating AWS::WAF::LoggingConfiguration resource with 'ResourceArn' pointing to the Web ACL and 'LogDestinationConfigs' specifying Kinesis Data Firehose delivery stream ARNs. This captures web traffic patterns and security events for analysis."
    },
    "CKV2_AWS_31": {
        policy: "AWS WAF2 does not have a Logging Configuration",
        severity: "LOW",
        fix: "Enable WAFv2 logging by creating AWS::WAFv2::LoggingConfiguration resource with 'ResourceArn' pointing to the Web ACL and 'LogDestinationConfigs' specifying destinations like CloudWatch Logs, S3, or Kinesis Data Firehose for comprehensive web traffic monitoring."
    },
    "CKV_AWS_276": {
        policy: "Data Trace is not enabled in the API Gateway Method Settings",
        severity: "LOW",
        fix: "Enable API Gateway data trace logging by setting 'DataTraceEnabled: true' in MethodSettings of AWS::ApiGateway::Stage resource. This captures full request and response data for detailed debugging and API behavior analysis, useful for development and troubleshooting."
    },
    "CKV2_AWS_39": {
        policy: "Domain Name System (DNS) query logging is not enabled for Amazon Route 53 hosted zones",
        severity: "LOW",
        fix: "Enable Route 53 DNS query logging by creating AWS::Route53::QueryLoggingConfig resource with 'HostedZoneId' and 'CloudWatchLogsLogGroupArn'. This captures DNS queries made to the hosted zone for security monitoring, troubleshooting, and usage analytics."
    },
    "CKV_AWS_75": {
        policy: "Global Accelerator does not have Flow logs enabled",
        severity: "LOW",
        fix: "Enable Global Accelerator flow logs by setting 'Enabled: true' in FlowLogsConfig property of AWS::GlobalAccelerator::Accelerator resource. Specify 'FlowLogsS3Bucket' and 'FlowLogsS3Prefix' to capture network flow information for performance analysis and troubleshooting."
    },
    "CKV_AWS_325": {
        policy: "RDS Cluster audit logging for MySQL engine is disabled",
        severity: "LOW",
        fix: "Enable MySQL RDS cluster audit logging by setting 'EnableCloudwatchLogsExports' property to include 'audit' in AWS::RDS::DBCluster resource. Also configure the cluster parameter group with server_audit_logging=1 and appropriate server_audit_events for comprehensive database activity monitoring."
    },
    "CKV_AWS_353": {
        policy: "RDS instances have performance insights disabled",
        severity: "LOW",
        fix: "Enable RDS Performance Insights by setting 'EnablePerformanceInsights: true' and 'PerformanceInsightsRetentionPeriod' to desired retention days (7 or 731) in AWS::RDS::DBInstance resource. Optionally set 'PerformanceInsightsKMSKeyId' for encryption to gain detailed database performance monitoring."
    },
    "CKV2_AWS_62": {
        policy: "S3 buckets do not have event notifications enabled",
        severity: "LOW",
        fix: "Configure S3 event notifications by adding 'NotificationConfiguration' property in AWS::S3::Bucket resource. Define TopicConfigurations, QueueConfigurations, or LambdaConfigurations with appropriate events like 's3:ObjectCreated:*' to trigger notifications for bucket activities and automated workflows."
    },
    "CKV_AWS_284": {
        policy: "State machine does not have X-ray tracing enabled",
        severity: "LOW",
        fix: "Enable Step Functions X-Ray tracing by setting 'TracingConfiguration' property with 'Enabled: true' in AWS::StepFunctions::StateMachine resource. This provides distributed tracing capabilities to analyze execution flows, identify performance bottlenecks, and troubleshoot state machine workflows."
    },
    "CKV_AWS_86": {
        policy: "AWS CloudFront distribution with access logging disabled",
        severity: "INFO",
        fix: "Enable CloudFront access logging by configuring 'Logging' property in AWS::CloudFront::Distribution resource. Set 'Bucket' to S3 bucket name, optionally set 'Prefix' for log file organization, and 'IncludeCookies: false' to capture request logs for analytics, monitoring, and troubleshooting."
    },
    "CKV_AWS_67": {
        policy: "AWS CloudTrail is not enabled with multi trail and not capturing all management events",
        severity: "INFO",
        fix: "Configure CloudTrail for comprehensive logging by setting 'IsMultiRegionTrail: true', 'IncludeGlobalServiceEvents: true', and 'IsLogging: true' in AWS::CloudTrail::Trail resource. Configure EventSelectors to capture all management events with 'ReadWriteType: All' and 'IncludeManagementEvents: true'."
    },
    "CKV_AWS_35": {
        policy: "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
        severity: "INFO",
        fix: "Enable CloudTrail log encryption by setting 'KMSKeyId' property with a customer-managed KMS key ARN in AWS::CloudTrail::Trail resource. This encrypts CloudTrail logs at rest using your own KMS key, providing enhanced security and control over access to audit logs."
    },
    "CKV2_AWS_10": {
        policy: "AWS CloudTrail trail logs is not integrated with CloudWatch Log",
        severity: "INFO",
        fix: "Integrate CloudTrail with CloudWatch Logs by setting 'CloudWatchLogsLogGroupArn' and 'CloudWatchLogsRoleArn' properties in AWS::CloudTrail::Trail resource. This enables real-time log monitoring, alerting, and analysis of AWS API calls through CloudWatch Logs."
    },
    "CKV_AWS_338": {
        policy: "AWS CloudWatch log groups retention set to less than 365 days",
        severity: "INFO",
        fix: "Configure CloudWatch Log Groups with adequate retention by setting 'RetentionInDays' property to 365 or higher in AWS::Logs::LogGroup resource. This ensures logs are retained for sufficient time for compliance, audit, and historical analysis requirements."
    },
    "CKV_AWS_314": {
        policy: "AWS CodeBuild project not configured with logging configuration",
        severity: "INFO",
        fix: "Configure CodeBuild project logging by setting 'LogsConfig' property in AWS::CodeBuild::Project resource. Enable CloudWatchLogs with 'Status: ENABLED' and optionally configure S3Logs for build log storage and monitoring. This provides visibility into build processes and troubleshooting capabilities."
    },
    "CKV_AWS_7": {
        policy: "AWS Customer Master Key (CMK) rotation is not enabled",
        severity: "INFO",
        fix: "Enable KMS key rotation by setting 'EnableKeyRotation: true' property in AWS::KMS::Key resource. This automatically rotates the key material annually while keeping the same key ID, ARN, and permissions, enhancing security by regularly changing encryption keys."
    },
    "CKV_AWS_92": {
        policy: "AWS Elastic Load Balancer (Classic) with access log disabled",
        severity: "INFO",
        fix: "Enable Classic Load Balancer access logging by setting 'AccessLoggingPolicy' property with 'Enabled: true', 'S3BucketName', and optionally 'S3BucketPrefix' in AWS::ElasticLoadBalancing::LoadBalancer resource. This captures detailed request logs for traffic analysis and troubleshooting."
    },
    "CKV_AWS_91": {
        policy: "AWS Elastic Load Balancer v2 (ELBv2) with access log disabled",
        severity: "INFO",
        fix: "Enable Application/Network Load Balancer access logging by adding 'LoadBalancerAttributes' with 'Key: access_logs.s3.enabled', 'Value: true' and 'Key: access_logs.s3.bucket' with S3 bucket name in AWS::ElasticLoadBalancingV2::LoadBalancer resource for comprehensive traffic monitoring."
    },
    "CKV2_AWS_63": {
        policy: "AWS Network Firewall is not configured with logging configuration",
        severity: "INFO",
        fix: "Configure Network Firewall logging by creating AWS::NetworkFirewall::LoggingConfiguration resource with 'FirewallArn', 'LoggingConfiguration' specifying LogDestinationConfigs for CloudWatch Logs, S3, or Kinesis Data Firehose to capture network traffic patterns and security events."
    },
    "CKV_AWS_71": {
        policy: "AWS Redshift database does not have audit logging enabled",
        severity: "INFO",
        fix: "Enable Redshift audit logging by setting 'LoggingProperties' with 'BucketName' and optionally 'S3KeyPrefix' in AWS::Redshift::Cluster resource. This captures database connection logs, user activity logs, and user activity queries for security monitoring and compliance."
    },
    "CKV2_AWS_11": {
        policy: "AWS VPC Flow Logs not enabled",
        severity: "INFO",
        fix: "Enable VPC Flow Logs by creating AWS::EC2::FlowLog resource with 'ResourceType: VPC', 'ResourceId' pointing to VPC ID, 'TrafficType: ALL' or 'REJECT', and 'LogDestination' specifying CloudWatch Logs group ARN or S3 bucket for network traffic monitoring and security analysis."
    },
    // **** NETWORKING POLICIES ****
    "CKV_AWS_328": {
        policy: "ALB is not configured with the defensive or strictest desync mitigation mode",
        severity: "HIGH",
        fix: "In your CloudFormation template, set the 'DesyncMitigationMode' property to either 'defensive' or 'strictest' in your AWS::ElasticLoadBalancingV2::LoadBalancer resource. This protects against HTTP Desync attacks that could lead to DDoS, cache poisoning, and data theft. Example: DesyncMitigationMode: 'defensive'"
    },
    "CKV2_AWS_38": {
        policy: "Domain Name System Security Extensions (DNSSEC) signing is not enabled for Amazon Route 53 public hosted zones",
        severity: "HIGH",
        fix: "Enable DNSSEC signing for your Route 53 public hosted zones in CloudFormation by: 1) Creating an AWS::Route53::HostedZone resource for your domain, 2) Adding an AWS::Route53::KeySigningKey resource with a reference to a KMS key, 3) Creating an AWS::Route53::HostedZoneDNSSEC resource that references your hosted zone. This protects your DNS records from tampering and DNS spoofing attacks."
    },
    "CKV_AWS_291": {
        policy: "MSK nodes are not private",
        severity: "HIGH",
        fix: "Configure your AWS::MSK::Cluster resource in CloudFormation to use private subnets by setting the 'BrokerNodeGroupInfo.ClientSubnets' property to reference only private subnet IDs, and ensure 'BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type' is not set to 'SERVICE_PROVIDED_EIPS'. This prevents public internet access to your Kafka brokers, reducing attack surface."
    },
    "CKV2_AWS_66": {
        policy: "MWAA environment is publicly accessible",
        severity: "HIGH",
        fix: "Set 'NetworkConfiguration.AccessMode' property to 'PRIVATE_ONLY' in your AWS::MWAA::Environment CloudFormation resource. This ensures your Managed Workflows for Apache Airflow environment can only be accessed from within your VPC and not from the public internet, reducing potential attack vectors."
    },
    "CKV_AWS_352": {
        policy: "NACL ingress allows all ports",
        severity: "HIGH",
        fix: "In your AWS::EC2::NetworkAclEntry resources, avoid using port range 0-65535 for ingress rules. Instead, define specific NetworkAclEntry resources for each required port or port range with the Protocol, PortRange.From, and PortRange.To properties explicitly specified. This limits network traffic to only necessary services and reduces the attack surface."
    },
    "CKV_AWS_192": {
        policy: "WAF enables message lookup in Log4j2",
        severity: "HIGH",
        fix: "Add a rule to your AWS::WAFv2::WebACL resource that blocks requests containing Log4j2 JNDI lookup patterns. Create a ByteMatchSet with pattern strings like '${jndi:' and configure your WAF to block these patterns. This protects against Log4Shell vulnerabilities (CVE-2021-44228) that could allow remote code execution."
    },
    "CKV_AWS_131": {
        policy: "ALB does not drop HTTP headers",
        severity: "MEDIUM",
        fix: "Configure your AWS::ElasticLoadBalancingV2::LoadBalancer to drop invalid HTTP headers by setting the 'LoadBalancerAttributes' property to include an attribute with 'Key: routing.http.drop_invalid_header_fields.enabled' and 'Value: true'. This prevents potentially malicious HTTP headers from being forwarded to your application."
    },
    "CKV2_AWS_70": {
        policy: "AWS API Gateway method lacking authorization or API keys",
        severity: "MEDIUM",
        fix: "Add authorization to your AWS::ApiGateway::Method by setting the 'AuthorizationType' property to 'AWS_IAM', 'COGNITO_USER_POOLS', or 'CUSTOM' (not 'NONE'). Alternatively, set 'ApiKeyRequired' to 'true'. This ensures that API endpoints require proper authentication before being accessed."
    },
    "CKV2_AWS_54": {
        policy: "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication",
        severity: "MEDIUM",
        fix: "In your AWS::CloudFront::Distribution resource, set the 'ViewerCertificate.MinimumProtocolVersion' property to 'TLSv1.2_2021' or newer. Avoid using older protocols like 'TLSv1', 'TLSv1_2016', or 'TLSv1.1_2016' which have known vulnerabilities. This ensures stronger encryption and secure communications with clients."
    },
    "CKV2_AWS_72": {
        policy: "AWS CloudFront origin protocol policy does not enforce HTTPS-only",
        severity: "MEDIUM",
        fix: "In your AWS::CloudFront::Distribution resource, set 'DistributionConfig.Origins.CustomOriginConfig.OriginProtocolPolicy' to 'https-only' for each origin. This ensures that CloudFront only connects to your origins using HTTPS, preventing insecure HTTP communications that could expose sensitive data."
    },
    "CKV_AWS_34": {
        policy: "AWS CloudFront viewer protocol policy is not configured with HTTPS",
        severity: "MEDIUM",
        fix: "Set the 'ViewerProtocolPolicy' property to either 'redirect-to-https' or 'https-only' in the DefaultCacheBehavior and any CacheBehaviors of your AWS::CloudFront::Distribution resource. Using 'redirect-to-https' will automatically redirect HTTP requests to HTTPS, while 'https-only' will reject HTTP requests entirely."
    },
    "CKV_AWS_2": {
        policy: "AWS Elastic Load Balancer v2 (ELBv2) listener that allow connection requests over HTTP",
        severity: "MEDIUM",
        fix: "For AWS::ElasticLoadBalancingV2::Listener resources, ensure the 'Protocol' property is set to 'HTTPS' or 'TLS' rather than 'HTTP' or 'TCP'. If you need to support HTTP, create a redirect listener with 'DefaultActions.Type' set to 'redirect' and 'RedirectConfig.Protocol' set to 'HTTPS'. This enforces encrypted communications between clients and your load balancer."
    },
    "CKV2_AWS_75": {
        policy: "AWS Lambda function URL having overly permissive cross-origin resource sharing permissions",
        severity: "MEDIUM",
        fix: "When configuring AWS::Lambda::Url resources, avoid setting 'Cors.AllowOrigins' to '*'. Instead, specify exact domains that need access in the AllowOrigins array. Also, set 'Cors.AllowMethods' to only include necessary HTTP methods and 'Cors.AllowCredentials' to 'false' unless you specifically need cross-origin requests with credentials. This prevents cross-site attacks."
    },
    "CKV_AWS_378": {
        policy: "AWS Load Balancer uses HTTP protocol",
        severity: "MEDIUM",
        fix: "Configure your AWS::ElasticLoadBalancingV2::TargetGroup to use HTTPS by setting the 'Protocol' property to 'HTTPS' instead of 'HTTP'. Also, specify a proper 'HealthCheckProtocol' value of 'HTTPS'. If your application doesn't support HTTPS, implement TLS termination at the load balancer and use AWS::ElasticLoadBalancingV2::Listener with HTTPS protocol."
    },
    "CKV2_AWS_69": {
        policy: "AWS RDS database instance not configured with encryption in transit",
        severity: "MEDIUM",
        fix: "Enable encryption in transit for your AWS::RDS::DBInstance by setting both 'StorageEncrypted: true' and including a parameter group (AWS::RDS::DBParameterGroup) with parameters like 'ssl_force_connection=1' or 'rds.force_ssl=1' depending on your database engine. This ensures all database connections use SSL/TLS encryption to protect data during transmission."
    },
    "CKV_AWS_379": {
        policy: "AWS S3 bucket not configured with secure data transport policy",
        severity: "MEDIUM",
        fix: "Add a bucket policy to your AWS::S3::Bucket that enforces HTTPS-only access. In the AWS::S3::BucketPolicy resource, include a condition that denies requests when 'aws:SecureTransport' is 'false'. Example: \"Effect\": \"Deny\", \"Principal\": \"*\", \"Action\": \"s3:*\", \"Resource\": [bucket ARN and objects], \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}."
    },
    "CKV_AWS_370": {
        policy: "AWS SageMaker model does not use network isolation",
        severity: "MEDIUM",
        fix: "Enable network isolation for your AWS::SageMaker::Model by setting the 'EnableNetworkIsolation' property to 'true'. This creates a security boundary around your model container, preventing it from making outbound network calls, which helps protect against data exfiltration and improves security of your machine learning workloads."
    },
    "CKV2_AWS_68": {
        policy: "AWS SageMaker notebook instance IAM policy is overly permissive",
        severity: "MEDIUM",
        fix: "Restrict the IAM policy attached to your SageMaker notebook instance by defining a custom policy in AWS::IAM::Role with least-privilege permissions. Avoid using wildcard '*' in the Action and Resource elements. Instead, specify only the exact permissions needed for your workload. Reference this role in your AWS::SageMaker::NotebookInstance's 'RoleArn' property."
    },
    "CKV_AWS_277": {
        policy: "AWS Security Group allows all traffic on all ports",
        severity: "MEDIUM",
        fix: "Remove any overly permissive rules from your AWS::EC2::SecurityGroup resource. Instead of using a CidrIp of '0.0.0.0/0' with port range '0-65535', define specific ingress rules with appropriate IpProtocol, FromPort, ToPort, and CidrIp values that match your application's requirements. This limits exposure to only the necessary services and network ranges."
    },
    "CKV_AWS_164": {
        policy: "AWS Transfer Server is publicly exposed",
        severity: "MEDIUM",
        fix: "Set the 'EndpointType' property to 'VPC' instead of 'PUBLIC' in your AWS::Transfer::Server resource, and provide appropriate 'EndpointDetails' with VPC configuration including subnet IDs and security groups. This restricts your SFTP/FTPS/FTP server to be accessible only from within your VPC rather than from the public internet."
    },
    "CKV_AWS_90": {
        policy: "DocDB TLS is disabled",
        severity: "MEDIUM",
        fix: "Enable TLS for your AWS::DocDB::DBCluster by creating an AWS::DocDB::DBClusterParameterGroup with the 'tls' parameter set to 'enabled', then reference this parameter group in your DBCluster resource's 'DBClusterParameterGroupName' property. This enforces encrypted connections between clients and your DocumentDB cluster."
    },
    "CKV2_AWS_29": {
        policy: "Public API gateway not configured with AWS Web Application Firewall v2 (AWS WAFv2)",
        severity: "MEDIUM",
        fix: "Protect your public API Gateway by creating an AWS::WAFv2::WebACL resource with appropriate rules, then associate it with your API stage using an AWS::WAFv2::WebACLAssociation resource where 'ResourceArn' references your AWS::ApiGateway::Stage ARN. This provides an additional security layer against common web vulnerabilities and attacks."
    },
    "CKV_AWS_365": {
        policy: "TLS not enforced in SES configuration set",
        severity: "MEDIUM",
        fix: "Enable TLS enforcement in your AWS::SES::ConfigurationSet by adding a TlsPolicy property set to 'Require'. This ensures that Amazon SES only delivers email to recipients that support TLS connections, preventing email contents from being transmitted over unencrypted connections."
    },
    "CKV2_AWS_20": {
        policy: "ALB does not redirect HTTP requests into HTTPS ones",
        severity: "LOW",
        fix: "Create an HTTP-to-HTTPS redirect by adding an AWS::ElasticLoadBalancingV2::Listener with 'Protocol: HTTP' and configure its 'DefaultActions' with 'Type: redirect' and 'RedirectConfig: { Protocol: \"HTTPS\", Port: \"443\", StatusCode: \"HTTP_301\" }'. This ensures all HTTP traffic is automatically redirected to secure HTTPS connections."
    },
    "CKV2_AWS_7": {
        policy: "Amazon EMR clusters' security groups are open to the world",
        severity: "LOW",
        fix: "For AWS::EMR::Cluster resources, specify security groups in 'SecurityConfiguration' that have restricted inbound rules. Create associated AWS::EC2::SecurityGroup resources with ingress rules that limit source IPs to specific CIDR blocks or security groups, not '0.0.0.0/0'. This prevents unauthorized access to your EMR cluster from the internet."
    },
    "CKV2_AWS_15": {
        policy: "Auto scaling groups associated with a load balancer do not use elastic load balancing health checks",
        severity: "LOW",
        fix: "Configure your AWS::AutoScaling::AutoScalingGroup to use ELB health checks by setting the 'HealthCheckType' property to 'ELB' and setting an appropriate 'HealthCheckGracePeriod' value. This ensures instances are replaced if they fail load balancer health checks, improving application availability."
    },
    "CKV_AWS_233": {
        policy: "AWS ACM certificate does not enable Create before Destroy",
        severity: "LOW",
        fix: "Use the DependsOn attribute in CloudFormation to ensure the new certificate is created before the old one is destroyed. In practice, implement a blue/green deployment strategy for certificate rotation, where you create a new certificate resource with a different name, update references to use the new certificate, then remove the old certificate resource after deployment is successful."
    },
    "CKV2_AWS_71": {
        policy: "AWS ACM Certificate with wildcard domain name",
        severity: "LOW",
        fix: "Instead of using wildcard certificates (*.example.com) in your AWS::CertificateManager::Certificate resources, specify distinct certificates with explicit domain names in the 'DomainName' and 'SubjectAlternativeNames' properties. This improves security by limiting the scope of each certificate to only the domains that actually need it."
    },
    "CKV2_AWS_28": {
        policy: "AWS Application Load Balancer (ALB) not configured with AWS Web Application Firewall v2 (AWS WAFv2)",
        severity: "LOW",
        fix: "Protect your ALB by creating an AWS::WAFv2::WebACL resource with appropriate security rules, then associate it with your load balancer using an AWS::WAFv2::WebACLAssociation resource where 'ResourceArn' references your AWS::ElasticLoadBalancingV2::LoadBalancer ARN. This adds protection against common web attacks."
    },
    "CKV2_AWS_32": {
        policy: "AWS CloudFront distribution does not have a strict security headers policy attached",
        severity: "LOW",
        fix: "Add a response headers policy to your AWS::CloudFront::Distribution by creating an AWS::CloudFront::ResponseHeadersPolicy resource with security headers (X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, etc.), then reference it in your distribution's cache behaviors using the 'ResponseHeadersPolicyId' property. This helps prevent various browser-based attacks."
    },
    "CKV_AWS_174": {
        policy: "AWS CloudFront web distribution using insecure TLS version",
        severity: "LOW",
        fix: "In your AWS::CloudFront::Distribution resource, update the 'ViewerCertificate.MinimumProtocolVersion' property to 'TLSv1.2_2021' or newer. This ensures that CloudFront only accepts connections using modern, secure TLS protocols, protecting against vulnerabilities in older TLS versions."
    },
    "CKV2_AWS_42": {
        policy: "AWS CloudFront web distribution with default SSL certificate",
        severity: "LOW",
        fix: "Use a custom SSL certificate in your AWS::CloudFront::Distribution by setting 'ViewerCertificate.CloudFrontDefaultCertificate' to 'false' and providing either 'ViewerCertificate.AcmCertificateArn' (recommended) or 'ViewerCertificate.IamCertificateId'. This improves security and builds trust with users by using your domain's certificate rather than the generic CloudFront one."
    },
    "CKV_AWS_374": {
        policy: "AWS CloudFront web distribution with geo restriction disabled",
        severity: "LOW",
        fix: "Enable geographic restrictions in your AWS::CloudFront::Distribution by configuring the 'Restrictions.GeoRestriction' property with appropriate 'RestrictionType' ('whitelist' or 'blacklist') and 'Locations' array containing the ISO 3166-1-alpha-2 country codes you want to allow or block. This can help prevent access from high-risk regions or countries where you don't do business."
    },
    "CKV2_AWS_49": {
        policy: "AWS Database Migration Service endpoint do not have SSL configured",
        severity: "LOW",
        fix: "Enable SSL for your AWS::DMS::Endpoint by setting appropriate SSL mode in the 'MySqlSettings', 'PostgreSqlSettings', 'OracleSettings', 'SybaseSettings', 'MicrosoftSqlServerSettings', etc. depending on your database type. For example, add 'SslMode: verify-full' and provide certificate information when applicable. This encrypts data during migration."
    },
    "CKV2_AWS_12": {
        policy: "AWS Default Security Group does not restrict all traffic",
        severity: "LOW",
        fix: "Remove all ingress and egress rules from your default security group by creating an AWS::EC2::SecurityGroupIngress and AWS::EC2::SecurityGroupEgress with the default security group ID, then add only the specific rules you need. Alternatively, create a custom security group with specific rules and don't use the default security group."
    },
    "CKV_AWS_138": {
        policy: "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled",
        severity: "LOW",
        fix: "Enable cross-zone load balancing for your AWS::ElasticLoadBalancing::LoadBalancer by setting the 'CrossZone' property to 'true'. This ensures that traffic is distributed evenly across all instances in all availability zones, improving availability and fault tolerance of your application."
    },
    "CKV_AWS_376": {
        policy: "AWS Elastic Load Balancer with listener TLS/SSL is not configured",
        severity: "LOW",
        fix: "Add a secure listener to your AWS::ElasticLoadBalancing::LoadBalancer by configuring 'Listeners' with 'Protocol: HTTPS' or 'Protocol: SSL', appropriate 'LoadBalancerPort', 'InstanceProtocol', 'InstancePort', and 'SSLCertificateId' pointing to your ACM or IAM certificate. This ensures encrypted communication between clients and your load balancer."
    },
    "CKV_AWS_196": {
        policy: "AWS Elasticache security groups are not defined",
        severity: "LOW",
        fix: "For AWS::ElastiCache::CacheCluster or AWS::ElastiCache::ReplicationGroup resources, specify the 'SecurityGroupIds' property with references to AWS::EC2::SecurityGroup resources that have appropriate ingress rules. This ensures that only authorized sources can connect to your ElastiCache cluster."
    },
    "CKV_AWS_137": {
        policy: "AWS Elasticsearch is not configured inside a VPC",
        severity: "LOW",
        fix: "Configure your AWS::Elasticsearch::Domain within a VPC by setting 'VPCOptions' with appropriate 'SubnetIds' and 'SecurityGroupIds'. Remove any 'AccessPolicies' that allow public access. This ensures your Elasticsearch domain is only accessible from within your VPC network, not from the public internet."
    },
    "CKV_AWS_248": {
        policy: "AWS Elasticsearch uses the default security group",
        severity: "LOW",
        fix: "Create a dedicated security group for your AWS::Elasticsearch::Domain with specific ingress/egress rules, then reference it in the 'VPCOptions.SecurityGroupIds' property instead of using the default security group. This follows the principle of least privilege and improves your security posture."
    },
    "CKV_AWS_213": {
        policy: "AWS ELB Policy uses some unsecure protocols",
        severity: "LOW",
        fix: "Create an AWS::ElasticLoadBalancing::LoadBalancerPolicy resource with secure SSL protocols and ciphers, then associate it with your load balancer. Set 'PolicyAttributes' to include only secure protocols (e.g., 'Protocol-TLSv1.2', 'Protocol-TLSv1.3') and strong ciphers, avoiding deprecated ones like SSLv3 or TLSv1.0."
    },
    "CKV2_AWS_74": {
        policy: "AWS Load Balancers do not use strong ciphers",
        severity: "LOW",
        fix: "For AWS::ElasticLoadBalancingV2::Listener resources with HTTPS protocol, set the 'SslPolicy' property to a policy that enforces strong ciphers, such as 'ELBSecurityPolicy-TLS-1-2-2017-01' or newer. This ensures that your load balancer only negotiates connections using strong encryption algorithms, protecting data in transit."
    },
    "CKV_AWS_230": {
        policy: "AWS NACL allows ingress from 0.0.0.0/0 to port 20",
        severity: "LOW",
        fix: "Modify your AWS::EC2::NetworkAclEntry for port 20 (FTP data) to restrict the 'CidrBlock' from '0.0.0.0/0' to specific IP ranges that need FTP access. If possible, completely remove public access to this port and use more secure file transfer methods. This prevents unauthorized FTP access attempts."
    },
    "CKV_AWS_229": {
        policy: "AWS NACL allows ingress from 0.0.0.0/0 to port 21",
        severity: "LOW",
        fix: "Modify your AWS::EC2::NetworkAclEntry for port 21 (FTP control) to restrict the 'CidrBlock' from '0.0.0.0/0' to specific IP ranges that need FTP access. If possible, completely remove public access to this port and use more secure file transfer methods like SFTP (port 22) with proper authentication."
    },
    "CKV_AWS_232": {
        policy: "AWS NACL allows ingress from 0.0.0.0/0 to port 22",
        severity: "LOW",
        fix: "Modify your AWS::EC2::NetworkAclEntry for port 22 (SSH) to restrict the 'CidrBlock' from '0.0.0.0/0' to specific IP ranges that need SSH access. For example, limit it to your company's IP range or VPN IP range. This prevents unauthorized SSH access attempts from the internet."
    },
    "CKV_AWS_231": {
        policy: "AWS NACL allows ingress from 0.0.0.0/0 to port 3389",
        severity: "LOW",
        fix: "Modify your AWS::EC2::NetworkAclEntry for port 3389 (RDP) to restrict the 'CidrBlock' from '0.0.0.0/0' to specific IP ranges that need RDP access. For example, limit it to your company's IP range or VPN IP range. This prevents unauthorized RDP access attempts from the internet."
    },
    "CKV2_AWS_35": {
        policy: "AWS NAT Gateways are not utilized for the default route",
        severity: "LOW",
        fix: "Configure private subnet route tables to use NAT Gateways for internet access by creating AWS::EC2::Route resources with 'DestinationCidrBlock: 0.0.0.0/0' and 'NatGatewayId' referencing your AWS::EC2::NatGateway resource. This provides secure outbound internet access for resources in private subnets without exposing them directly."
    },
    "CKV_AWS_198": {
        policy: "AWS RDS security groups are not defined",
        severity: "LOW",
        fix: "Specify security groups for your AWS::RDS::DBInstance or AWS::RDS::DBCluster by setting the 'VPCSecurityGroups' property to reference AWS::EC2::SecurityGroup resources with appropriate ingress rules. This ensures that only authorized network sources can connect to your database."
    },
    "CKV2_AWS_44": {
        policy: "AWS route table with VPC peering overly permissive to all traffic",
        severity: "LOW",
        fix: "When creating routes for VPC peering in AWS::EC2::Route resources, avoid using overly broad CIDR blocks like '0.0.0.0/0'. Instead, specify the exact CIDR range of the peered VPC in the 'DestinationCidrBlock' property. This limits traffic across the peering connection to only what's necessary."
    },
    "CKV_AWS_375": {
        policy: "AWS S3 bucket has global view ACL permissions enabled",
        severity: "LOW",
        fix: "Remove global view ACL permissions from your S3 bucket by setting 'PublicAccessBlockConfiguration' properties in your AWS::S3::Bucket resource: Set 'BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', and 'RestrictPublicBuckets' all to 'true'. This prevents any public access to your bucket contents."
    },
    "CKV_AWS_122": {
        policy: "AWS SageMaker notebook instance configured with direct internet access feature",
        severity: "LOW",
        fix: "Disable direct internet access for your AWS::SageMaker::NotebookInstance by setting the 'DirectInternetAccess' property to 'Disabled' and placing the notebook in a private subnet with a NAT Gateway for outbound access. This prevents the notebook from being directly accessible from the internet."
    },
    "CKV_AWS_382": {
        policy: "AWS Security Group allows unrestricted egress traffic",
        severity: "LOW",
        fix: "Remove the default '0.0.0.0/0' egress rule from your AWS::EC2::SecurityGroup and replace it with specific outbound rules that allow only necessary traffic. Define AWS::EC2::SecurityGroupEgress resources with specific 'CidrIp', 'IpProtocol', 'FromPort', and 'ToPort' values based on your application's requirements."
    },
    "CKV_AWS_260": {
        policy: "AWS security groups allow ingress from 0.0.0.0/0 to port 80",
        severity: "LOW",
        fix: "Modify your AWS::EC2::SecurityGroup ingress rules for port 80 (HTTP) to restrict the 'CidrIp' from '0.0.0.0/0' to specific IP ranges, or place resources behind a load balancer and only allow traffic from the load balancer's security group. For public web services, consider using CloudFront with WAF for added protection."
    },
    "CKV_AWS_380": {
        policy: "AWS Transfer Server not using latest Security Policy",
        severity: "LOW",
        fix: "Set the 'Protocols' property in your AWS::Transfer::Server resource to only include secure protocols ('SFTP', 'FTPS') and not 'FTP'. Additionally, set the 'SecurityPolicyName' property to the most recent security policy version (e.g., 'TransferSecurityPolicy-2020-06'). This ensures secure file transfers with up-to-date encryption."
    },
    "CKV_AWS_130": {
        policy: "AWS VPC subnets should not allow automatic public IP assignment",
        severity: "LOW",
        fix: "Set 'MapPublicIpOnLaunch' to 'false' in your AWS::EC2::Subnet resources, especially for subnets intended to host private resources. This prevents instances launched in these subnets from automatically receiving public IP addresses, reducing your public attack surface."
    },
    "CKV_AWS_175": {
        policy: "AWS WAF does not have associated rules",
        severity: "LOW",
        fix: "Add at least one rule to your AWS::WAFv2::WebACL by configuring the 'Rules' property with appropriate rule statements. At minimum, include AWS managed rule groups like 'AWSManagedRulesCommonRuleSet' to protect against common vulnerabilities, and consider adding custom rules specific to your application's security requirements."
    },
    "CKV_AWS_148": {
        policy: "Default VPC is planned to be provisioned",
        severity: "LOW",
        fix: "Avoid using the default VPC by explicitly creating custom AWS::EC2::VPC resources with appropriate CIDR blocks and security controls. If you must reference a VPC and don't specify one, use an explicit reference to an existing custom VPC instead of relying on the default VPC. This follows security best practices of using purpose-built networks."
    },
    "CKV_AWS_323": {
        policy: "ElastiCache cluster is using the default subnet group",
        severity: "LOW",
        fix: "Create a custom AWS::ElastiCache::SubnetGroup resource with appropriate private subnets, then reference it in your AWS::ElastiCache::CacheCluster or AWS::ElastiCache::ReplicationGroup resource using the 'CacheSubnetGroupName' property. This ensures your ElastiCache clusters are placed in properly secured and isolated subnets."
    },
    "CKV2_AWS_19": {
        policy: "Not all EIP addresses allocated to a VPC are attached to EC2 instances",
        severity: "LOW",
        fix: "Ensure all AWS::EC2::EIP resources are associated with instances or network interfaces by always including either the 'InstanceId' property or the 'NetworkInterfaceId' property. Unattached Elastic IPs incur costs without providing value, and should be properly attached or released."
    },
    "CKV_AWS_23": {
        policy: "Not every Security Group rule has a description",
        severity: "LOW",
        fix: "Add a descriptive 'Description' property to all ingress and egress rules in your AWS::EC2::SecurityGroup resources. The description should clearly explain the purpose of each rule, making it easier to audit security configurations and understand why specific ports or protocols are allowed."
    },
    "CKV_AWS_154": {
        policy: "Redshift is deployed outside of a VPC",
        severity: "LOW",
        fix: "Deploy your AWS::Redshift::Cluster within a VPC by specifying the 'ClusterSubnetGroupName' property referencing an AWS::Redshift::ClusterSubnetGroup resource that contains private subnet IDs. Additionally, set 'PubliclyAccessible' to 'false' to ensure the cluster is only accessible from within your VPC network."
    },
    "CKV_AWS_377": {
        policy: "Route 53 domains do not have transfer lock protection",
        severity: "LOW",
        fix: "Enable transfer lock protection for your Route 53 domains by setting 'TransferLock: true' in your AWS::Route53Domains::Domain resource. This prevents unauthorized domain transfers by requiring additional verification steps, protecting your domains from hijacking attempts."
    },
    "CKV2_AWS_6": {
        policy: "S3 Bucket does not have public access blocks",
        severity: "LOW",
        fix: "Add public access block configuration to your AWS::S3::Bucket by including the 'PublicAccessBlockConfiguration' property with all four settings ('BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', 'RestrictPublicBuckets') set to 'true'. This prevents any accidental public exposure of your bucket contents."
    },
    "CKV2_AWS_5": {
        policy: "Security Groups are not attached to EC2 instances or ENIs",
        severity: "LOW",
        fix: "Ensure all AWS::EC2::SecurityGroup resources are referenced by either AWS::EC2::Instance resources (in the 'SecurityGroupIds' property) or by AWS::EC2::NetworkInterface resources. Unused security groups increase complexity and can introduce security risks when modified later without understanding their impact."
    },
    "CKV_AWS_123": {
        policy: "VPC endpoint service is not configured for manual acceptance",
        severity: "LOW",
        fix: "Configure your AWS::EC2::VPCEndpointService to require manual acceptance by setting the 'AcceptanceRequired' property to 'true'. This ensures that you must explicitly approve each consumer VPC that attempts to create an endpoint to your service, preventing unauthorized access."
    },
    "CKV_AWS_152": {
        policy: "AWS Elastic Load Balancer v2 (ELBv2) with cross-zone load balancing disabled",
        severity: "INFO",
        fix: "Enable cross-zone load balancing for your AWS::ElasticLoadBalancingV2::LoadBalancer by setting a load balancer attribute with 'Key: load_balancing.cross_zone.enabled' and 'Value: true' in the 'LoadBalancerAttributes' property. This ensures traffic is distributed evenly across all instances in all availability zones."
    },
    "CKV2_AWS_1": {
        policy: "AWS Network ACL is not in use",
        severity: "INFO",
        fix: "Ensure all AWS::EC2::Subnet resources are associated with custom Network ACLs by creating AWS::EC2::NetworkAcl resources with appropriate rules, then creating AWS::EC2::SubnetNetworkAclAssociation resources to link them to your subnets. This provides an additional layer of network security beyond security groups."
    },
    "CKV_AWS_306": {
        policy: "AWS SageMaker notebook instance is not placed in VPC",
        severity: "INFO",
        fix: "Place your AWS::SageMaker::NotebookInstance within a VPC by specifying the 'SubnetId' property with a private subnet ID and including appropriate security group IDs in the 'SecurityGroupIds' property. This improves security by isolating the notebook instance within your private network."
    },
    "CKV_AWS_25": {
        policy: "AWS Security Group allows all traffic on RDP port (3389)",
        severity: "INFO",
        fix: "Modify your AWS::EC2::SecurityGroup ingress rules for port 3389 (RDP) to restrict the 'CidrIp' from '0.0.0.0/0' to specific IP ranges that require RDP access. Ideally, limit access to your corporate IP ranges or require users to connect through a bastion host or VPN. This prevents unauthorized RDP access attempts."
    },
    "CKV_AWS_24": {
        policy: "AWS Security Group allows all traffic on SSH port (22)",
        severity: "INFO",
        fix: "Modify your AWS::EC2::SecurityGroup ingress rules for port 22 (SSH) to restrict the 'CidrIp' from '0.0.0.0/0' to specific IP ranges that require SSH access. Ideally, limit access to your corporate IP ranges or require users to connect through a bastion host or VPN. This prevents unauthorized SSH access attempts."
    },
    // **** SERVERLESS POLICIES ****
    "CKV_AWS_173": {
        policy: "AWS Lambda encryption settings environmental variable is not set properly",
        severity: "LOW",
        fix: "When using environment variables in your AWS::Lambda::Function or AWS::Serverless::Function resource, add the 'KmsKeyArn' property with a valid KMS key ARN to encrypt these variables. Example: 'KmsKeyArn: arn:aws:kms:region:account-id:key/key-id'. This protects sensitive information stored in environment variables from unauthorized access, which is especially important for secrets, API keys, or connection strings."
    },
    "CKV_AWS_50": {
        policy: "AWS Lambda functions with tracing not enabled",
        severity: "LOW",
        fix: "Enable AWS X-Ray tracing for your Lambda function by adding the 'TracingConfig' property with 'Mode: Active' to your AWS::Lambda::Function resource. Example: \"TracingConfig\": { \"Mode\": \"Active\" }. This allows you to visualize and troubleshoot performance issues, errors, and latency by providing distributed tracing data for your serverless applications."
    },
    // **** SUPPLY CHAIN POLICIES ****
    "CKV_AWS_386": {
        policy: "Potential WhoAMI name confusion attack exposure",
        severity: "LOW",
        fix: "When using AWS::EC2::Image or custom AMI references in CloudFormation, always specify the exact AMI ID rather than using wildcards or generic names. If using AWS::ImageBuilder resources, explicitly specify trusted owners by their account IDs in the 'ImageRecipeVersion.Platform' or similar properties. For example, use 'ImageId: ami-0123456789abcdef0' with the complete AMI ID rather than relying on dynamic lookups with wildcards. This prevents attackers from exploiting name similarity to trick users into using malicious images that mimic trusted ones."
    },
    // **** ELASTICSEARCH POLICIES ****
    "CKV_AWS_6": {
        policy: "AWS Elasticsearch does not have node-to-node encryption enabled",
        severity: "MEDIUM",
        fix: "Enable node-to-node encryption in your AWS::Elasticsearch::Domain resource by adding the 'NodeToNodeEncryptionOptions' property with 'Enabled: true'. This ensures that data remains encrypted in-transit while being distributed and replicated between nodes in your Elasticsearch cluster, protecting against potential eavesdropping or man-in-the-middle attacks on your internal cluster traffic."
    },
    "CKV_AWS_83": {
        policy: "AWS Elasticsearch domain is not configured with HTTPS",
        severity: "MEDIUM",
        fix: "Configure your AWS::Elasticsearch::Domain resource to enforce HTTPS by adding the 'DomainEndpointOptions' property with 'EnforceHTTPS: true'. This ensures all communication between applications and your Elasticsearch domain occurs over encrypted channels, preventing potential interception of sensitive data and eliminating man-in-the-middle attack vectors."
    },
    "CKV_AWS_84": {
        policy: "AWS Elasticsearch domain logging is not enabled",
        severity: "MEDIUM",
        fix: "Enable logging for your AWS::Elasticsearch::Domain by configuring the 'LogPublishingOptions' property. At minimum, enable audit logs with: 'LogPublishingOptions: { AUDIT_LOGS: { Enabled: true, CloudWatchLogsLogGroupArn: !GetAtt ElasticsearchLogGroup.Arn } }'. You should also consider enabling INDEX_SLOW_LOGS, SEARCH_SLOW_LOGS, and ES_APPLICATION_LOGS. This helps with troubleshooting performance issues and provides audit trails for compliance requirements."
    },
    "CKV_AWS_5": {
        policy: "AWS Elasticsearch domain Encryption for data at rest is disabled",
        severity: "LOW",
        fix: "Enable encryption at rest for your AWS::Elasticsearch::Domain resource by adding the 'EncryptionAtRestOptions' property with 'Enabled: true'. Optionally, you can specify a KMS key with 'KmsKeyId: !Ref MyKmsKeyId'. This protects sensitive data stored in indices, logs, and snapshots from unauthorized access if the underlying storage is compromised."
    },
    // **** PUBLIC POLICIES ****
    "CKV_AWS_88": {
        policy: "AWS EC2 instances with public IP and associated with security groups have Internet access",
        severity: "HIGH",
        fix: "Remove public IP addressing from EC2 instances by setting 'AssociatePublicIpAddress: false' in the NetworkInterfaces property of your AWS::EC2::Instance or AWS::EC2::LaunchTemplate resources. For existing public-facing applications, consider using a load balancer or NAT gateway instead, keeping your EC2 instances in private subnets while still allowing necessary outbound internet access."
    },
    "CKV_AWS_32": {
        policy: "AWS Private ECR repository policy is overly permissive",
        severity: "MEDIUM",
        fix: "Modify the RepositoryPolicyText property in your AWS::ECR::Repository resource to avoid using wildcard principals (\"*\"). Instead, specify explicit AWS account IDs or IAM roles/users that need access to your repository. For example, replace \"Principal\": \"*\" with \"Principal\": { \"AWS\": [\"arn:aws:iam::123456789012:role/MyRole\"] }. This limits access to only authenticated and authorized entities."
    },
    "CKV_AWS_17": {
        policy: "AWS RDS database instance is publicly accessible",
        severity: "MEDIUM",
        fix: "Set the 'PubliclyAccessible' property to 'false' in your AWS::RDS::DBInstance resource. Additionally, place your RDS instance in a private subnet with appropriate security groups that restrict access to only necessary application servers. For access from outside the VPC, consider using a bastion host or VPN connection instead of making the database directly accessible from the internet."
    },
    "CKV_AWS_87": {
        policy: "AWS Redshift cluster instance with public access setting enabled",
        severity: "MEDIUM",
        fix: "Configure your AWS::Redshift::Cluster resource with 'PubliclyAccessible: false' to ensure the cluster is not directly accessible from the internet. Additionally, place the cluster in private subnets and configure security groups to only allow connections from authorized application servers or client networks."
    },
    "CKV_AWS_59": {
        policy: "AWS API gateway methods are publicly accessible",
        severity: "LOW",
        fix: "Secure your AWS::ApiGateway::Method resources by implementing one of these approaches: 1) Set 'AuthorizationType' to a value other than 'NONE' (such as 'AWS_IAM', 'COGNITO_USER_POOLS', or 'CUSTOM'), 2) Set 'ApiKeyRequired' to 'true', or 3) For OPTIONS methods used in CORS, you can keep 'AuthorizationType: NONE'. This ensures that all API methods require proper authentication or authorization before access is granted."
    },
    "CKV_AWS_89": {
        policy: "AWS DMS replication instance is publicly accessible",
        severity: "LOW",
        fix: "Set the 'PubliclyAccessible' property to 'false' in your AWS::DMS::ReplicationInstance resource. This ensures your Database Migration Service replication instance only has private IP addresses and is not accessible from the internet, reducing the attack surface of your migration infrastructure."
    },
    "CKV_AWS_69": {
        policy: "AWS MQ is publicly accessible",
        severity: "LOW",
        fix: "Configure your AWS::AmazonMQ::Broker resource with 'PubliclyAccessible: false' to ensure the message broker is only accessible from within your VPC. This prevents potential unauthorized access to your messaging infrastructure and protects sensitive data that might be transmitted through your message queues."
    },
    // **** S3 POLICIES ****
    "CKV_AWS_20": {
        policy: "AWS S3 bucket ACL grants READ permission to everyone",
        severity: "HIGH",
        fix: "Remove public read access from your S3 bucket by removing the 'AccessControl' property from your AWS::S3::Bucket resource or explicitly setting it to 'Private'. If using a separate AWS::S3::BucketPolicy resource, ensure it does not grant broad public read access. Never use 'PublicRead' or 'PublicReadWrite' access controls in production environments unless the bucket is specifically intended to host public web content."
    },
    "CKV_AWS_57": {
        policy: "AWS S3 Bucket has an ACL defined which allows public WRITE access",
        severity: "HIGH",
        fix: "Remove public write access from your S3 bucket by removing the 'AccessControl' property from your AWS::S3::Bucket resource or explicitly setting it to 'Private'. If the 'AccessControl' property is set to 'PublicReadWrite', change it to 'Private'. Public write access to S3 buckets poses a severe security risk as it allows anyone to add, modify, or delete content in your bucket."
    },
    "CKV_AWS_53": {
        policy: "AWS S3 Buckets has block public access setting disabled",
        severity: "MEDIUM",
        fix: "Enable the 'BlockPublicAcls' setting in your AWS::S3::Bucket resource by adding the 'PublicAccessBlockConfiguration' property with 'BlockPublicAcls: true'. This prevents new public ACLs from being applied to the bucket and its objects, reducing the risk of accidental public exposure of sensitive data. Example: \"PublicAccessBlockConfiguration\": { \"BlockPublicAcls\": true, ... }"
    },
    "CKV_AWS_54": {
        policy: "AWS S3 Bucket BlockPublicPolicy is not set to True",
        severity: "MEDIUM",
        fix: "Enable the 'BlockPublicPolicy' setting in your AWS::S3::Bucket resource by adding or updating the 'PublicAccessBlockConfiguration' property with 'BlockPublicPolicy: true'. This prevents the attachment of public bucket policies, providing an additional layer of protection against inadvertent public access. Example: \"PublicAccessBlockConfiguration\": { \"BlockPublicPolicy\": true, ... }"
    },
    "CKV_AWS_55": {
        policy: "AWS S3 bucket IgnorePublicAcls is not set to True",
        severity: "MEDIUM",
        fix: "Enable the 'IgnorePublicAcls' setting in your AWS::S3::Bucket resource by adding or updating the 'PublicAccessBlockConfiguration' property with 'IgnorePublicAcls: true'. This setting causes S3 to ignore all public ACLs on the bucket and its objects, effectively nullifying any existing public access granted via ACLs. Example: \"PublicAccessBlockConfiguration\": { \"IgnorePublicAcls\": true, ... }"
    },
    "CKV_AWS_56": {
        policy: "AWS S3 bucket RestrictPublicBucket is not set to True",
        severity: "MEDIUM",
        fix: "Enable the 'RestrictPublicBuckets' setting in your AWS::S3::Bucket resource by adding or updating the 'PublicAccessBlockConfiguration' property with 'RestrictPublicBuckets: true'. This restricts access to buckets with public policies to only AWS services and authorized users within the account. Example: \"PublicAccessBlockConfiguration\": { \"RestrictPublicBuckets\": true, ... }"
    },
    "CKV_AWS_70": {
        policy: "AWS S3 bucket policy overly permissive to any principal",
        severity: "MEDIUM",
        fix: "Revise your AWS::S3::BucketPolicy to avoid using wildcard principals like \"Principal\": \"*\" or \"Principal\": {\"AWS\": \"*\"}. Instead, explicitly specify the ARNs of IAM users, roles, or AWS accounts that need access. For example, replace \"Principal\": \"*\" with \"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:role/MyRole\"}. This prevents anonymous access and limits the bucket access to only authorized identities."
    },
    "CKV_AWS_93": {
        policy: "S3 bucket policy allows lockout all but root user",
        severity: "MEDIUM",
        fix: "Modify your AWS::S3::BucketPolicy to avoid overly restrictive deny statements that could lock out all users except the root user. If using broad deny statements with \"Effect\": \"Deny\" and \"Principal\": \"*\", ensure you include a condition that excludes specific IAM roles or users who need administrative access. Example: Add \"Condition\": {\"StringNotLike\": {\"aws:PrincipalArn\": [\"arn:aws:iam::123456789012:role/AdminRole\"]}}."
    },
    "CKV_AWS_19": {
        policy: "AWS S3 buckets do not have server side encryption",
        severity: "LOW",
        fix: "Enable server-side encryption for your S3 bucket by adding the 'BucketEncryption' property to your AWS::S3::Bucket resource with 'ServerSideEncryptionConfiguration' that specifies either 'AES256' or 'aws:kms' as the SSEAlgorithm. Example: \"BucketEncryption\": { \"ServerSideEncryptionConfiguration\": [{ \"ServerSideEncryptionByDefault\": { \"SSEAlgorithm\": \"AES256\" }}]}. This ensures all objects stored in the bucket are encrypted at rest."
    },
    "CKV_AWS_21": {
        policy: "AWS S3 Object Versioning is disabled",
        severity: "LOW",
        fix: "Enable object versioning for your S3 bucket by adding the 'VersioningConfiguration' property with 'Status: Enabled' to your AWS::S3::Bucket resource. Example: \"VersioningConfiguration\": { \"Status\": \"Enabled\" }. Versioning helps protect against accidental deletions and modifications by preserving multiple copies of objects, allowing you to recover previous versions if needed."
    },
    "CKV_AWS_18": {
        policy: "AWS Access logging not enabled on S3 buckets",
        severity: "INFO",
        fix: "Enable access logging for your S3 bucket by adding the 'LoggingConfiguration' property to your AWS::S3::Bucket resource, specifying a destination bucket and optional prefix. Example: \"LoggingConfiguration\": { \"DestinationBucketName\": \"my-log-bucket\", \"LogFilePrefix\": \"logs/\" }. Access logging provides detailed records of requests made to your bucket, which is useful for security audits, compliance verification, and troubleshooting."
    },
    // **** SECRETS POLICIES ****
    "CKV_AWS_41": {
        policy: "AWS access keys and secrets are hard coded in infrastructure",
        severity: "HIGH",
        fix: "Remove hardcoded AWS access keys and secret keys from the CloudFormation template. Replace direct credentials with CloudFormation parameters using NoEcho for security: \"Parameters: { MyAccessKey: { Type: String, NoEcho: true } }\" and reference them with \"!Ref MyAccessKey\" where needed."
    },
    "CKV_AWS_46": {
        policy: "EC2 user data exposes secrets",
        severity: "HIGH",
        fix: "Remove credentials and secrets from the UserData property of AWS::EC2::Instance resources. For AWS permissions, add an IAM instance profile instead: \"IamInstanceProfile: !Ref MyInstanceProfile\" where MyInstanceProfile is an AWS::IAM::InstanceProfile resource with appropriate permissions."
    },
    "CKV_AWS_45": {
        policy: "Lambda function's environment variables expose secrets",
        severity: "MEDIUM",
        fix: "Remove sensitive values from the Environment.Variables property of AWS::Lambda::Function resources. For AWS access, use the Lambda's execution role by setting the Role property to reference an AWS::IAM::Role with appropriate permissions. For other secrets, use AWS Systems Manager Parameter Store with secure references: \"MY_SECRET: '{{resolve:ssm-secure:/path/to/parameter:1}}'\"."
    }
};

export { CheckovPolicies, PolicyInfo };