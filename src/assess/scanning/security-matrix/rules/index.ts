import { ec2Rules } from './ec2/index.js';
import { ecrRules } from './ecr/index.js';
import { ecsRules } from './ecs/index.js';
import { efsRules } from './efs/index.js';
import { eksRules } from './eks/index.js';
import { elasticacheRules } from './elasticache/index.js';
import { fsxRules } from './fsx/index.js';
import { lambdaRules } from './lambda/index.js';
import { identityAccessRules } from './iam/index.js';
import { s3Rules } from './s3/index.js';
import { rdsRules } from './rds/index.js';
import { apiGatewayRules } from './api-gateway/index.js';
import { cloudfrontRules } from './cloudfront/index.js';
import { vpcConfigurationRules } from './vpc/index.js';
import { securityGroupRules } from './security-group/index.js';
import { dynamodbRules } from './dynamodb/index.js';
import { stepFunctionsRules } from './step-functions/index.js';
import { transitGatewayRules } from './transit-gateway/index.js';
import { networkManagerRules } from './network-manager/index.js';
import { networkFirewallRules } from './network-firewall/index.js';
import { iotRules } from './iot/index.js';
import { neptuneRules } from './neptune/index.js';
import { redshiftRules } from './redshift/index.js';
import { documentdbRules } from './documentdb/index.js';
import { timestreamRules } from './timestream/index.js';
import { dmsRules } from './dms/index.js';
import { sagemakerRules } from './sagemaker/index.js';
import { lexRules } from './lex/index.js';
import { openSearchRules } from './opensearch/index.js';
import { cognitoRules } from './cognito/index.js';
import { securityLakeRules } from './security-lake/index.js';
import { kmsRules } from './kms/index.js';
import { organizationsRules } from './organizations/index.js';
import { iamIdentityCenterRules } from './iam-identity-center/index.js';
import { athenaRules } from './athena/index.js';
import { emrRules } from './emr/index.js';
import { kinesisDataAnalyticsRules } from './kinesis-data-analytics/index.js';
import { kinesisDataFirehoseRules } from './kinesis-data-firehose/index.js';
import { quicksightRules } from './quicksight/index.js';
import { mskRules } from './msk/index.js';
import { elbRules } from './elastic-load-balancing/index.js';
import { elasticBeanstalkRules } from './elastic-beanstalk/index.js';
import { batchRules } from './batch/index.js';

import { mediastoreRules } from './mediastore/index.js';
import { mediapackageRules } from './mediapackage/index.js';
import { medialiveRules } from './medialive/index.js';
import { codebuildRules } from './codebuild/index.js';
import { codepipelineRules } from './codepipeline/index.js';
import { codedeployRules } from './codedeploy/index.js';
import { eventBridgeRules } from './event-bridge/index.js';

export const allCloudFormationRules = [
  ...ec2Rules,
  ...ecrRules,
  ...ecsRules,
  ...efsRules,
  ...eksRules,
  ...elasticacheRules,
  ...fsxRules,
  ...lambdaRules,
  ...iamIdentityCenterRules,
  ...identityAccessRules,
  ...iotRules,
  ...kmsRules,
  ...s3Rules,
  ...rdsRules,
  ...apiGatewayRules,
  ...cloudfrontRules,
  ...vpcConfigurationRules,
  ...securityGroupRules,
  ...dynamodbRules,
  ...cognitoRules,
  ...stepFunctionsRules,
  ...transitGatewayRules,
  ...networkFirewallRules,
  ...networkManagerRules,
  ...neptuneRules,
  ...openSearchRules,
  ...organizationsRules,
  ...redshiftRules,
  ...documentdbRules,
  ...timestreamRules,
  ...dmsRules,
  ...lexRules,
  ...sagemakerRules,
  ...securityLakeRules,
  ...athenaRules,
  ...emrRules,
  ...kinesisDataAnalyticsRules,
  ...kinesisDataFirehoseRules,
  ...quicksightRules,
  ...mskRules,
  ...elbRules,
  ...elasticBeanstalkRules,
  ...batchRules,

  ...mediastoreRules,
  ...mediapackageRules,
  ...medialiveRules,
  ...codebuildRules,
  ...codepipelineRules,
  ...codedeployRules,
  ...eventBridgeRules,
];

import { BaseTerraformRule } from '../terraform-rule-base.js';
import { tfEc2Rules } from './ec2/index.js';
import { tfEcrRules } from './ecr/index.js';
import { tfEcsRules } from './ecs/index.js';
import { tfEfsRules } from './efs/index.js';
import { tfEksRules } from './eks/index.js';
import { tfElasticacheRules } from './elasticache/index.js';
import { tfFsxRules } from './fsx/index.js';
import { tfLambdaRules } from './lambda/index.js';
import { tfIamRules } from './iam/index.js';
import { tfS3Rules } from './s3/index.js';
import { tfRdsRules } from './rds/index.js';
import { tfApiGatewayRules } from './api-gateway/index.js';
import { tfCloudfrontRules } from './cloudfront/index.js';
import { tfVpcRules } from './vpc/index.js';
import { tfSecurityGroupRules } from './security-group/index.js';
import { tfDynamodbRules } from './dynamodb/index.js';
import { tfStepFunctionsRules } from './step-functions/index.js';
import { tfTransitGatewayRules } from './transit-gateway/index.js';
import { tfNetworkManagerRules } from './network-manager/index.js';
import { tfNetworkFirewallRules } from './network-firewall/index.js';
import { tfIotRules } from './iot/index.js';
import { tfNeptuneRules } from './neptune/index.js';
import { tfRedshiftRules } from './redshift/index.js';
import { tfDocumentdbRules } from './documentdb/index.js';
import { tfTimestreamRules } from './timestream/index.js';
import { tfDmsRules } from './dms/index.js';
import { tfSagemakerRules } from './sagemaker/index.js';
import { tfLexRules } from './lex/index.js';
import { tfOpensearchRules } from './opensearch/index.js';
import { tfCognitoRules } from './cognito/index.js';
import { tfSecurityLakeRules } from './security-lake/index.js';
import { tfKmsRules } from './kms/index.js';
import { tfOrganizationsRules } from './organizations/index.js';
import { tfIamIdentityCenterRules } from './iam-identity-center/index.js';
import { tfAthenaRules } from './athena/index.js';
import { tfEmrRules } from './emr/index.js';
import { tfKinesisDataAnalyticsRules } from './kinesis-data-analytics/index.js';
import { tfKinesisDataFirehoseRules } from './kinesis-data-firehose/index.js';
import { tfQuicksightRules } from './quicksight/index.js';
import { tfMskRules } from './msk/index.js';
import { tfElbRules } from './elastic-load-balancing/index.js';
import { tfElasticBeanstalkRules } from './elastic-beanstalk/index.js';
import { tfBatchRules } from './batch/index.js';
import { tfMediastoreRules } from './mediastore/index.js';
import { tfMediapackageRules } from './mediapackage/index.js';
import { tfMedialiveRules } from './medialive/index.js';
import { tfCodebuildRules } from './codebuild/index.js';
import { tfCodepipelineRules } from './codepipeline/index.js';
import { tfCodedeployRules } from './codedeploy/index.js';
import { tfEventBridgeRules } from './event-bridge/index.js';
import { tfAutoscalingRules } from './autoscaling/index.js';
import { tfSecretsManagementRules } from './secrets-management/index.js';
import { tfSnsRules } from './sns/index.js';
import { tfSqsRules } from './sqs/index.js';
import { tfSsmRules } from './ssm/index.js';

export const allTerraformRules: BaseTerraformRule[] = [
  ...tfEc2Rules,
  ...tfEcrRules,
  ...tfEcsRules,
  ...tfEfsRules,
  ...tfEksRules,
  ...tfElasticacheRules,
  ...tfFsxRules,
  ...tfLambdaRules,
  ...tfIamIdentityCenterRules,
  ...tfIamRules,
  ...tfIotRules,
  ...tfKmsRules,
  ...tfS3Rules,
  ...tfRdsRules,
  ...tfApiGatewayRules,
  ...tfCloudfrontRules,
  ...tfVpcRules,
  ...tfSecurityGroupRules,
  ...tfDynamodbRules,
  ...tfCognitoRules,
  ...tfStepFunctionsRules,
  ...tfTransitGatewayRules,
  ...tfNetworkFirewallRules,
  ...tfNetworkManagerRules,
  ...tfNeptuneRules,
  ...tfOpensearchRules,
  ...tfOrganizationsRules,
  ...tfRedshiftRules,
  ...tfDocumentdbRules,
  ...tfTimestreamRules,
  ...tfDmsRules,
  ...tfLexRules,
  ...tfSagemakerRules,
  ...tfSecurityLakeRules,
  ...tfAthenaRules,
  ...tfEmrRules,
  ...tfKinesisDataAnalyticsRules,
  ...tfKinesisDataFirehoseRules,
  ...tfQuicksightRules,
  ...tfMskRules,
  ...tfElbRules,
  ...tfElasticBeanstalkRules,
  ...tfBatchRules,
  ...tfMediastoreRules,
  ...tfMediapackageRules,
  ...tfMedialiveRules,
  ...tfCodebuildRules,
  ...tfCodepipelineRules,
  ...tfCodedeployRules,
  ...tfEventBridgeRules,
  ...tfAutoscalingRules,
  ...tfSecretsManagementRules,
  ...tfSnsRules,
  ...tfSqsRules,
  ...tfSsmRules,
];
