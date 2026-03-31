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

export const allRules = [
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
];
