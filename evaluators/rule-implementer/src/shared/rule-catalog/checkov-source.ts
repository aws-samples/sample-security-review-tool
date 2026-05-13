import * as path from 'node:path';
import { CheckovPolicies } from '../../../../../src/assess/scanning/checkov/checkov_fixes.js';
import type { RuleEntry } from '../types/rule-catalog.js';
import { sha256OfFile } from './hash.js';

const SCANNER = 'checkov' as const;

export function loadCheckovRules(srtRepoRoot: string): RuleEntry[] {
    const sourceFile = path.join(srtRepoRoot, 'src', 'assess', 'scanning', 'checkov', 'checkov_fixes.ts');
    const sourceHash = sha256OfFile(sourceFile);

    return Object.entries(CheckovPolicies)
        .filter(([checkId]) => checkId !== 'N/A')
        .map(([checkId, policy]) => ({
            checkId,
            scanner: SCANNER,
            service: inferServiceFromPolicy(policy.policy),
            priority: normalizePriority(policy.severity),
            description: policy.policy,
            fixGuidance: policy.fix,
            sourceLocation: sourceFile,
            sourceHash,
            applicableFormats: ['cfn', 'cdk'],
        }));
}

function normalizePriority(severity: string): 'HIGH' | 'MEDIUM' | 'LOW' {
    const upper = severity.toUpperCase();
    if (upper === 'CRITICAL' || upper === 'HIGH') return 'HIGH';
    if (upper === 'MEDIUM') return 'MEDIUM';
    return 'LOW';
}

function inferServiceFromPolicy(policyText: string): string | undefined {
    // Policies read like "AWS <Service> ...". Longest alternatives first to avoid shadowing.
    const match = policyText.match(/\b(Elastic Beanstalk|Elastic Load Balancer|Elastic Load Balancers|Elasticsearch|ElastiCache|API Gateway|CloudFormation|CloudFront|CloudTrail|CloudWatch|DocumentDB|DocDB|DynamoDB|EventBridge|OpenSearch|Route53|SageMaker|SecretsManager|Secrets Manager|StepFunctions|Step Functions|Transfer Family|DataSync|CodeBuild|CodePipeline|CodeDeploy|MediaStore|MediaPackage|MediaLive|QuickSight|TimeStream|Neptune|Cognito|Redshift|AppSync|Athena|Batch|Glue|Kinesis|Lambda|Load Balancer|Networking|Network Firewall|S3|RDS|EC2|EBS|EFS|EKS|ECS|ECR|EMR|SNS|SQS|IAM|KMS|MSK|WAF|VPC|SSM|DMS|MQ|ACM|ECR)\b/i);
    if (!match) return undefined;
    const normalized = match[1].toLowerCase().replace(/\s+/g, '-');
    if (normalized === 'docdb') return 'documentdb';
    if (normalized === 'elastic-load-balancers' || normalized === 'load-balancer') return 'elastic-load-balancer';
    return normalized;
}
