import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { aws_codebuild as codebuild, aws_iam as iam } from 'aws-cdk-lib';

/**
 * Fixture for CODEBUILD-009.
 *
 * CODEBUILD-009 has a single finding: MISSING_BUCKET_INSPECTION_PERMISSIONS.
 * It fires whenever a CodeBuild project is associated with an S3 bucket
 * (via Source, Artifacts, or S3 build logs) and the project's service role
 * does not effectively allow BOTH s3:GetBucketAcl and s3:GetBucketLocation
 * on that bucket (either because the permission is entirely missing, or
 * because it is granted but then overridden by an explicit Deny).
 *
 * Each project below reaches the finding via a different code path in the
 * adapter, using a service role whose permissions are deliberately
 * insufficient. All S3 locations and role/policy relationships are literal
 * strings or intrinsics (Ref/GetAtt to in-template logical IDs) so they
 * remain statically resolvable after CloudFormation preprocessing.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const assumeRolePolicyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'codebuild.amazonaws.com' },
          Action: 'sts:AssumeRole',
        },
      ],
    };

    // --- Case 1: S3 Source, service role has NO relevant permissions at all ---
    const roleNoPerms = new iam.CfnRole(this, 'RoleNoPerms', {
      assumeRolePolicyDocument,
    });

    new codebuild.CfnProject(this, 'ProjectS3SourceNoPerms', {
      serviceRole: roleNoPerms.attrArn,
      source: {
        type: 'S3',
        location: 'my-source-bucket/source.zip',
      },
      artifacts: { type: 'NO_ARTIFACTS' },
      environment: {
        type: 'LINUX_CONTAINER',
        computeType: 'BUILD_GENERAL1_SMALL',
        image: 'aws/codebuild/standard:6.0',
      },
    });

    // --- Case 2: S3 Artifacts, service role has both actions allowed but one
    // is explicitly denied by another statement, so it is not effectively granted ---
    const roleDenied = new iam.CfnRole(this, 'RoleDenied', {
      assumeRolePolicyDocument,
      policies: [
        {
          policyName: 'AllowThenDenyBucketPerms',
          policyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
                Resource: 'arn:aws:s3:::my-artifact-bucket',
              },
              {
                Effect: 'Deny',
                Action: 's3:GetBucketLocation',
                Resource: 'arn:aws:s3:::my-artifact-bucket',
              },
            ],
          },
        },
      ],
    });

    new codebuild.CfnProject(this, 'ProjectS3ArtifactsDenied', {
      serviceRole: roleDenied.attrArn,
      source: { type: 'NO_SOURCE' },
      artifacts: {
        type: 'S3',
        location: 'my-artifact-bucket',
      },
      environment: {
        type: 'LINUX_CONTAINER',
        computeType: 'BUILD_GENERAL1_SMALL',
        image: 'aws/codebuild/standard:6.0',
      },
    });

    // --- Case 3: S3 build logs, service role (via an attached AWS::IAM::Policy)
    // only has s3:GetBucketAcl, missing s3:GetBucketLocation ---
    const rolePartial = new iam.CfnRole(this, 'RolePartialPerms', {
      assumeRolePolicyDocument,
    });

    new iam.CfnPolicy(this, 'PartialPermsPolicy', {
      policyName: 'OnlyGetBucketAcl',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 's3:GetBucketAcl',
            Resource: 'arn:aws:s3:::my-logs-bucket',
          },
        ],
      },
      roles: [rolePartial.ref],
    });

    new codebuild.CfnProject(this, 'ProjectS3LogsPartialPerms', {
      serviceRole: rolePartial.attrArn,
      source: { type: 'NO_SOURCE' },
      artifacts: { type: 'NO_ARTIFACTS' },
      logsConfig: {
        s3Logs: {
          status: 'ENABLED',
          location: 'my-logs-bucket/build-log',
        },
      },
      environment: {
        type: 'LINUX_CONTAINER',
        computeType: 'BUILD_GENERAL1_SMALL',
        image: 'aws/codebuild/standard:6.0',
      },
    });
  }
}
