import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * S3-005: S3 buckets used as CloudFront origins must restrict access using OAC or OAI.
 *
 * Both Origin Access Control (OAC) and Origin Access Identity (OAI) prevent direct public
 * access to S3 buckets, ensuring objects can only be accessed through CloudFront.
 *
 * OAC is the newer approach with additional features (SigV4, SSE-KMS support), but OAI
 * remains a valid security configuration for existing deployments.
 */
export class S3005Rule extends BaseRule {
	constructor() {
		super(
			'S3-005',
			'HIGH',
			'S3 bucket used as CloudFront origin lacks access restriction (OAC or OAI)',
			['AWS::S3::Bucket']
		);
	}

	public override evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
		if (!this.appliesTo(resource.Type)) return null;

		const bucketLogicalId = this.findResourceLogicalId(template, resource);
		if (!bucketLogicalId) return null;

		if (!this.isUsedAsCloudFrontOrigin(template, bucketLogicalId)) return null;

		if (this.hasValidAccessRestriction(template, bucketLogicalId)) return null;

		return this.createResult(
			stackName,
			template,
			resource,
			this.description,
			'Configure Origin Access Control (OAC) or Origin Access Identity (OAI) for CloudFront distributions using this bucket, and update bucket policy to restrict access.'
		);
	}

	private findResourceLogicalId(template: Template, resource: Resource): string | undefined {
		return Object.keys(template.Resources || {}).find(
			key => template.Resources![key] === resource
		);
	}

	private isUsedAsCloudFrontOrigin(template: Template, bucketLogicalId: string): boolean {
		for (const resource of Object.values(template.Resources || {})) {
			if (resource.Type !== 'AWS::CloudFront::Distribution') continue;

			const origins = resource.Properties?.DistributionConfig?.Origins;
			if (!Array.isArray(origins)) continue;

			for (const origin of origins) {
				if (this.isS3Origin(origin) && this.originReferencesBucket(origin, bucketLogicalId)) {
					return true;
				}
			}
		}
		return false;
	}

	private isS3Origin(origin: any): boolean {
		if (origin.S3OriginConfig) return true;

		if (origin.CustomOriginConfig && origin.DomainName) {
			return this.isS3DomainName(origin.DomainName);
		}
		return false;
	}

	private isS3DomainName(domainName: any): boolean {
		if (typeof domainName === 'string') {
			return this.isS3WebsiteEndpoint(domainName);
		}
		return this.referencesS3Attribute(domainName);
	}

	private isS3WebsiteEndpoint(domain: string): boolean {
		return domain.includes('.s3-website-') ||
			domain.includes('.s3-website.') ||
			domain.endsWith('.s3.amazonaws.com') ||
			(domain.includes('.s3.') && domain.includes('.amazonaws.com'));
	}

	private referencesS3Attribute(domainName: any): boolean {
		if (typeof domainName !== 'object' || !domainName['Fn::GetAtt']) return false;

		const getAtt = domainName['Fn::GetAtt'];
		if (!Array.isArray(getAtt) || getAtt.length < 2) return false;

		const attribute = getAtt[1];
		return attribute === 'WebsiteURL' || attribute === 'DomainName' || attribute === 'RegionalDomainName';
	}

	private originReferencesBucket(origin: any, bucketLogicalId: string): boolean {
		const domainName = origin.DomainName;
		if (typeof domainName === 'string') return false;

		return this.isRefTo(domainName, bucketLogicalId) ||
			this.isGetAttFrom(domainName, bucketLogicalId) ||
			this.isSubReferencing(domainName, bucketLogicalId) ||
			this.isJoinReferencing(domainName, bucketLogicalId);
	}

	private isRefTo(value: any, logicalId: string): boolean {
		return typeof value === 'object' && value.Ref === logicalId;
	}

	private isGetAttFrom(value: any, logicalId: string): boolean {
		if (typeof value !== 'object' || !value['Fn::GetAtt']) return false;
		const getAtt = value['Fn::GetAtt'];
		return Array.isArray(getAtt) && getAtt[0] === logicalId;
	}

	private isSubReferencing(value: any, logicalId: string): boolean {
		if (typeof value !== 'object' || !value['Fn::Sub']) return false;
		const sub = value['Fn::Sub'];
		return typeof sub === 'string' && sub.includes(`\${${logicalId}}`);
	}

	private isJoinReferencing(value: any, logicalId: string): boolean {
		if (typeof value !== 'object' || !value['Fn::Join']) return false;

		const join = value['Fn::Join'];
		if (!Array.isArray(join) || !Array.isArray(join[1])) return false;

		return join[1].some((part: any) =>
			this.isRefTo(part, logicalId) || this.isGetAttFrom(part, logicalId)
		);
	}

	private hasValidAccessRestriction(template: Template, bucketLogicalId: string): boolean {
		const hasOAC = this.hasOriginAccessControl(template, bucketLogicalId);
		const hasOAI = this.hasOriginAccessIdentity(template, bucketLogicalId);

		if (!hasOAC && !hasOAI) return false;

		return this.hasBucketPolicyForCloudFront(template, bucketLogicalId, hasOAC);
	}

	private hasOriginAccessControl(template: Template, bucketLogicalId: string): boolean {
		for (const resource of Object.values(template.Resources || {})) {
			if (resource.Type !== 'AWS::CloudFront::Distribution') continue;

			const origins = resource.Properties?.DistributionConfig?.Origins;
			if (!Array.isArray(origins)) continue;

			for (const origin of origins) {
				if (!this.isS3Origin(origin) || !this.originReferencesBucket(origin, bucketLogicalId)) continue;
				if (origin.OriginAccessControlId) return true;
			}
		}
		return false;
	}

	private hasOriginAccessIdentity(template: Template, bucketLogicalId: string): boolean {
		for (const resource of Object.values(template.Resources || {})) {
			if (resource.Type !== 'AWS::CloudFront::Distribution') continue;

			const origins = resource.Properties?.DistributionConfig?.Origins;
			if (!Array.isArray(origins)) continue;

			for (const origin of origins) {
				if (!this.isS3Origin(origin) || !this.originReferencesBucket(origin, bucketLogicalId)) continue;
				if (this.hasOAIConfigured(origin)) return true;
			}
		}
		return false;
	}

	private hasOAIConfigured(origin: any): boolean {
		const s3Config = origin.S3OriginConfig;
		if (!s3Config) return false;

		const oai = s3Config.OriginAccessIdentity;
		if (!oai) return false;

		if (typeof oai === 'string') {
			return oai.includes('origin-access-identity/cloudfront/');
		}

		return typeof oai === 'object' && (oai['Fn::Join'] || oai['Fn::Sub'] || oai.Ref);
	}

	private hasBucketPolicyForCloudFront(template: Template, bucketLogicalId: string, isOAC: boolean): boolean {
		for (const resource of Object.values(template.Resources || {})) {
			if (resource.Type !== 'AWS::S3::BucketPolicy') continue;
			if (!this.policyTargetsBucket(resource.Properties?.Bucket, bucketLogicalId)) continue;

			const statements = this.extractStatements(resource.Properties?.PolicyDocument);

			for (const statement of statements) {
				if (statement.Effect !== 'Allow') continue;
				if (isOAC && this.isCloudFrontServicePolicy(statement)) return true;
				if (!isOAC && this.isOAICanonicalUserPolicy(statement)) return true;
			}
		}
		return false;
	}

	private policyTargetsBucket(bucketRef: any, bucketLogicalId: string): boolean {
		if (typeof bucketRef === 'string') return bucketRef === bucketLogicalId;
		return this.isRefTo(bucketRef, bucketLogicalId);
	}

	private extractStatements(policyDocument: any): any[] {
		if (!policyDocument?.Statement) return [];
		return Array.isArray(policyDocument.Statement) ? policyDocument.Statement : [policyDocument.Statement];
	}

	private isCloudFrontServicePolicy(statement: any): boolean {
		const principal = statement.Principal;
		if (!principal) return false;

		if (principal.Service === 'cloudfront.amazonaws.com') return true;
		if (Array.isArray(principal.Service) && principal.Service.includes('cloudfront.amazonaws.com')) return true;

		return this.hasCloudFrontSourceArnCondition(statement.Condition);
	}

	private isOAICanonicalUserPolicy(statement: any): boolean {
		const principal = statement.Principal;
		if (!principal) return false;

		if (principal.CanonicalUser) return true;
		return false;
	}

	private hasCloudFrontSourceArnCondition(condition: any): boolean {
		if (!condition?.StringEquals) return false;

		const sourceArn = condition.StringEquals['aws:SourceArn'] || condition.StringEquals['AWS:SourceArn'];
		if (!sourceArn) return false;

		if (typeof sourceArn === 'string') return sourceArn.includes('cloudfront');
		if (Array.isArray(sourceArn)) return sourceArn.some((arn: string) => arn.includes('cloudfront'));

		return false;
	}

	public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
		return null;
	}
}

export default new S3005Rule();
