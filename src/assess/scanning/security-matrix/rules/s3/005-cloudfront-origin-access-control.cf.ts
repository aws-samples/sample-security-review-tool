import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * S3-005: S3 buckets used as CloudFront origins must restrict access using OAC or OAI.
 *
 * Both Origin Access Control (OAC) and Origin Access Identity (OAI) prevent direct public
 * access to S3 buckets, ensuring objects can only be accessed through CloudFront.
 * OAC is the newer approach with additional features (SigV4, SSE-KMS support), but OAI
 * remains a valid security configuration for existing deployments.
 *
 * Detects OAC via OriginAccessControlId on the origin, and OAI via
 * S3OriginConfig.OriginAccessIdentity (string, Ref, Fn::Sub, Fn::Join).
 * Resolves origin-to-bucket references through Ref, Fn::GetAtt, Fn::Sub (string and
 * array forms), and Fn::Join.
 *
 * Only evaluates origins using S3OriginConfig. Origins using CustomOriginConfig (S3
 * website endpoints) are excluded because OAC/OAI cannot be applied to them.
 *
 * Bucket policy presence is not checked — the policy may be managed in a separate stack
 * or outside CloudFormation entirely. OAC/OAI on the origin is sufficient to pass.
 *
 * Known limitations:
 * - Hardcoded string DomainName values (e.g. "mybucket.s3.amazonaws.com") cannot be
 *   linked to S3 bucket resources in the template.
 * - Fn::Select, Fn::If, and Fn::ImportValue are not handled in reference resolution.
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
			'Configure Origin Access Control (OAC) for CloudFront distributions using this bucket.'
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
		return !!origin.S3OriginConfig;
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
		if (typeof sub === 'string') return sub.includes(`\${${logicalId}}`);
		if (Array.isArray(sub) && typeof sub[0] === 'string') return sub[0].includes(`\${${logicalId}}`);
		return false;
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
		return this.hasOriginAccessControl(template, bucketLogicalId) ||
			this.hasOriginAccessIdentity(template, bucketLogicalId);
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

	public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
		return null;
	}
}

export default new S3005Rule();
