import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

export class CompLamb011Rule extends BaseRule {	
	constructor() {
		super(
			'LAMBDA-011',
			'HIGH',
			'Lambda function lacks CloudWatch alarms for monitoring',
			['AWS::Lambda::Function', 'AWS::CloudWatch::Alarm']
		);

		// Define important Lambda metrics that should be monitored
		this.importantMetrics = [
			'Errors',
			'Throttles',
			'Duration',
			'Invocations',
			'ConcurrentExecutions',
			'DeadLetterErrors'
		];
	}

	// List of important Lambda metrics to monitor
	private importantMetrics: string[];

	public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null | undefined {
		if (resource.Type !== 'AWS::Lambda::Function') return null;

		const lambdaLogicalId = this.getLambdaLogicalId(template, resource);
		if (!lambdaLogicalId) return null;

		const hasAlarms = this.findLambdaAlarms(template, lambdaLogicalId);
		
		if (hasAlarms) return null;

		return this.createResult(
			stackName,
			template,
			resource,
			this.description,
			`Create CloudWatch alarms for the following Lambda metrics: ${this.importantMetrics.join(',')}. Configure alarm actions (e.g., SNS notifications) to assign an owner who will monitor and respond to incidents.`
		);
	}

	private getLambdaLogicalId(template: Template, resource: Resource): string | null {
		if (!template.Resources) return null;
		
		for (const [logicalId, templateResource] of Object.entries(template.Resources)) {
			if (templateResource === resource) return logicalId;
		}

		return null;
	}

	private findLambdaAlarms(template: Template, lambdaLogicalId: string): boolean {
		if (!template.Resources) return false;

		for (const [resourceId, resource] of Object.entries(template.Resources)) {
			if (resource.Type !== 'AWS::CloudWatch::Alarm') continue;
			
			const properties = resource.Properties;
			if (!properties) continue;

			const namespace = properties.Namespace;
			if (namespace !== 'AWS/Lambda') continue;

			const dimensions = properties.Dimensions;
			if (!dimensions || !Array.isArray(dimensions)) continue;

			const functionDimension = dimensions.find((dim: any) =>
				dim.Name === 'FunctionName' && dim.Value
			);

			if (!functionDimension) continue;

			if (this.isLambdaReference(functionDimension.Value, lambdaLogicalId)) return true;
		}

		return false;
	}

	private isLambdaReference(dimensionValue: any, lambdaLogicalId: string): boolean {
		if (typeof dimensionValue === 'string') {
			return dimensionValue === lambdaLogicalId || dimensionValue === 'DEFAULT';
		}

		if (typeof dimensionValue === 'object') {
			if (dimensionValue.Ref && dimensionValue.Ref === lambdaLogicalId) return true;

			if (dimensionValue['Fn::GetAtt'] && Array.isArray(dimensionValue['Fn::GetAtt'])) {
				const referencedLogicalId = dimensionValue['Fn::GetAtt'][0];
				return referencedLogicalId === lambdaLogicalId;
			}
		}

		return false;
	}

	public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
		return null;
	}
}

export default new CompLamb011Rule();
