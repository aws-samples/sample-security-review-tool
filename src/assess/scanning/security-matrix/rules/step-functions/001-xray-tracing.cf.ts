import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class StepFunctions001Rule extends BaseRule {
  constructor() {
    super(
      'SF-002',
      'MEDIUM',
      'Step Function lacks X-Ray tracing for service integrations',
      ['AWS::StepFunctions::StateMachine']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::StepFunctions::StateMachine') {
      // First check if the state machine has integrations with services that support X-Ray
      const hasXRaySupportedIntegrations = this.hasXRaySupportedIntegrations(resource);

      // Only require X-Ray tracing if the state machine integrates with services that support it
      if (hasXRaySupportedIntegrations) {
        const tracingConfig = resource.Properties?.TracingConfiguration;

        if (!tracingConfig) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Add TracingConfiguration property to enable X-Ray tracing for service integrations.`
          );
        }

        // Handle intrinsic functions in TracingConfiguration
        if (typeof tracingConfig === 'object' && !('Enabled' in tracingConfig)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Add TracingConfiguration property to enable X-Ray tracing for service integrations.`
          );
        }

        const tracingEnabled = tracingConfig.Enabled;

        if (tracingEnabled === false) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set TracingConfiguration.Enabled to true to enable X-Ray tracing for service integrations.`
          );
        } else if (tracingEnabled !== true) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set TracingConfiguration.Enabled to true to enable X-Ray tracing for service integrations.`
          );
        }
      }
    }

    return null;
  }

  /**
   * Checks if the state machine has integrations with services that support X-Ray tracing
   */
  private hasXRaySupportedIntegrations(resource: CloudFormationResource): boolean {
    const definition = resource.Properties?.Definition;

    if (!definition) return false;

    // Convert definition to string for analysis
    let definitionStr: string;
    if (typeof definition === 'string') {
      definitionStr = definition;
    } else if (typeof definition === 'object') {
      definitionStr = JSON.stringify(definition);
    } else {
      return false;
    }

    // Validated list of AWS services with native X-Ray integration
    const xraySupportedServices = [
      // Compute services
      'Lambda', 'lambda',
      'EC2', 'ec2',
      'ECS', 'ecs',
      'EKS', 'eks',
      'Fargate', 'fargate',
      'ElasticBeanstalk', 'elasticbeanstalk',
      'AppRunner', 'app-runner',

      // API & Integration
      'ApiGateway', 'api-gateway', 'apigateway',
      'AppMesh', 'app-mesh',
      'StepFunctions', 'step-functions',

      // Messaging & Events
      'SQS', 'sqs',
      'SNS', 'sns',
      'EventBridge', 'eventbridge',

      // Databases
      'DynamoDB', 'dynamodb',

      // Application Services
      'AppSync', 'appsync',

      // Load Balancing
      'ApplicationLoadBalancer', 'alb'
    ];

    return xraySupportedServices.some(service => definitionStr.includes(service));
  }

}

export default new StepFunctions001Rule();
