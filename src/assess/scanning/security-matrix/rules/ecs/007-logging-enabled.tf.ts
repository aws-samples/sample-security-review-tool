import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEcs007Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ECS-007',
      'HIGH',
      'ECS task may not have logging enabled',
      ['aws_ecs_task_definition']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_ecs_task_definition') return null;

    const containerDefinitions = resource.values?.container_definitions;
    if (!containerDefinitions || typeof containerDefinitions !== 'string') return null;

    try {
      const containers = JSON.parse(containerDefinitions);
      if (!Array.isArray(containers) || containers.length === 0) return null;

      for (const container of containers) {
        const logConfiguration = container.logConfiguration;

        if (!logConfiguration) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Configure logConfiguration for each container in the task definition.'
          );
        }

        const logDriver = logConfiguration.logDriver;
        if (!logDriver) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Specify a logDriver in the logConfiguration for each container.'
          );
        }

        if (logDriver !== 'awslogs') {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            "Use 'awslogs' as the logDriver for CloudWatch Logs integration, which is the recommended logging solution for ECS."
          );
        }

        const options = logConfiguration.options;
        if (!options) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            'Configure options for the awslogs logDriver, including awslogs-group, awslogs-region, and awslogs-stream-prefix.'
          );
        }

        if (!options['awslogs-group']) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            "Specify 'awslogs-group' in the logConfiguration options to define the CloudWatch Logs group."
          );
        }

        if (!options['awslogs-region']) {
          return this.createScanResult(
            resource,
            projectName,
            this.description,
            "Specify 'awslogs-region' in the logConfiguration options to define the AWS region for CloudWatch Logs."
          );
        }
      }
    } catch {
      return null;
    }

    return null;
  }
}

export default new TfEcs007Rule();
