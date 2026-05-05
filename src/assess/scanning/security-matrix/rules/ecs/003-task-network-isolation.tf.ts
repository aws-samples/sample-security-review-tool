import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEcs003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ECS-003',
      'HIGH',
      'ECS task definition uses insecure network configuration',
      ['aws_ecs_task_definition']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_ecs_task_definition') return null;

    const networkMode = resource.values?.network_mode;
    if (networkMode !== 'awsvpc') {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        "Set network_mode = \"awsvpc\" for task definitions to isolate container networking."
      );
    }

    const containerDefinitions = resource.values?.container_definitions;
    if (!containerDefinitions || typeof containerDefinitions !== 'string') return null;

    try {
      const containers = JSON.parse(containerDefinitions);
      if (!Array.isArray(containers)) return null;

      for (const container of containers) {
        const portMappings = container.portMappings;
        if (Array.isArray(portMappings)) {
          for (const mapping of portMappings) {
            if (mapping.hostPort && mapping.hostPort !== 0) {
              return this.createScanResult(
                resource,
                projectName,
                this.description,
                'Use dynamic port mapping by omitting hostPort or setting it to 0 to allow the container to use ephemeral ports.'
              );
            }
          }
        }
      }
    } catch {
      return null;
    }

    return null;
  }
}

export default new TfEcs003Rule();
