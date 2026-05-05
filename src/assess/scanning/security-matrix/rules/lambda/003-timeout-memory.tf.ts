import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda003Rule extends BaseTerraformRule {
  private minTimeout = 3;
  private maxTimeout = 900;
  private minMemory = 128;
  private maxMemory = 3072;
  private maxMemoryHighUsage = 10240;

  constructor() {
    super(
      'LAMBDA-003',
      'HIGH',
      'Lambda function has inappropriate timeout or memory configuration',
      ['aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_lambda_function') return null;

    const timeout = resource.values?.timeout;
    if (timeout !== undefined && typeof timeout === 'number') {
      if (timeout > this.maxTimeout || timeout < this.minTimeout) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Configure timeout between ${this.minTimeout} and ${this.maxTimeout} seconds based on the function's expected execution time.`
        );
      }
    }

    const memorySize = resource.values?.memory_size;
    if (memorySize !== undefined && typeof memorySize === 'number') {
      const maxAllowedMemory = this.isHighMemoryFunction(resource) ? this.maxMemoryHighUsage : this.maxMemory;

      if (memorySize > maxAllowedMemory || memorySize < this.minMemory) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Configure memory_size between ${this.minMemory} MB and ${maxAllowedMemory} MB based on the function's memory requirements.`
        );
      }
    }

    return null;
  }

  private isHighMemoryFunction(resource: TerraformResource): boolean {
    const functionName = resource.values?.function_name || resource.name || '';
    const handler = resource.values?.handler || '';
    const runtime = resource.values?.runtime || '';

    const highMemoryKeywords = [
      'image', 'video', 'audio', 'process', 'transform', 'convert', 'analyze',
      'ml', 'ai', 'inference', 'predict', 'train', 'model', 'batch', 'etl'
    ];

    const combined = `${functionName} ${handler}`.toLowerCase();
    if (highMemoryKeywords.some(keyword => combined.includes(keyword))) {
      return true;
    }

    const highMemoryRuntimes = ['java', 'dotnet', 'go'];
    if (highMemoryRuntimes.some(rt => runtime.toLowerCase().includes(rt))) {
      return true;
    }

    return false;
  }
}

export default new TfLambda003Rule();
