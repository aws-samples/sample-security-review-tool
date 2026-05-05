import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class CompLamb003Rule extends BaseRule {
  constructor() {
    super(
      'LAMBDA-003',
      'HIGH',
      'Lambda function has inappropriate timeout or memory configuration',
      ['AWS::Lambda::Function']
    );

    // Default thresholds
    this.minTimeout = 3;       // 3 seconds
    this.maxTimeout = 900;     // 15 minutes (900 seconds)
    this.minMemory = 128;      // 128 MB
    this.maxMemory = 3072;     // 3 GB

    // Thresholds for high-memory functions
    this.maxMemoryHighUsage = 10240; // 10 GB
  }

  // Threshold values
  private minTimeout: number;
  private maxTimeout: number;
  private minMemory: number;
  private maxMemory: number;
  private maxMemoryHighUsage: number;

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::Lambda::Function') {
      // Skip if Properties is missing
      if (!resource.Properties) {
        return null;
      }

      // Check timeout configuration
      const timeout = resource.Properties.Timeout;

      // Skip if timeout is a reference or intrinsic function
      if (timeout !== undefined && typeof timeout === 'number') {
        // Check if timeout is too high or too low
        if (timeout > this.maxTimeout || timeout < this.minTimeout) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Configure Timeout between ${this.minTimeout} and ${this.maxTimeout} seconds based on the function's expected execution time.`
          );
        }
      }

      // Check memory configuration
      const memorySize = resource.Properties.MemorySize;

      // Skip if memory is a reference or intrinsic function
      if (memorySize !== undefined && typeof memorySize === 'number') {
        // Determine the appropriate maximum memory based on function type
        const maxAllowedMemory = this.isHighMemoryFunction(resource)
          ? this.maxMemoryHighUsage
          : this.maxMemory;

        // Check if memory is too high or too low
        if (memorySize > maxAllowedMemory || memorySize < this.minMemory) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Configure MemorySize between ${this.minMemory} MB and ${maxAllowedMemory} MB based on the function's memory requirements.`
          );
        }
      }
    }

    return null;
  }

  private isHighMemoryFunction(resource: CloudFormationResource): boolean {
    // Check if this function might need high memory based on its name, handler, or runtime

    // Check function name
    const functionName = resource.Properties?.FunctionName;
    let functionNameStr = '';

    if (typeof functionName === 'string') {
      functionNameStr = functionName;
    } else if (typeof functionName === 'object' && functionName !== null) {
      // For intrinsic functions, check the logical ID instead
      functionNameStr = resource.LogicalId || '';
    } else {
      // If no function name, use logical ID
      functionNameStr = resource.LogicalId || '';
    }

    const highMemoryKeywords = [
      'image', 'video', 'audio', 'process', 'transform', 'convert', 'analyze',
      'ml', 'ai', 'inference', 'predict', 'train', 'model', 'batch', 'etl',
      'parallel', 'compute', 'intensive', 'heavy', 'large'
    ];

    if (highMemoryKeywords.some(keyword => functionNameStr.toLowerCase().includes(keyword))) {
      return true;
    }

    // Check handler
    const handler = resource.Properties?.Handler;
    const handlerStr = typeof handler === 'string' ? handler : '';

    if (highMemoryKeywords.some(keyword => handlerStr.toLowerCase().includes(keyword))) {
      return true;
    }

    // Check runtime for memory-intensive languages
    const runtime = resource.Properties?.Runtime;
    const runtimeStr = typeof runtime === 'string' ? runtime : '';

    // These runtimes often need more memory
    const highMemoryRuntimes = ['java', 'dotnet', 'go', 'python3.9', 'python3.10', 'python3.11'];

    if (highMemoryRuntimes.some(rt => runtimeStr.toLowerCase().includes(rt))) {
      return true;
    }

    return false;
  }
}

export default new CompLamb003Rule();
