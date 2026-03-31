import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT18 Rule: Discuss and implement a logging strategy. Then enable and configure IoT logging.
 * 
 * Documentation: "IoT logging is disabled by default. There should be good reasons to log specific information 
 * and people responsible for doing something with this information. 
 * See https://docs.aws.amazon.com/iot/latest/developerguide/configure-logging.html"
 */
export class IoT018Rule extends BaseRule {
  constructor() {
    super(
      'IOT-018',
      'HIGH',
      'IoT resources lack proper logging configuration',
      ['AWS::IoT::LoggingOptions', 'AWS::IoT::TopicRule']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check for IoT Logging Options
    if (resource.Type === 'AWS::IoT::LoggingOptions') {
      // Check if logging is properly configured
      if (!this.loggingOptionsProperlyConfigured(resource)) {
        const issueMessage = `${this.description} (logging options not properly configured)`;
        const fix = 'Configure IoT logging options with appropriate log level and role';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }



    // Check for IoT Topic Rules
    if (resource.Type === 'AWS::IoT::TopicRule') {
      // Check if the topic rule has logging actions
      if (!this.topicRuleHasLogging(resource, allResources)) {
        const issueMessage = `${this.description} (topic rule lacks logging configuration)`;
        const fix = 'Configure IoT topic rules to include logging actions for important events';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    return null;
  }

  /**
   * Check if IoT Logging Options are properly configured
   */
  private loggingOptionsProperlyConfigured(resource: CloudFormationResource): boolean {
    // Check if logging is enabled
    const logLevel = resource.Properties?.LogLevel;
    if (!logLevel || logLevel === 'DISABLED' || logLevel === 'NONE') {
      return false;
    }
    
    // Check if a role ARN is provided for logging
    const roleArn = resource.Properties?.RoleArn;
    if (!roleArn) {
      return false;
    }
    
    return true;
  }

  /**
   * Check if the log group is used for IoT logging
   */
  private isIoTLogGroup(resource: CloudFormationResource): boolean {
    const logGroupName = resource.Properties?.LogGroupName;
    if (!logGroupName) {
      return false;
    }
    
    // Handle CloudFormation intrinsic functions and references
    if (typeof logGroupName !== 'string') {
      // If it's a reference or intrinsic function, we can't determine if it's for IoT
      // So we'll assume it's not an IoT log group to avoid false positives
      return false;
    }
    
    // Check if the log group name indicates it's for IoT
    return logGroupName.includes('/aws/iot') || 
           logGroupName.includes('IoT') || 
           logGroupName.includes('iot');
  }

  /**
   * Check if the log group is properly configured
   */
  private logGroupProperlyConfigured(resource: CloudFormationResource): boolean {
    // Check if retention period is set
    const retentionInDays = resource.Properties?.RetentionInDays;
    if (!retentionInDays || retentionInDays < 7) {
      return false;
    }
    
    return true;
  }

  /**
   * Check if the IoT Topic Rule has logging actions
   */
  private topicRuleHasLogging(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    const actions = resource.Properties?.TopicRulePayload?.Actions;
    if (!actions || !Array.isArray(actions) || actions.length === 0) {
      return false;
    }
    
    // Check if any action is a CloudWatch Logs action
    const hasCloudWatchLogsAction = actions.some(action => 
      action.CloudwatchLogs !== undefined || 
      action.Firehose !== undefined || 
      action.IotAnalytics !== undefined
    );
    
    // Check if there's an error action
    const hasErrorAction = resource.Properties?.TopicRulePayload?.ErrorAction !== undefined;
    
    // If there's a direct logging action, return true
    if (hasCloudWatchLogsAction) {
      return true;
    }
    
    // If there's a Lambda action, check if the Lambda function logs to CloudWatch
    const hasLambdaAction = actions.some(action => action.Lambda !== undefined);
    if (hasLambdaAction && allResources) {
      // Extract Lambda function ARNs
      const lambdaFunctionArns = actions
        .filter(action => action.Lambda !== undefined)
        .map(action => action.Lambda.FunctionArn);
      
      // Check if any of the Lambda functions have logging configured
      return allResources.some(res => {
        if (res.Type === 'AWS::Lambda::Function') {
          const functionName = res.Properties?.FunctionName;
          
          // Handle CloudFormation intrinsic functions and references
          if (typeof functionName !== 'string') {
            // If it's a reference or intrinsic function, we can't determine the function name
            // So we'll check if any Lambda function ARN includes the logical ID
            return lambdaFunctionArns.some(arn => 
              typeof arn === 'string' && arn.includes(res.LogicalId)
            );
          }
          
          const functionArn = `arn:aws:lambda:${process.env.AWS_REGION || 'us-east-1'}:${process.env.AWS_ACCOUNT_ID || '123456789012'}:function:${functionName}`;
          
          // Check if this Lambda function is used in the topic rule
          return lambdaFunctionArns.some(arn => 
            typeof arn === 'string' && arn.includes(functionName)
          ) && 
                 // Check if the Lambda function has tracing enabled
                 (res.Properties?.TracingConfig?.Mode === 'Active' || 
                  // Or check if it has environment variables for logging
                  (res.Properties?.Environment?.Variables && 
                   Object.keys(res.Properties.Environment.Variables).some(key => 
                     key.includes('LOG') || key.includes('LOGGING')
                   )));
        }
        return false;
      });
    }
    
    // If there's an error action, that's better than nothing
    return hasErrorAction;
  }
}

export default new IoT018Rule();
