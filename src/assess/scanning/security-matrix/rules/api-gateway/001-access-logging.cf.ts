import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG1 Rule: Enable access logging on API Gateway endpoints with explicit retention period
 * 
 * Documentation: "Enable access logging on API Gateway endpoints. Make sure the log has an explicit 
 * retention period (default is unlimited) and automatic deletion activated in accordance with the 
 * customer's data retention expectations."
 * 
 * Note: Basic API Gateway logging check is covered by Checkov rule CKV_AWS_120, which verifies that
 * logging is enabled. This rule extends that functionality by also checking for explicit log retention
 * periods, which is not covered by the Checkov rule.
 */
export class ApiGw001Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-001',
      'HIGH',
      'API Gateway does not have access logging enabled with proper retention',
      ['AWS::ApiGateway::Stage', 'AWS::Logs::LogGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    if (resource.Type === 'AWS::ApiGateway::Stage') {
      const accessLogSetting = resource.Properties?.AccessLogSetting;

      if (!accessLogSetting) {
        return this.createScanResult(          
          resource,           
          stackName,
          `${this.description}`,
          `Add AccessLogSetting with DestinationArn and Format properties`
        );
      }

      const destinationArn = accessLogSetting.DestinationArn;
      const format = accessLogSetting.Format;

      if (!destinationArn || !format) {
        return this.createScanResult(          
          resource,           
          stackName,
          `${this.description}`,
          `Ensure both DestinationArn and Format properties are specified in AccessLogSetting`
        );
      }

      // Check if the destination log group has a retention period set
      const logGroupRef = this.extractLogGroupRef(destinationArn);
      if (logGroupRef) {
        const logGroup = this.findLogGroup(logGroupRef, allResources);
        if (logGroup) {
          const retentionInDays = logGroup.Properties?.RetentionInDays;
          if (!retentionInDays) {
            return this.createScanResult(          
              resource,          
              stackName,
          `${this.description} (log group has no retention period)`,
          `Set RetentionInDays property on the CloudWatch Logs log group to define an explicit retention period`
        );
          }
        } else {
          // Log group reference exists but we can't find the actual log group in the template
          return this.createScanResult(          
            resource,          
            stackName,
          `${this.description} (referenced log group not found or retention not verifiable)`,
          `Ensure the referenced CloudWatch Logs log group has RetentionInDays property set`
        );
        }
      }
    }

    // Check log groups that might be used for API Gateway logging
    if (resource.Type === 'AWS::Logs::LogGroup') {
      const logGroupName = resource.Properties?.LogGroupName;
      
      // Only check log groups that appear to be for API Gateway
      if (logGroupName && typeof logGroupName === 'string' && 
          (logGroupName.includes('API-Gateway') || 
           logGroupName.includes('APIGateway') || 
           logGroupName.includes('api-gateway'))) {
        
        const retentionInDays = resource.Properties?.RetentionInDays;
        if (!retentionInDays) {
          return this.createScanResult(          
            resource,          
            stackName,
          `${this.description} (API Gateway log group has no retention period)`,
          `Set RetentionInDays property to define an explicit retention period`
        );
        }
      }
    }

    return null;
  }

  private extractLogGroupRef(destinationArn: any): string | null {
    if (!destinationArn) {
      return null;
    }

    // Handle string ARN
    if (typeof destinationArn === 'string') {
      const match = destinationArn.match(/arn:aws:logs:[^:]*:[^:]*:log-group:([^:]*)/);
      return match ? match[1] : null;
    }

    // Handle Ref or GetAtt
    if (typeof destinationArn === 'object') {
      // Direct reference
      if (destinationArn.Ref) {
        return destinationArn.Ref;
      }
      
      // GetAtt reference
      if (destinationArn['Fn::GetAtt'] && Array.isArray(destinationArn['Fn::GetAtt'])) {
        return destinationArn['Fn::GetAtt'][0];
      }
      
      // Handle Fn::Sub - common in CDK templates
      if (destinationArn['Fn::Sub']) {
        const subValue = destinationArn['Fn::Sub'];
        if (typeof subValue === 'string') {
          // Extract log group name from ARN pattern in Fn::Sub
          const match = subValue.match(/arn:aws:logs:[^:]*:[^:]*:log-group:([^:${}]*|(\${[^}]+}))/);
          if (match) {
            // If it's a variable reference like ${LogGroupName}, extract the variable name
            if (match[1].startsWith('${') && match[1].endsWith('}')) {
              return match[1].substring(2, match[1].length - 1);
            }
            return match[1];
          }
        }
      }
      
      // Handle Fn::Join - common in CDK templates
      if (destinationArn['Fn::Join'] && Array.isArray(destinationArn['Fn::Join'])) {
        const joinArray = destinationArn['Fn::Join'][1];
        if (Array.isArray(joinArray)) {
          // Look for log group pattern in joined elements
          for (let i = 0; i < joinArray.length; i++) {
            const element = joinArray[i];
            if (typeof element === 'string' && element.includes('log-group:')) {
              // Check if the next element is the log group name
              if (i + 1 < joinArray.length) {
                const nextElement = joinArray[i + 1];
                if (typeof nextElement === 'string') {
                  return nextElement;
                } else if (typeof nextElement === 'object' && nextElement.Ref) {
                  return nextElement.Ref;
                }
              }
            }
          }
        }
      }
    }

    return null;
  }

  private findLogGroup(logGroupRef: string, resources: CloudFormationResource[]): CloudFormationResource | null {
    // First try direct logical ID match
    const directMatch = resources.find(r => 
      r.Type === 'AWS::Logs::LogGroup' && 
      r.LogicalId === logGroupRef
    );
    
    if (directMatch) {
      return directMatch;
    }
    
    // If no direct match, try to find log groups that might be related to this reference
    // This handles cases where CDK generates log groups with different naming patterns
    
    // Check for log groups with LogGroupName that contains the reference
    const nameMatch = resources.find(r => 
      r.Type === 'AWS::Logs::LogGroup' && 
      r.Properties?.LogGroupName && 
      this.logGroupNameContainsRef(r.Properties.LogGroupName, logGroupRef)
    );
    
    if (nameMatch) {
      return nameMatch;
    }
    
    // Check for log groups that might be associated with API Gateway
    // This is a fallback for when we can't find a direct match
    const apiGatewayLogGroups = resources.filter(r => 
      r.Type === 'AWS::Logs::LogGroup' && 
      this.isLikelyApiGatewayLogGroup(r)
    );
    
    // If there's only one API Gateway log group, it's likely the one we're looking for
    if (apiGatewayLogGroups.length === 1) {
      return apiGatewayLogGroups[0];
    }
    
    return null;
  }
  
  private logGroupNameContainsRef(logGroupName: any, logGroupRef: string): boolean {
    // Handle string log group name
    if (typeof logGroupName === 'string') {
      return logGroupName.includes(logGroupRef);
    }
    
    // Handle Ref
    if (typeof logGroupName === 'object' && logGroupName.Ref === logGroupRef) {
      return true;
    }
    
    // Handle Fn::Sub
    if (typeof logGroupName === 'object' && logGroupName['Fn::Sub']) {
      const subValue = logGroupName['Fn::Sub'];
      if (typeof subValue === 'string' && subValue.includes(logGroupRef)) {
        return true;
      }
    }
    
    // Handle Fn::Join
    if (typeof logGroupName === 'object' && 
        logGroupName['Fn::Join'] && 
        Array.isArray(logGroupName['Fn::Join']) && 
        Array.isArray(logGroupName['Fn::Join'][1])) {
      
      return logGroupName['Fn::Join'][1].some(element => {
        if (typeof element === 'string') {
          return element.includes(logGroupRef);
        }
        if (typeof element === 'object' && element.Ref === logGroupRef) {
          return true;
        }
        return false;
      });
    }
    
    return false;
  }
  
  private isLikelyApiGatewayLogGroup(resource: CloudFormationResource): boolean {
    const logGroupName = resource.Properties?.LogGroupName;
    
    // Check string log group name
    if (typeof logGroupName === 'string') {
      return logGroupName.includes('API-Gateway') || 
             logGroupName.includes('APIGateway') || 
             logGroupName.includes('api-gateway') ||
             logGroupName.includes('apigateway') ||
             logGroupName.includes('/aws/apigateway/') ||
             logGroupName.includes('/AWS/ApiGateway/');
    }
    
    // Check Fn::Sub
    if (typeof logGroupName === 'object' && logGroupName['Fn::Sub']) {
      const subValue = logGroupName['Fn::Sub'];
      if (typeof subValue === 'string') {
        return subValue.includes('API-Gateway') || 
               subValue.includes('APIGateway') || 
               subValue.includes('api-gateway') ||
               subValue.includes('apigateway') ||
               subValue.includes('/aws/apigateway/') ||
               subValue.includes('/AWS/ApiGateway/');
      }
    }
    
    // Check Fn::Join
    if (typeof logGroupName === 'object' && 
        logGroupName['Fn::Join'] && 
        Array.isArray(logGroupName['Fn::Join']) && 
        Array.isArray(logGroupName['Fn::Join'][1])) {
      
      return logGroupName['Fn::Join'][1].some(element => {
        if (typeof element === 'string') {
          return element.includes('API-Gateway') || 
                 element.includes('APIGateway') || 
                 element.includes('api-gateway') ||
                 element.includes('apigateway') ||
                 element.includes('/aws/apigateway/') ||
                 element.includes('/AWS/ApiGateway/');
        }
        return false;
      });
    }
    
    return false;
  }
}

export default new ApiGw001Rule();
