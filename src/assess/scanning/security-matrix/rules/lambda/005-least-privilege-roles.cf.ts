import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class CompLamb005Rule extends BaseRule {
  constructor() {
    super(
      'LAMBDA-005',
      'HIGH',
      'Lambda function IAM role violates principle of least privilege',
      ['AWS::IAM::Role', 'AWS::Lambda::Function']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Skip if allResources is not provided
    if (!allResources) {
      allResources = [];
    }

    // Process IAM Role resources
    if (resource.Type === 'AWS::IAM::Role') {
      // Skip if Properties is missing
      if (!resource.Properties) {
        return null;
      }

      // Check if this role is associated with a Lambda function
      const isLambdaRole = this.isLambdaRole(resource, allResources);

      if (!isLambdaRole) {
        return null;
      }

      // Check for overly permissive policies
      const policies = resource.Properties.Policies || [];
      const managedPolicyArns = resource.Properties.ManagedPolicyArns || [];

      // Check inline policies
      for (const policy of policies) {
        const policyDocument = policy.PolicyDocument;

        if (policyDocument) {
          const statements = policyDocument.Statement;

          if (statements && Array.isArray(statements)) {
            for (const statement of statements) {
              if (this.isOverlyPermissiveStatement(statement)) {
                return this.createScanResult(
                  resource,
                  stackName,
                  `${this.description}`,
                  `Replace wildcard actions (e.g., '*' or 'service:*') with specific actions that the Lambda function actually needs, and restrict resources to specific ARNs instead of using '*'.`
                );
              }
            }
          }
        }
      }

      // Check managed policies
      for (const policyArn of managedPolicyArns) {
        if (typeof policyArn === 'string' && this.isOverlyPermissiveManagedPolicy(policyArn)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Replace overly permissive managed policy '${policyArn}' with a custom policy that grants only the specific permissions required by the Lambda function.`
          );
        }
      }
    }

    // Process Lambda Function resources to check their roles
    if (resource.Type === 'AWS::Lambda::Function') {
      // Skip if Properties is missing
      if (!resource.Properties) {
        return null;
      }

      // Get the role associated with this Lambda function
      const role = resource.Properties.Role;

      // Skip if role is not specified
      if (!role) {
        return null;
      }

      // Find the referenced role resource
      let roleResource: CloudFormationResource | undefined;

      if (typeof role === 'string') {
        // Direct string reference (could be ARN or logical ID)
        roleResource = allResources.find(r => r.LogicalId === role && r.Type === 'AWS::IAM::Role');
      } else if (typeof role === 'object' && role !== null) {
        // Ref or GetAtt reference
        if (role.Ref) {
          roleResource = allResources.find(r => r.LogicalId === role.Ref && r.Type === 'AWS::IAM::Role');
        } else if (role['Fn::GetAtt'] && Array.isArray(role['Fn::GetAtt']) && role['Fn::GetAtt'].length > 0) {
          roleResource = allResources.find(r => r.LogicalId === role['Fn::GetAtt'][0] && r.Type === 'AWS::IAM::Role');
        }
      }

      // If we found the role resource, evaluate it
      if (roleResource) {
        return this.evaluate(roleResource, stackName, allResources);
      }
    }

    return null;
  }

  private isLambdaRole(resource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Check if this role is associated with a Lambda function

    // Method 1: Check if any Lambda function references this role
    const roleId = resource.LogicalId;
    const lambdaFunctions = allResources.filter(r => r.Type === 'AWS::Lambda::Function' && r.Properties?.Role);

    for (const lambda of lambdaFunctions) {
      const role = lambda.Properties.Role;

      // Check different types of references
      if (typeof role === 'string' && role === roleId) {
        return true;
      } else if (typeof role === 'object' && role !== null) {
        // Ref reference
        if (role.Ref && role.Ref === roleId) {
          return true;
        }

        // GetAtt reference
        if (role['Fn::GetAtt'] && Array.isArray(role['Fn::GetAtt']) && role['Fn::GetAtt'][0] === roleId) {
          return true;
        }

        // Sub reference
        if (role['Fn::Sub'] && typeof role['Fn::Sub'] === 'string' && role['Fn::Sub'].includes(`\${${roleId}}`)) {
          return true;
        }

        // Join reference
        if (role['Fn::Join'] && Array.isArray(role['Fn::Join']) && role['Fn::Join'].length === 2) {
          const joinParts = role['Fn::Join'][1];
          if (Array.isArray(joinParts) && JSON.stringify(joinParts).includes(roleId)) {
            return true;
          }
        }
      }
    }

    // Method 2: Check the assume role policy document
    const assumeRolePolicyDocument = resource.Properties?.AssumeRolePolicyDocument;

    if (assumeRolePolicyDocument) {
      const statements = assumeRolePolicyDocument.Statement;

      if (statements && Array.isArray(statements)) {
        for (const statement of statements) {
          const principal = statement.Principal;

          if (principal && principal.Service) {
            if (Array.isArray(principal.Service)) {
              if (principal.Service.includes('lambda.amazonaws.com')) {
                return true;
              }
            } else if (typeof principal.Service === 'string' && principal.Service === 'lambda.amazonaws.com') {
              return true;
            } else if (typeof principal.Service === 'object' && principal.Service !== null) {
              // Handle intrinsic functions in Service field
              const serviceStr = JSON.stringify(principal.Service);
              if (serviceStr.includes('lambda.amazonaws.com')) {
                return true;
              }
            }
          }
        }
      }
    }

    // Method 3: Check for Lambda-related role name or path
    const roleName = resource.Properties?.RoleName;
    const path = resource.Properties?.Path;

    if ((typeof roleName === 'string' && roleName.toLowerCase().includes('lambda')) ||
      (typeof path === 'string' && path.toLowerCase().includes('lambda')) ||
      resource.LogicalId.toLowerCase().includes('lambda')) {
      return true;
    }

    return false;
  }

  private isOverlyPermissiveStatement(statement: any): boolean {
    // Check if the statement is overly permissive

    // Skip if statement is not an object
    if (typeof statement !== 'object' || statement === null) {
      return false;
    }

    // Only check Allow statements
    if (statement.Effect !== 'Allow') {
      return false;
    }

    // Check for wildcard actions
    let actions: string[] = [];

    if (Array.isArray(statement.Action)) {
      actions = statement.Action.filter((a: any) => typeof a === 'string');
    } else if (typeof statement.Action === 'string') {
      actions = [statement.Action];
    }

    // If no valid actions, check if there's an intrinsic function that might contain wildcards
    if (actions.length === 0 && typeof statement.Action === 'object' && statement.Action !== null) {
      const actionStr = JSON.stringify(statement.Action);
      if (actionStr.includes('*')) {
        // If the action contains a wildcard and the resource is also a wildcard, it's overly permissive
        if (this.hasWildcardResource(statement.Resource)) {
          return true;
        }
      }
      return false;
    }

    // Check each action for wildcards
    for (const action of actions) {
      // Check for global wildcard or service-level wildcard
      if (action === '*' || action.endsWith(':*')) {
        // Check if the resource is also a wildcard
        if (this.hasWildcardResource(statement.Resource)) {
          return true;
        }
      }

      // Check for dangerous partial wildcards like "iam:*" or "s3:*"
      const dangerousServices = ['iam:', 's3:', 'dynamodb:', 'lambda:', 'ec2:', 'rds:', 'kms:'];
      for (const service of dangerousServices) {
        if (action === `${service}*`) {
          // Check if the resource is also a wildcard
          if (this.hasWildcardResource(statement.Resource)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Check if a resource specification includes wildcards
   */
  private hasWildcardResource(resource: any): boolean {
    // Handle string resources
    if (typeof resource === 'string') {
      return resource === '*';
    }

    // Handle array of resources
    if (Array.isArray(resource)) {
      return resource.some(r => typeof r === 'string' && r === '*');
    }

    // Handle intrinsic functions
    if (typeof resource === 'object' && resource !== null) {
      const resourceStr = JSON.stringify(resource);
      return resourceStr.includes('"*"');
    }

    return false;
  }

  private isOverlyPermissiveManagedPolicy(policyArn: string): boolean {
    // Check if the managed policy is overly permissive

    // List of known overly permissive managed policies
    const overlyPermissivePolicies = [
      'arn:aws:iam::aws:policy/AdministratorAccess',
      'arn:aws:iam::aws:policy/PowerUserAccess',
      'arn:aws:iam::aws:policy/AmazonS3FullAccess',
      'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
      'arn:aws:iam::aws:policy/AmazonRDSFullAccess',
      'arn:aws:iam::aws:policy/AmazonEC2FullAccess',
      'arn:aws:iam::aws:policy/AmazonSNSFullAccess',
      'arn:aws:iam::aws:policy/AmazonSQSFullAccess',
      'arn:aws:iam::aws:policy/AmazonKinesisFullAccess',
      'arn:aws:iam::aws:policy/IAMFullAccess',
      'arn:aws:iam::aws:policy/AWSLambdaFullAccess',
      'arn:aws:iam::aws:policy/ReadOnlyAccess'
    ];

    // Check for exact matches
    if (overlyPermissivePolicies.includes(policyArn)) {
      return true;
    }

    // Check for partial matches (e.g., custom policies with similar names)
    const permissiveKeywords = [
      'FullAccess',
      'AdministratorAccess',
      'PowerUserAccess',
      'Admin',
      'Root'
    ];

    return permissiveKeywords.some(keyword => policyArn.includes(keyword));
  }
}

export default new CompLamb005Rule();
