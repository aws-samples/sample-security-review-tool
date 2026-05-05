import { describe, it, expect } from 'vitest';
import { O002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/organizations/002-restrict-admin-privileges.cf.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('ORG-002Rule', () => {
  const rule = new O002Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to IAM resource types', () => {
      expect(rule.appliesTo('AWS::IAM::User')).toBe(true);
      expect(rule.appliesTo('AWS::IAM::Role')).toBe(true);
      expect(rule.appliesTo('AWS::IAM::Policy')).toBe(true);
      expect(rule.appliesTo('AWS::IAM::ManagedPolicy')).toBe(true);
    });

    it('should not apply to unsupported resource types', () => {
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    it('should return null for IAM user without Organizations permissions', () => {
      const template: Template = {
        Resources: {
          TestUser: {
            Type: 'AWS::IAM::User',
            Properties: {
              UserName: 'test-user',
              Policies: [{
                PolicyName: 'S3Access',
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Action: 's3:GetObject',
                    Resource: '*'
                  }]
                }
              }]
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestUser'] as Resource);
      expect(result).toBeNull();
    });

    it('should return finding for IAM user with Organizations permissions', () => {
      const template: Template = {
        Resources: {
          TestUser: {
            Type: 'AWS::IAM::User',
            Properties: {
              UserName: 'admin-user',
              Policies: [{
                PolicyName: 'OrganizationsAccess',
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Action: 'organizations:*',
                    Resource: '*'
                  }]
                }
              }]
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestUser'] as Resource);
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::IAM::User');
      expect(result?.resourceName).toBe('TestUser');
      expect(result?.fix).toBe('Remove Organizations permissions from IAM user. Use IAM roles instead.');
    });

    it('should return null for role with MFA constraint', () => {
      const template: Template = {
        Resources: {
          TestRole: {
            Type: 'AWS::IAM::Role',
            Properties: {
              RoleName: 'OrganizationsAdminRole',
              AssumeRolePolicyDocument: {
                Statement: [{
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'sts:AssumeRole',
                  Condition: {
                    Bool: {
                      'aws:MultiFactorAuthPresent': 'true'
                    }
                  }
                }]
              },
              Policies: [{
                PolicyName: 'OrganizationsAccess',
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Action: 'organizations:CreateAccount',
                    Resource: '*'
                  }]
                }
              }]
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestRole'] as Resource);
      expect(result).toBeNull();
    });

    it('should return null for role with external ID constraint', () => {
      const template: Template = {
        Resources: {
          TestRole: {
            Type: 'AWS::IAM::Role',
            Properties: {
              RoleName: 'OrganizationsAdminRole',
              AssumeRolePolicyDocument: {
                Statement: [{
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'sts:AssumeRole',
                  Condition: {
                    StringEquals: {
                      'sts:ExternalId': 'unique-external-id'
                    }
                  }
                }]
              },
              Policies: [{
                PolicyName: 'OrganizationsAccess',
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Action: 'organizations:CreateAccount',
                    Resource: '*'
                  }]
                }
              }]
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestRole'] as Resource);
      expect(result).toBeNull();
    });

    it('should return finding for role without access constraints', () => {
      const template: Template = {
        Resources: {
          TestRole: {
            Type: 'AWS::IAM::Role',
            Properties: {
              RoleName: 'LocalAdminRole',
              AssumeRolePolicyDocument: {
                Statement: [{
                  Effect: 'Allow',
                  Principal: {
                    Service: 'ec2.amazonaws.com'
                  },
                  Action: 'sts:AssumeRole'
                }]
              },
              Policies: [{
                PolicyName: 'OrganizationsAccess',
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Action: 'organizations:EnableAWSServiceAccess',
                    Resource: '*'
                  }]
                }
              }]
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestRole'] as Resource);
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::IAM::Role');
      expect(result?.resourceName).toBe('TestRole');
      expect(result?.fix).toBe('Add MFA condition "aws:MultiFactorAuthPresent": "true" to role assume policy.');
    });

    it('should return finding for policy attached to users with Organizations permissions', () => {
      const template: Template = {
        Resources: {
          TestPolicy: {
            Type: 'AWS::IAM::Policy',
            Properties: {
              PolicyName: 'OrganizationsPolicy',
              PolicyDocument: {
                Statement: [{
                  Effect: 'Allow',
                  Action: 'organizations:DeleteAccount',
                  Resource: '*'
                }]
              },
              Users: ['test-user']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestPolicy'] as Resource);
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::IAM::Policy');
      expect(result?.resourceName).toBe('TestPolicy');
      expect(result?.fix).toBe('Remove Organizations permissions from policy attached to users. Use roles instead.');
    });

    it('should return null for policy attached only to roles', () => {
      const template: Template = {
        Resources: {
          TestPolicy: {
            Type: 'AWS::IAM::Policy',
            Properties: {
              PolicyName: 'OrganizationsPolicy',
              PolicyDocument: {
                Statement: [{
                  Effect: 'Allow',
                  Action: 'organizations:RegisterDelegatedAdministrator',
                  Resource: '*'
                }]
              },
              Roles: ['cross-account-role']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestPolicy'] as Resource);
      expect(result).toBeNull();
    });
  });

  describe('evaluate', () => {
    it('should return null for any resource type since it is a stub method', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::IAM::User',
        Properties: {},
        LogicalId: 'TestUser'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});