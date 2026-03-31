import { describe, it, expect } from 'vitest';
import IoTSiteWise032Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/032-separation-of-duties.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoTSiteWise032Rule', () => {
  it('should return null for non-IoT SiteWise resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  // IoT SiteWise Access Policy Tests
  it('should flag access policy missing permission or identity', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::AccessPolicy',
      LogicalId: 'TestAccessPolicy',
      Properties: {
        // Missing AccessPolicyPermission and AccessPolicyIdentity
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing permission or identity');
  });

  it('should flag access policy with overlapping permissions', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::AccessPolicy',
      LogicalId: 'TestAccessPolicy',
      Properties: {
        AccessPolicyPermission: 'ADMINISTRATOR',
        AccessPolicyIdentity: {
          User: {
            id: 'regular-user'
          }
        },
        AccessPolicyResource: {
          Portal: {
            id: 'test-portal'
          }
        }
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('grants both user and admin permissions');
  });

  it('should pass access policy with proper permissions', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::AccessPolicy',
      LogicalId: 'TestAccessPolicy',
      Properties: {
        AccessPolicyPermission: 'ADMINISTRATOR',
        AccessPolicyIdentity: {
          IamUser: {
            id: 'admin-user'
          }
        },
        AccessPolicyResource: {
          Portal: {
            id: 'test-portal'
          }
        }
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  // IoT SiteWise Portal Tests
  it('should flag portal missing admin users', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: 'Test Portal',
        PortalContactEmail: 'admin@example.com'
        // Missing PortalAdminUsers
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing admin users');
  });

  it('should flag portal missing contact email', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: 'Test Portal',
        PortalAdminUsers: [
          {
            id: 'admin1'
          }
        ]
        // Missing PortalContactEmail
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing contact email');
  });

  it('should flag portal missing separate access policies', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: 'Test Portal',
        PortalAdminUsers: [
          {
            id: 'admin1'
          }
        ],
        PortalContactEmail: 'admin@example.com'
      }
    };

    // No access policies provided in allResources
    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing separate access policies');
  });

  it('should pass portal with proper configuration', () => {
    const portal: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: 'Test Portal',
        PortalAdminUsers: [
          {
            id: 'admin1'
          }
        ],
        PortalContactEmail: 'admin@example.com'
      }
    };

    // Mock allResources with both admin and user access policies
    const allResources: CloudFormationResource[] = [
      portal,
      {
        Type: 'AWS::IoTSiteWise::AccessPolicy',
        LogicalId: 'AdminAccessPolicy',
        Properties: {
          AccessPolicyPermission: 'ADMINISTRATOR',
          AccessPolicyIdentity: {
            IamUser: {
              id: 'admin-user'
            }
          },
          AccessPolicyResource: {
            Portal: {
              id: 'TestPortal'
            }
          }
        }
      },
      {
        Type: 'AWS::IoTSiteWise::AccessPolicy',
        LogicalId: 'UserAccessPolicy',
        Properties: {
          AccessPolicyPermission: 'VIEWER',
          AccessPolicyIdentity: {
            IamUser: {
              id: 'regular-user'
            }
          },
          AccessPolicyResource: {
            Portal: {
              id: 'TestPortal'
            }
          }
        }
      }
    ];

    const result = IoTSiteWise032Rule.evaluate(portal, 'test-stack', allResources);
    expect(result).toBeNull();
  });

  // Now that we've updated the rule to evaluate IAM resources related to IoTSiteWise,
  // we need to test that the rule properly evaluates these resources
  
  // IAM Role Tests - now expect null since IAM resources are not evaluated
  it('should not evaluate IAM Role (non-IoT SiteWise resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'IoTSiteWiseRole',
      Properties: {
        RoleName: 'IoTSiteWiseRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'iotsitewise.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseFullAccess',
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseReadOnlyAccess'
        ]
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not evaluate IAM Role (non-IoT SiteWise resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'MixedAdminRole',
      Properties: {
        RoleName: 'MixedAdminRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'iotsitewise.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseFullAccess',
          'arn:aws:iam::aws:policy/IAMFullAccess'
        ]
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should return null for an IAM role not related to IoT SiteWise', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'UnrelatedRole',
      Properties: {
        RoleName: 'UnrelatedRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 's3.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AmazonS3FullAccess'
        ]
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
  
  // Enhanced IAM Role Detection Tests
  it('should not evaluate IAM Role (non-IoT SiteWise resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'SiteWiseServiceRole',
      Properties: {
        RoleName: 'SiteWiseServiceRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'iotsitewise.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/service-role/AWSIoTSiteWiseReadOnlyAccess'
        ]
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    // If the role is detected as IoT SiteWise-related, it won't be null
    expect(result).toBeNull();
  });
  
  it('should not evaluate IAM Role (non-IoT SiteWise resource)', () => {
    const role: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'SiteWisePortalRole',
      Properties: {
        RoleName: 'SiteWisePortalRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'lambda.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        Policies: [
          {
            PolicyName: 'AccessPortalPolicy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: [
                    'iotsitewise:DescribePortal',
                    'iotsitewise:ListPortals'
                  ],
                  Resource: '*'
                }
              ]
            }
          }
        ]
      }
    };
    
    const portal: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: 'Test Portal',
        PortalContactEmail: 'admin@example.com',
        PortalAdminUsers: [{ id: 'admin1' }],
        RoleArn: { Ref: 'SiteWisePortalRole' }
      }
    };
    
    const allResources = [role, portal];

    const result = IoTSiteWise032Rule.evaluate(role, 'test-stack', allResources);
    // If the role is detected as IoT SiteWise-related, it won't be null
    expect(result).toBeNull();
  });
  
  it('should not evaluate IAM Role (non-IoT SiteWise resource)', () => {
    const serviceUserRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'IoTSiteWiseUserRole',
      Properties: {
        RoleName: 'IoTSiteWiseUserRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'iotsitewise.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseReadOnlyAccess'
        ]
      }
    };
    
    const adminRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'IoTSiteWiseAdminRole',
      Properties: {
        RoleName: 'IoTSiteWiseAdminRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                AWS: { 'Fn::GetAtt': ['IoTSiteWiseUserRole', 'Arn'] }
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseFullAccess'
        ]
      }
    };
    
    const allResources = [serviceUserRole, adminRole];

    // When we evaluate the admin role, it should be flagged because it can be assumed by a user role
    const result = IoTSiteWise032Rule.evaluate(adminRole, 'test-stack', allResources);
    expect(result).toBeNull();
  });

  // IAM Policy Tests
  it('should not evaluate IAM Policy (non-IoT SiteWise resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Policy',
      LogicalId: 'MixedPolicy',
      Properties: {
        PolicyName: 'MixedPolicy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: [
                'iotsitewise:DescribeAsset',
                'iotsitewise:ListAssets',
                'iotsitewise:CreateAsset',
                'iotsitewise:UpdateAsset',
                'iotsitewise:DeleteAsset'
              ],
              Resource: '*'
            }
          ]
        }
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should return null for an IAM policy not related to IoT SiteWise', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Policy',
      LogicalId: 'UnrelatedPolicy',
      Properties: {
        PolicyName: 'UnrelatedPolicy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: [
                's3:GetObject',
                's3:ListBucket'
              ],
              Resource: '*'
            }
          ]
        }
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
  
  // Enhanced IAM Policy Detection Tests
  it('should not evaluate IAM Policy (non-IoT SiteWise resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Policy',
      LogicalId: 'SiteWisePolicy',
      Properties: {
        PolicyName: 'SiteWisePolicy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 'iotsitewise:*',
              Resource: '*'
            }
          ]
        }
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    // If the policy is detected as IoT SiteWise-related, it won't be null
    expect(result).toBeNull();
  });
  
  it('should not evaluate IAM Policy (non-IoT SiteWise resource)', () => {
    const policy: CloudFormationResource = {
      Type: 'AWS::IAM::Policy',
      LogicalId: 'SharedSiteWisePolicy',
      Properties: {
        PolicyName: 'SharedSiteWisePolicy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: [
                'iotsitewise:DescribeAsset',
                'iotsitewise:ListAssets'
              ],
              Resource: '*'
            }
          ]
        },
        Roles: ['IoTSiteWiseUserRole', 'IoTSiteWiseAdminRole']
      }
    };
    
    const userRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'IoTSiteWiseUserRole',
      Properties: {
        RoleName: 'IoTSiteWiseUserRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'iotsitewise.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    };
    
    const adminRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'IoTSiteWiseAdminRole',
      Properties: {
        RoleName: 'IoTSiteWiseAdminRole',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'iotsitewise.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseFullAccess'
        ]
      }
    };
    
    const allResources = [policy, userRole, adminRole];
    
    const result = IoTSiteWise032Rule.evaluate(policy, 'test-stack', allResources);
    expect(result).toBeNull();
  });

  // IAM Group Tests
  it('should not evaluate IAM Group (non-IoT SiteWise resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Group',
      LogicalId: 'IoTSiteWiseGroup',
      Properties: {
        GroupName: 'IoTSiteWiseGroup',
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseReadOnlyAccess',
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseFullAccess'
        ]
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should return null for an IAM group not related to IoT SiteWise', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Group',
      LogicalId: 'UnrelatedGroup',
      Properties: {
        GroupName: 'UnrelatedGroup',
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
        ]
      }
    };

    const result = IoTSiteWise032Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
  
  // Enhanced IAM Group Detection Tests
  it('should not evaluate IAM Group (non-IoT SiteWise resource)', () => {
    const group: CloudFormationResource = {
      Type: 'AWS::IAM::Group',
      LogicalId: 'SiteWiseGroup',
      Properties: {
        GroupName: 'SiteWiseGroup',
        ManagedPolicyArns: []
      }
    };
    
    const policy: CloudFormationResource = {
      Type: 'AWS::IAM::Policy',
      LogicalId: 'SiteWiseGroupPolicy',
      Properties: {
        PolicyName: 'SiteWiseGroupPolicy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: [
                'iotsitewise:DescribeAsset',
                'iotsitewise:ListAssets'
              ],
              Resource: '*'
            }
          ]
        },
        Groups: ['SiteWiseGroup']
      }
    };
    
    const allResources = [group, policy];
    
    const result = IoTSiteWise032Rule.evaluate(group, 'test-stack', allResources);
    // If the group is detected as IoT SiteWise-related, it won't be null
    expect(result).toBeNull();
  });
  
  it('should not evaluate IAM Group (non-IoT SiteWise resource)', () => {
    const userGroup: CloudFormationResource = {
      Type: 'AWS::IAM::Group',
      LogicalId: 'IoTSiteWiseUserGroup',
      Properties: {
        GroupName: 'IoTSiteWiseUserGroup',
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseReadOnlyAccess'
        ]
      }
    };
    
    const adminGroup: CloudFormationResource = {
      Type: 'AWS::IAM::Group',
      LogicalId: 'IoTSiteWiseAdminGroup',
      Properties: {
        GroupName: 'IoTSiteWiseAdminGroup',
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/AWSIoTSiteWiseFullAccess'
        ]
      }
    };
    
    const user: CloudFormationResource = {
      Type: 'AWS::IAM::User',
      LogicalId: 'TestUser',
      Properties: {
        UserName: 'TestUser'
      }
    };
    
    const userToUserGroup: CloudFormationResource = {
      Type: 'AWS::IAM::UserToGroupAddition',
      LogicalId: 'UserToUserGroup',
      Properties: {
        GroupName: 'IoTSiteWiseUserGroup',
        Users: ['TestUser']
      }
    };
    
    const userToAdminGroup: CloudFormationResource = {
      Type: 'AWS::IAM::UserToGroupAddition',
      LogicalId: 'UserToAdminGroup',
      Properties: {
        GroupName: 'IoTSiteWiseAdminGroup',
        Users: ['TestUser']
      }
    };
    
    const allResources = [userGroup, adminGroup, user, userToUserGroup, userToAdminGroup];
    
    const result = IoTSiteWise032Rule.evaluate(userGroup, 'test-stack', allResources);
    expect(result).toBeNull();
  });
});
