import { describe, it, expect } from 'vitest';
import { Iam009Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iam/009-permissions-boundaries.cf.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Iam009Rule', () => {
    const rule = new Iam009Rule();
    const stackName = 'test-stack';

    describe('appliesTo', () => {
        it('should apply to AWS::IAM::Role', () => {
            expect(rule.appliesTo('AWS::IAM::Role')).toBe(true);
        });

        it('should not apply to compute resources', () => {
            expect(rule.appliesTo('AWS::Lambda::Function')).toBe(false);
            expect(rule.appliesTo('AWS::CodeBuild::Project')).toBe(false);
            expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
        });

        it('should not apply to other resource types', () => {
            expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
        });
    });

    describe('evaluateResource', () => {
        it('should return null for non-IAM::Role resources', () => {
            const template: Template = {
                Resources: {
                    TestBucket: { Type: 'AWS::S3::Bucket', Properties: {} }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);
            expect(result).toBeNull();
        });

        it('should return null for role not referenced by any compute resource', () => {
            const template: Template = {
                Resources: {
                    AdminRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            ManagedPolicyArns: ['arn:aws:iam::aws:policy/AdministratorAccess']
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['AdminRole'] as Resource);
            expect(result).toBeNull();
        });

        it('should return null for role referenced by compute but without IAM-mutating permissions', () => {
            const template: Template = {
                Resources: {
                    LambdaRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole']
                        }
                    },
                    LambdaFunction: {
                        Type: 'AWS::Lambda::Function',
                        Properties: {
                            Role: { 'Fn::GetAtt': ['LambdaRole', 'Arn'] }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['LambdaRole'] as Resource);
            expect(result).toBeNull();
        });

        it('should return null for role with IAM permissions and PermissionsBoundary', () => {
            const template: Template = {
                Resources: {
                    LambdaRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            ManagedPolicyArns: ['arn:aws:iam::aws:policy/AdministratorAccess'],
                            PermissionsBoundary: 'arn:aws:iam::123456789012:policy/MyBoundary'
                        }
                    },
                    LambdaFunction: {
                        Type: 'AWS::Lambda::Function',
                        Properties: {
                            Role: { 'Fn::GetAtt': ['LambdaRole', 'Arn'] }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['LambdaRole'] as Resource);
            expect(result).toBeNull();
        });

        it('should return null for role with PermissionsBoundary using Ref', () => {
            const template: Template = {
                Resources: {
                    LambdaRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            ManagedPolicyArns: ['arn:aws:iam::aws:policy/IAMFullAccess'],
                            PermissionsBoundary: { Ref: 'BoundaryPolicy' }
                        }
                    },
                    LambdaFunction: {
                        Type: 'AWS::Lambda::Function',
                        Properties: {
                            Role: { 'Fn::GetAtt': ['LambdaRole', 'Arn'] }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['LambdaRole'] as Resource);
            expect(result).toBeNull();
        });

        it('should return finding for Lambda role with AdministratorAccess and no boundary', () => {
            const template: Template = {
                Resources: {
                    LambdaRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            ManagedPolicyArns: ['arn:aws:iam::aws:policy/AdministratorAccess']
                        }
                    },
                    LambdaFunction: {
                        Type: 'AWS::Lambda::Function',
                        Properties: {
                            Role: { 'Fn::GetAtt': ['LambdaRole', 'Arn'] }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['LambdaRole'] as Resource);
            expect(result).not.toBeNull();
            expect(result?.resourceType).toBe('AWS::IAM::Role');
            expect(result?.resourceName).toBe('LambdaRole');
            expect(result?.fix).toContain('PermissionsBoundary');
        });

        it('should return finding for CodeBuild role with IAMFullAccess and no boundary', () => {
            const template: Template = {
                Resources: {
                    CodeBuildRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            ManagedPolicyArns: ['arn:aws:iam::aws:policy/IAMFullAccess']
                        }
                    },
                    CodeBuildProject: {
                        Type: 'AWS::CodeBuild::Project',
                        Properties: {
                            ServiceRole: { 'Fn::GetAtt': ['CodeBuildRole', 'Arn'] }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['CodeBuildRole'] as Resource);
            expect(result).not.toBeNull();
            expect(result?.resourceName).toBe('CodeBuildRole');
        });

        it('should return finding for role with inline iam:CreateRole action and no boundary', () => {
            const template: Template = {
                Resources: {
                    LambdaRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            Policies: [{
                                PolicyName: 'IamPolicy',
                                PolicyDocument: {
                                    Statement: [{
                                        Effect: 'Allow',
                                        Action: ['iam:CreateRole', 'iam:AttachRolePolicy'],
                                        Resource: '*'
                                    }]
                                }
                            }]
                        }
                    },
                    LambdaFunction: {
                        Type: 'AWS::Lambda::Function',
                        Properties: {
                            Role: { 'Fn::GetAtt': ['LambdaRole', 'Arn'] }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['LambdaRole'] as Resource);
            expect(result).not.toBeNull();
        });

        it('should return finding for role with iam:* action and no boundary', () => {
            const template: Template = {
                Resources: {
                    GlueRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            Policies: [{
                                PolicyName: 'IamPolicy',
                                PolicyDocument: {
                                    Statement: [{
                                        Effect: 'Allow',
                                        Action: 'iam:*',
                                        Resource: '*'
                                    }]
                                }
                            }]
                        }
                    },
                    GlueJob: {
                        Type: 'AWS::Glue::Job',
                        Properties: {
                            Role: { Ref: 'GlueRole' }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['GlueRole'] as Resource);
            expect(result).not.toBeNull();
        });

        it('should return finding for role with wildcard * action and no boundary', () => {
            const template: Template = {
                Resources: {
                    EC2Role: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            Policies: [{
                                PolicyName: 'AdminPolicy',
                                PolicyDocument: {
                                    Statement: [{
                                        Effect: 'Allow',
                                        Action: '*',
                                        Resource: '*'
                                    }]
                                }
                            }]
                        }
                    },
                    EC2Instance: {
                        Type: 'AWS::EC2::Instance',
                        Properties: {
                            IamInstanceProfile: { Ref: 'EC2Role' }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['EC2Role'] as Resource);
            expect(result).not.toBeNull();
        });

        it('should return null for role with only IAM read permissions', () => {
            const template: Template = {
                Resources: {
                    SageMakerRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            Policies: [{
                                PolicyName: 'IamReadPolicy',
                                PolicyDocument: {
                                    Statement: [{
                                        Effect: 'Allow',
                                        Action: ['iam:GetRole', 'iam:ListRoles'],
                                        Resource: '*'
                                    }]
                                }
                            }]
                        }
                    },
                    SageMakerNotebook: {
                        Type: 'AWS::SageMaker::NotebookInstance',
                        Properties: {
                            RoleArn: { 'Fn::GetAtt': ['SageMakerRole', 'Arn'] }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['SageMakerRole'] as Resource);
            expect(result).toBeNull();
        });

        it('should handle role referenced via Fn::If conditional', () => {
            const template: Template = {
                Resources: {
                    CodeBuildRole: {
                        Type: 'AWS::IAM::Role',
                        Properties: {
                            AssumeRolePolicyDocument: {},
                            ManagedPolicyArns: ['arn:aws:iam::aws:policy/ReadOnlyAccess']
                        }
                    },
                    CodeBuildProject: {
                        Type: 'AWS::CodeBuild::Project',
                        Properties: {
                            ServiceRole: {
                                'Fn::If': ['CreateRole', { 'Fn::GetAtt': ['CodeBuildRole', 'Arn'] }, { Ref: 'ExternalRoleArn' }]
                            }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['CodeBuildRole'] as Resource);
            expect(result).toBeNull();
        });
    });

    describe('evaluate', () => {
        it('should return null (legacy stub)', () => {
            const resource: CloudFormationResource = {
                Type: 'AWS::IAM::Role',
                Properties: {},
                LogicalId: 'TestRole'
            };

            expect(rule.evaluate(resource, stackName)).toBeNull();
        });
    });

    describe('rule properties', () => {
        it('should have correct id and priority', () => {
            expect(rule.id).toBe('IAM-009');
            expect(rule.priority).toBe('HIGH');
        });
    });
});
