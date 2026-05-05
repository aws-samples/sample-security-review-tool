import { describe, it, expect } from 'vitest';
import { Vpc003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/vpc/003-flow-log-retention.cf.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Vpc003Rule', () => {
    const rule = new Vpc003Rule();
    const stackName = 'test-stack';

    describe('appliesTo', () => {
        it('should apply to AWS::EC2::FlowLog type', () => {
            expect(rule.appliesTo('AWS::EC2::FlowLog')).toBe(true);
        });

        it('should not apply to other resource types', () => {
            expect(rule.appliesTo('AWS::EC2::VPC')).toBe(false);
            expect(rule.appliesTo('AWS::Logs::LogGroup')).toBe(false);
            expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
        });
    });

    describe('evaluateResource - CloudWatch Logs destination', () => {
        it('should return null when log group has RetentionInDays configured (via Ref)', () => {
            const template: Template = {
                Resources: {
                    FlowLogGroup: {
                        Type: 'AWS::Logs::LogGroup',
                        Properties: {
                            RetentionInDays: 90
                        }
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogGroupName: { Ref: 'FlowLogGroup' },
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should return finding when log group is missing RetentionInDays (via Ref)', () => {
            const template: Template = {
                Resources: {
                    FlowLogGroup: {
                        Type: 'AWS::Logs::LogGroup',
                        Properties: {}
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogGroupName: { Ref: 'FlowLogGroup' },
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).not.toBeNull();
            expect(result?.resourceType).toBe('AWS::EC2::FlowLog');
            expect(result?.resourceName).toBe('VpcFlowLog');
            expect(result?.fix).toContain('RetentionInDays');
        });

        it('should return null when log group has RetentionInDays configured (via Fn::GetAtt)', () => {
            const template: Template = {
                Resources: {
                    FlowLogGroup: {
                        Type: 'AWS::Logs::LogGroup',
                        Properties: {
                            RetentionInDays: 365
                        }
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::GetAtt': ['FlowLogGroup', 'Arn'] },
                            LogDestinationType: 'cloud-watch-logs',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should return finding when log group is missing RetentionInDays (via Fn::GetAtt)', () => {
            const template: Template = {
                Resources: {
                    FlowLogGroup: {
                        Type: 'AWS::Logs::LogGroup',
                        Properties: {}
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::GetAtt': ['FlowLogGroup', 'Arn'] },
                            LogDestinationType: 'cloud-watch-logs',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).not.toBeNull();
            expect(result?.fix).toContain('RetentionInDays');
        });

        it('should return null when log group has RetentionInDays configured (via Fn::Sub)', () => {
            const template: Template = {
                Resources: {
                    FlowLogGroup: {
                        Type: 'AWS::Logs::LogGroup',
                        Properties: {
                            RetentionInDays: 30
                        }
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::Sub': '${FlowLogGroup.Arn}' },
                            LogDestinationType: 'cloud-watch-logs',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should return null when Fn::Sub array references external variable', () => {
            const template: Template = {
                Resources: {
                    FlowLogGroup: {
                        Type: 'AWS::Logs::LogGroup',
                        Properties: {}
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::Sub': ['${LogGroup.Arn}', { LogGroup: { Ref: 'FlowLogGroup' } }] },
                            LogDestinationType: 'cloud-watch-logs',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            // Fn::Sub with array format - the regex extracts "LogGroup" not "FlowLogGroup"
            // LogGroup is not a valid resource, so it returns null (can't validate external)
            expect(result).toBeNull();
        });

        it('should default to cloud-watch-logs when LogDestinationType is not specified', () => {
            const template: Template = {
                Resources: {
                    FlowLogGroup: {
                        Type: 'AWS::Logs::LogGroup',
                        Properties: {}
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogGroupName: { Ref: 'FlowLogGroup' },
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).not.toBeNull();
            expect(result?.fix).toContain('RetentionInDays');
        });

        it('should return null when log group is defined externally (string LogGroupName)', () => {
            const template: Template = {
                Resources: {
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogGroupName: '/aws/vpc/flowlogs',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should return null when LogDestination references external resource', () => {
            const template: Template = {
                Resources: {
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: 'arn:aws:logs:us-east-1:123456789012:log-group:external-log-group',
                            LogDestinationType: 'cloud-watch-logs',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });
    });

    describe('evaluateResource - S3 destination', () => {
        it('should return null when S3 bucket has LifecycleConfiguration with rules', () => {
            const template: Template = {
                Resources: {
                    FlowLogBucket: {
                        Type: 'AWS::S3::Bucket',
                        Properties: {
                            LifecycleConfiguration: {
                                Rules: [
                                    {
                                        Status: 'Enabled',
                                        ExpirationInDays: 90
                                    }
                                ]
                            }
                        }
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::GetAtt': ['FlowLogBucket', 'Arn'] },
                            LogDestinationType: 's3',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should return finding when S3 bucket is missing LifecycleConfiguration', () => {
            const template: Template = {
                Resources: {
                    FlowLogBucket: {
                        Type: 'AWS::S3::Bucket',
                        Properties: {}
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::GetAtt': ['FlowLogBucket', 'Arn'] },
                            LogDestinationType: 's3',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).not.toBeNull();
            expect(result?.resourceType).toBe('AWS::EC2::FlowLog');
            expect(result?.fix).toContain('LifecycleConfiguration');
        });

        it('should return finding when S3 bucket has empty lifecycle rules', () => {
            const template: Template = {
                Resources: {
                    FlowLogBucket: {
                        Type: 'AWS::S3::Bucket',
                        Properties: {
                            LifecycleConfiguration: {
                                Rules: []
                            }
                        }
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::GetAtt': ['FlowLogBucket', 'Arn'] },
                            LogDestinationType: 's3',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).not.toBeNull();
            expect(result?.fix).toContain('LifecycleConfiguration');
        });

        it('should return null when S3 bucket has lifecycle rules (via Fn::Sub)', () => {
            const template: Template = {
                Resources: {
                    FlowLogBucket: {
                        Type: 'AWS::S3::Bucket',
                        Properties: {
                            LifecycleConfiguration: {
                                Rules: [
                                    {
                                        Status: 'Enabled',
                                        ExpirationInDays: 365
                                    }
                                ]
                            }
                        }
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::Sub': '${FlowLogBucket.Arn}' },
                            LogDestinationType: 's3',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should return finding when S3 bucket is missing lifecycle rules (via Ref)', () => {
            const template: Template = {
                Resources: {
                    FlowLogBucket: {
                        Type: 'AWS::S3::Bucket',
                        Properties: {}
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { Ref: 'FlowLogBucket' },
                            LogDestinationType: 's3',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).not.toBeNull();
            expect(result?.fix).toContain('LifecycleConfiguration');
        });

        it('should return null when S3 bucket is defined externally (string LogDestination)', () => {
            const template: Template = {
                Resources: {
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: 'arn:aws:s3:::external-bucket',
                            LogDestinationType: 's3',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });
    });

    describe('evaluateResource - Kinesis Data Firehose destination', () => {
        it('should return null for Kinesis Data Firehose destination (retention managed externally)', () => {
            const template: Template = {
                Resources: {
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::GetAtt': ['FirehoseDeliveryStream', 'Arn'] },
                            LogDestinationType: 'kinesis-data-firehose',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });
    });

    describe('evaluateResource - edge cases', () => {
        it('should return null for non-applicable resource types', () => {
            const template: Template = {
                Resources: {
                    TestVpc: {
                        Type: 'AWS::EC2::VPC',
                        Properties: {
                            CidrBlock: '10.0.0.0/16'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['TestVpc'] as Resource);
            expect(result).toBeNull();
        });

        it('should handle empty properties', () => {
            const template: Template = {
                Resources: {
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {}
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should handle template with no Resources', () => {
            const template: Template = {};

            const resource = {
                Type: 'AWS::EC2::FlowLog',
                Properties: {
                    LogGroupName: { Ref: 'FlowLogGroup' }
                }
            } as Resource;

            const result = rule.evaluateResource(stackName, template, resource);
            expect(result).toBeNull();
        });

        it('should handle Ref to non-existent resource', () => {
            const template: Template = {
                Resources: {
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogGroupName: { Ref: 'NonExistentLogGroup' }
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should handle Fn::GetAtt with string format', () => {
            const template: Template = {
                Resources: {
                    FlowLogGroup: {
                        Type: 'AWS::Logs::LogGroup',
                        Properties: {
                            RetentionInDays: 14
                        }
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::GetAtt': 'FlowLogGroup.Arn' },
                            LogDestinationType: 'cloud-watch-logs',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });

        it('should handle Fn::GetAtt referencing wrong resource type', () => {
            const template: Template = {
                Resources: {
                    SomeQueue: {
                        Type: 'AWS::SQS::Queue',
                        Properties: {}
                    },
                    VpcFlowLog: {
                        Type: 'AWS::EC2::FlowLog',
                        Properties: {
                            LogDestination: { 'Fn::GetAtt': ['SomeQueue', 'Arn'] },
                            LogDestinationType: 'cloud-watch-logs',
                            ResourceId: { Ref: 'TestVpc' },
                            ResourceType: 'VPC',
                            TrafficType: 'ALL'
                        }
                    }
                }
            };

            const result = rule.evaluateResource(stackName, template, template.Resources!['VpcFlowLog'] as Resource);
            expect(result).toBeNull();
        });
    });

    describe('evaluate', () => {
        it('should return null (legacy stub method)', () => {
            const resource: CloudFormationResource = {
                Type: 'AWS::EC2::FlowLog',
                Properties: {
                    LogGroupName: { Ref: 'FlowLogGroup' }
                },
                LogicalId: 'VpcFlowLog'
            };

            expect(rule.evaluate(resource, stackName)).toBeNull();
        });
    });

    describe('rule properties', () => {
        it('should have correct id and priority', () => {
            expect(rule.id).toBe('VPC-003');
            expect(rule.priority).toBe('HIGH');
        });
    });
});
