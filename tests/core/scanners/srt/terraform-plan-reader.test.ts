import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { readTerraformPlan } from '../../../../src/assess/scanning/security-matrix/terraform-plan-reader.js';

describe('TerraformPlanReader', () => {
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tf-plan-reader-'));
  });

  afterAll(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  async function writePlan(plan: unknown): Promise<string> {
    const planPath = path.join(tmpDir, `plan-${Math.round(performance.now())}-${Math.random()}.json`);
    await fs.writeFile(planPath, JSON.stringify(plan), 'utf-8');
    return planPath;
  }

  it('returns resources with their resolved literal values', async () => {
    const planPath = await writePlan({
      planned_values: {
        root_module: {
          resources: [
            { type: 'aws_s3_bucket', name: 'b', address: 'aws_s3_bucket.b', values: { bucket: 'my-bucket' } }
          ]
        }
      }
    });

    const resources = await readTerraformPlan(planPath);

    expect(resources).toHaveLength(1);
    expect(resources[0].values.bucket).toBe('my-bucket');
  });

  it('collapses a top-level reference that planned_values dropped because it is unknown at plan time', async () => {
    const planPath = await writePlan({
      planned_values: {
        root_module: {
          resources: [
            { type: 'aws_cloudtrail', name: 'ct', address: 'aws_cloudtrail.ct', values: { name: 'trail' } }
          ]
        }
      },
      configuration: {
        root_module: {
          resources: [
            {
              address: 'aws_cloudtrail.ct',
              type: 'aws_cloudtrail',
              name: 'ct',
              expressions: {
                name: { constant_value: 'trail' },
                s3_bucket_name: { references: ['aws_s3_bucket.logs.id', 'aws_s3_bucket.logs'] }
              }
            }
          ]
        }
      }
    });

    const resources = await readTerraformPlan(planPath);

    expect(resources[0].values.name).toBe('trail');
    expect(resources[0].values.s3_bucket_name).toBe('aws_s3_bucket.logs');
  });

  it('collapses a reference that appears as null in planned_values to the target address', async () => {
    const planPath = await writePlan({
      planned_values: {
        root_module: {
          resources: [
            {
              type: 'aws_s3_bucket_logging',
              name: 'cf_logs',
              address: 'aws_s3_bucket_logging.cf_logs',
              values: { bucket: null, target_prefix: 's3-logs/' }
            }
          ]
        }
      },
      configuration: {
        root_module: {
          resources: [
            {
              address: 'aws_s3_bucket_logging.cf_logs',
              type: 'aws_s3_bucket_logging',
              name: 'cf_logs',
              expressions: {
                bucket: { references: ['aws_s3_bucket.cf_logs.id', 'aws_s3_bucket.cf_logs'] },
                target_prefix: { constant_value: 's3-logs/' }
              }
            }
          ]
        }
      }
    });

    const resources = await readTerraformPlan(planPath);

    expect(resources[0].values.bucket).toBe('aws_s3_bucket.cf_logs');
    expect(resources[0].values.target_prefix).toBe('s3-logs/');
  });

  it('leaves a multi-source reference alone when no single address covers all entries', async () => {
    const planPath = await writePlan({
      planned_values: {
        root_module: {
          resources: [
            { type: 'aws_cloudtrail', name: 'ct', address: 'aws_cloudtrail.ct', values: { s3_bucket_name: null } }
          ]
        }
      },
      configuration: {
        root_module: {
          resources: [
            {
              address: 'aws_cloudtrail.ct',
              type: 'aws_cloudtrail',
              name: 'ct',
              expressions: {
                s3_bucket_name: { references: ['aws_s3_bucket.a.id', 'aws_s3_bucket.b.id'] }
              }
            }
          ]
        }
      }
    });

    const resources = await readTerraformPlan(planPath);
    expect(resources[0].values.s3_bucket_name).toBeNull();
  });

  it('collapses references nested inside block expressions and arrays to addresses', async () => {
    const planPath = await writePlan({
      planned_values: {
        root_module: {
          resources: [
            {
              type: 'aws_cloudtrail',
              name: 'ct',
              address: 'aws_cloudtrail.ct',
              values: {
                event_selector: [{ read_write_type: 'All', data_resource: [{ type: 'AWS::DynamoDB::Table' }] }]
              }
            }
          ]
        }
      },
      configuration: {
        root_module: {
          resources: [
            {
              address: 'aws_cloudtrail.ct',
              type: 'aws_cloudtrail',
              name: 'ct',
              expressions: {
                event_selector: [
                  {
                    read_write_type: { constant_value: 'All' },
                    data_resource: [
                      {
                        type: { constant_value: 'AWS::DynamoDB::Table' },
                        values: { references: ['aws_dynamodb_table.t.arn', 'aws_dynamodb_table.t'] }
                      }
                    ]
                  }
                ]
              }
            }
          ]
        }
      }
    });

    const resources = await readTerraformPlan(planPath);
    const dataResource = resources[0].values.event_selector[0].data_resource[0];

    expect(dataResource.type).toBe('AWS::DynamoDB::Table');
    expect(dataResource.values).toBe('aws_dynamodb_table.t');
  });

  it('does not overwrite a known value with its reference', async () => {
    const planPath = await writePlan({
      planned_values: {
        root_module: {
          resources: [
            { type: 'aws_cloudtrail', name: 'ct', address: 'aws_cloudtrail.ct', values: { s3_bucket_name: 'known-bucket' } }
          ]
        }
      },
      configuration: {
        root_module: {
          resources: [
            {
              address: 'aws_cloudtrail.ct',
              type: 'aws_cloudtrail',
              name: 'ct',
              expressions: { s3_bucket_name: { references: ['aws_s3_bucket.logs.id'] } }
            }
          ]
        }
      }
    });

    const resources = await readTerraformPlan(planPath);

    expect(resources[0].values.s3_bucket_name).toBe('known-bucket');
  });

  it('aligns child-module relative config addresses with full planned_values addresses', async () => {
    const planPath = await writePlan({
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: 'module.m',
              resources: [
                { type: 'aws_cloudtrail', name: 'ct', address: 'module.m.aws_cloudtrail.ct', values: { name: 'trail' } }
              ]
            }
          ]
        }
      },
      configuration: {
        root_module: {
          module_calls: {
            m: {
              module: {
                resources: [
                  {
                    address: 'aws_cloudtrail.ct',
                    type: 'aws_cloudtrail',
                    name: 'ct',
                    expressions: { s3_bucket_name: { references: ['aws_s3_bucket.inner.id'] } }
                  }
                ]
              }
            }
          }
        }
      }
    });

    const resources = await readTerraformPlan(planPath);

    expect(resources[0].address).toBe('module.m.aws_cloudtrail.ct');
    expect(resources[0].values.s3_bucket_name).toBe('aws_s3_bucket.inner');
  });

  it('returns an empty array when the plan has no planned values', async () => {
    const planPath = await writePlan({ format_version: '1.2' });
    expect(await readTerraformPlan(planPath)).toEqual([]);
  });
});
