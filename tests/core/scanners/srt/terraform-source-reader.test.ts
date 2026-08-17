import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { readTerraformSource } from '../../../../src/assess/scanning/security-matrix/terraform-source-reader.js';
import { isUnresolved } from '../../../../src/assess/scanning/security-matrix/terraform-rule-base.js';

describe('TerraformSourceReader', () => {
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tf-source-reader-'));
  });

  afterAll(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  async function writeProject(files: Record<string, string>): Promise<string> {
    const projectDir = await fs.mkdtemp(path.join(tmpDir, 'project-'));

    for (const [relativePath, content] of Object.entries(files)) {
      const filePath = path.join(projectDir, relativePath);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, content, 'utf-8');
    }

    return projectDir;
  }

  it('reads literal values with their types preserved', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        resource "aws_api_gateway_stage" "prod" {
          stage_name           = "prod"
          xray_tracing_enabled = true
        }
      `
    });

    const resources = await readTerraformSource(projectDir);

    expect(resources).toHaveLength(1);
    expect(resources[0].type).toBe('aws_api_gateway_stage');
    expect(resources[0].name).toBe('prod');
    expect(resources[0].address).toBe('aws_api_gateway_stage.prod');
    expect(resources[0].values.stage_name).toBe('prod');
    expect(resources[0].values.xray_tracing_enabled).toBe(true);
  });

  it('collapses a reference to the target address so adapters can match it', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        resource "aws_wafv2_web_acl_association" "a" {
          resource_arn = aws_api_gateway_stage.prod.arn
          web_acl_arn  = aws_wafv2_web_acl.acl.arn
        }
      `
    });

    const [association] = await readTerraformSource(projectDir);

    expect(association.values.resource_arn).toBe('aws_api_gateway_stage.prod');
    expect(association.values.web_acl_arn).toBe('aws_wafv2_web_acl.acl');
  });

  it('collapses references inside nested blocks', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        resource "aws_api_gateway_stage" "prod" {
          access_log_settings {
            destination_arn = aws_cloudwatch_log_group.lg.arn
          }
        }
      `
    });

    const [stage] = await readTerraformSource(projectDir);

    expect(stage.values.access_log_settings[0].destination_arn).toBe('aws_cloudwatch_log_group.lg');
  });

  it('leaves a string that interpolates into surrounding text intact', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        resource "aws_s3_bucket" "b" {
          bucket = "\${aws_s3_bucket.other.id}-logs"
        }
      `
    });

    const [bucket] = await readTerraformSource(projectDir);

    expect(bucket.values.bucket).toBe('${aws_s3_bucket.other.id}-logs');
  });

  it('resolves a variable to its declared default', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        variable "bucket_name" {
          default = "my-bucket"
        }
        resource "aws_s3_bucket" "b" {
          bucket = var.bucket_name
        }
      `
    });

    const [bucket] = await readTerraformSource(projectDir);

    expect(bucket.values.bucket).toBe('my-bucket');
  });

  it('keeps a zero default rather than treating it as absent', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        variable "cooldown" {
          default = 0
        }
        resource "aws_autoscaling_group" "a" {
          default_cooldown = var.cooldown
        }
      `
    });

    const [group] = await readTerraformSource(projectDir);

    expect(group.values.default_cooldown).toBe(0);
  });

  it('marks a variable with no default as unresolved', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        variable "cooldown" {
          type = number
        }
        resource "aws_autoscaling_group" "a" {
          default_cooldown = var.cooldown
        }
      `
    });

    const [group] = await readTerraformSource(projectDir);

    expect(isUnresolved(group.values.default_cooldown)).toBe(true);
  });

  it('marks a variable declared in another file as unresolved, because defaults resolve per file', async () => {
    const projectDir = await writeProject({
      'variables.tf': 'variable "cooldown" { default = 300 }',
      'main.tf': 'resource "aws_autoscaling_group" "a" { default_cooldown = var.cooldown }'
    });

    const group = (await readTerraformSource(projectDir)).find(resource => resource.type === 'aws_autoscaling_group')!;

    expect(isUnresolved(group.values.default_cooldown)).toBe(true);
  });

  it('marks locals, data sources and module outputs as unresolved', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        resource "aws_autoscaling_group" "a" {
          from_local  = local.cooldown
          from_data   = data.aws_ami.chosen.id
          from_module = module.sizing.cooldown
        }
      `
    });

    const [group] = await readTerraformSource(projectDir);

    expect(isUnresolved(group.values.from_local)).toBe(true);
    expect(isUnresolved(group.values.from_data)).toBe(true);
    expect(isUnresolved(group.values.from_module)).toBe(true);
  });

  it('treats a resource reference as an address, not as an unresolved value', async () => {
    const projectDir = await writeProject({
      'main.tf': `
        resource "aws_launch_template" "lt" { name = "lt" }
        resource "aws_autoscaling_group" "a" {
          launch_template_id = aws_launch_template.lt.id
        }
      `
    });

    const group = (await readTerraformSource(projectDir)).find(resource => resource.type === 'aws_autoscaling_group')!;

    expect(group.values.launch_template_id).toBe('aws_launch_template.lt');
    expect(isUnresolved(group.values.launch_template_id)).toBe(false);
  });

  it('reads resources from downloaded modules using plan-style addresses', async () => {
    const projectDir = await writeProject({
      'main.tf': 'resource "aws_s3_bucket" "root" { bucket = "root" }',
      '.terraform/modules/modules.json': JSON.stringify({
        Modules: [
          { Key: '', Dir: '.' },
          { Key: 'storage', Dir: '.terraform/modules/storage' }
        ]
      }),
      '.terraform/modules/storage/main.tf': 'resource "aws_s3_bucket" "inner" { bucket = "inner" }'
    });

    const addresses = (await readTerraformSource(projectDir)).map(resource => resource.address);

    expect(addresses).toContain('aws_s3_bucket.root');
    expect(addresses).toContain('module.storage.aws_s3_bucket.inner');
  });

  it('returns nothing for a directory with no Terraform files', async () => {
    const projectDir = await writeProject({ 'README.md': 'no terraform here' });

    expect(await readTerraformSource(projectDir)).toEqual([]);
  });
});
