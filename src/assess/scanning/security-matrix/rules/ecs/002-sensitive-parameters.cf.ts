import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';
import { hasIntrinsicFunction, containsPattern } from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * ECS-002: Store sensitive parameters in SecureString parameters and/or Secrets Manager
 *
 * Sensitive parameters include API access keys, client secrets, database connection strings
 * with credentials, passwords, SSH private keys, or anything granting system access.
 * Tasks should pull these from secure storage like SSM Parameter Store SecureString or Secrets Manager.
 */
export class Ecs002Rule extends BaseRule {
  private static readonly SAFE_ENV_VARS: ReadonlySet<string> = new Set([
    // AWS SDK configuration
    'aws_nodejs_connection_reuse_enabled',
    'aws_max_attempts',
    'aws_retry_mode',
    'aws_metadata_service_timeout',
    'aws_metadata_service_num_attempts',
    'aws_endpoint_url',
    'aws_ignore_configured_endpoint_urls',
    'aws_enable_endpoint_discovery',
    'aws_use_dualstack_endpoint',
    'aws_use_fips_endpoint',
    'aws_ec2_metadata_disabled',
    'aws_ec2_metadata_v1_disabled',
    'aws_request_min_compression_size_bytes',
    'aws_disable_request_compression',
    'aws_defaults_mode',
    'aws_ca_bundle',
    // Lambda reserved variables
    'aws_region',
    'aws_default_region',
    'aws_execution_env',
    'aws_lambda_function_name',
    'aws_lambda_function_memory_size',
    'aws_lambda_function_version',
    'aws_lambda_initialization_type',
    'aws_lambda_log_group_name',
    'aws_lambda_log_stream_name',
    'aws_lambda_runtime_api',
    'lambda_task_root',
    'lambda_runtime_dir',
    // Common non-sensitive configuration
    'node_env',
    'node_options',
    'log_level',
    'debug',
    'tz',
    'lang',
    'lc_all',
    // Connection pool/timeout settings
    'connection_timeout',
    'connection_pool_size',
    'max_connections',
    'idle_timeout',
    'keep_alive_timeout',
  ]);

  private static readonly SENSITIVE_NAME_PATTERNS: readonly RegExp[] = [
    /password/i, /passwd/i, /secret/i, /token/i, /cred/i,
    /private_key/i, /privatekey/i, /ssh_key/i,
    /api_key/i, /apikey/i, /conn_str/i, /connection_string/i,
    /oauth/i, /jwt/i
  ];

  private static readonly VALID_SECRET_PATTERNS: readonly RegExp[] = [
    /secretsmanager/i, /ssm/i, /arn:aws:secretsmanager/i, /arn:aws:ssm/i,
    /SecretString/i, /SecureString/i, /Parameter/i,
    /fromSecretAttributes/i, /fromSecretName/i, /fromSecretPartialArn/i,
    /fromSecretCompleteArn/i, /valueFromLookup/i, /valueForStringParameter/i,
    /stringValue/i, /stringParameter/i, /Token/i, /CfnSecret/i, /CfnParameter/i
  ];

  constructor() {
    super(
      'ECS-002',
      'HIGH',
      'ECS task may not be using secure parameter storage for sensitive information',
      ['AWS::ECS::TaskDefinition']
    );
  }

  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
    if (!this.appliesTo(resource.Type)) return null;

    const containers = resource.Properties?.ContainerDefinitions;
    if (!this.hasContainers(containers)) return null;

    for (const container of containers as Record<string, unknown>[]) {
      const envVarResult = this.checkEnvironmentVariables(stackName, template, resource, container);
      if (envVarResult) return envVarResult;

      const secretResult = this.checkSecrets(stackName, template, resource, container);
      if (secretResult) return secretResult;
    }

    return null;
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    return null;
  }

  private hasContainers(containers: unknown): containers is unknown[] {
    return Array.isArray(containers) && containers.length > 0;
  }

  private checkEnvironmentVariables(
    stackName: string,
    template: Template,
    resource: Resource,
    container: Record<string, unknown>
  ): ScanResult | null {
    const envVars = container.Environment;
    if (!Array.isArray(envVars) || envVars.length === 0) return null;

    const sensitiveVars = envVars.filter((env: { Name?: string; Value?: unknown }) =>
      this.isSensitiveEnvVar(env.Name, env.Value)
    );

    if (sensitiveVars.length > 0) {
      const names = sensitiveVars.map((env: { Name?: string }) => env.Name).join(', ');
      return this.createResult(
        stackName,
        template,
        resource,
        `${this.description}. Potentially sensitive environment variables: ${names}`,
        'Store sensitive parameters in AWS Secrets Manager or SSM Parameter Store SecureString.'
      );
    }

    return null;
  }

  private checkSecrets(
    stackName: string,
    template: Template,
    resource: Resource,
    container: Record<string, unknown>
  ): ScanResult | null {
    const secrets = container.Secrets;
    if (!Array.isArray(secrets) || secrets.length === 0) return null;

    for (const secret of secrets) {
      const result = this.validateSecretReference(stackName, template, resource, secret);
      if (result) return result;
    }

    return null;
  }

  private validateSecretReference(
    stackName: string,
    template: Template,
    resource: Resource,
    secret: { ValueFrom?: unknown }
  ): ScanResult | null {
    const valueFrom = secret.ValueFrom;

    if (!valueFrom) {
      return this.createResult(
        stackName,
        template,
        resource,
        `${this.description}. Secret defined without ValueFrom property`,
        'Ensure all secrets reference AWS Secrets Manager or SSM Parameter Store.'
      );
    }

    if (typeof valueFrom === 'string' && !this.isValidSecretString(valueFrom)) {
      return this.createResult(
        stackName,
        template,
        resource,
        `${this.description}. Secret may not reference Secrets Manager or SSM`,
        'Ensure secrets reference AWS Secrets Manager or SSM Parameter Store SecureString.'
      );
    }

    if (typeof valueFrom === 'object' && hasIntrinsicFunction(valueFrom) && !this.isValidSecretIntrinsic(valueFrom)) {
      return this.createResult(
        stackName,
        template,
        resource,
        `${this.description}. Secret intrinsic may not reference Secrets Manager or SSM`,
        'Ensure secrets reference AWS Secrets Manager or SSM Parameter Store SecureString.'
      );
    }

    return null;
  }

  private isValidSecretString(value: string): boolean {
    return value.includes('secretsmanager') ||
      value.includes('ssm') ||
      value.includes('arn:aws:secretsmanager') ||
      value.includes('arn:aws:ssm');
  }

  private isValidSecretIntrinsic(value: unknown): boolean {
    return Ecs002Rule.VALID_SECRET_PATTERNS.some(pattern => containsPattern(value, pattern));
  }

  private isSensitiveEnvVar(name: unknown, value: unknown): boolean {
    if (name === undefined || name === null) return false;
    if (value === undefined || value === null) return false;

    if (typeof name === 'string' && this.isSafeEnvVar(name)) return false;
    if (this.hasSensitiveName(name)) return true;
    if (this.hasSensitiveValue(value)) return true;

    return false;
  }

  private isSafeEnvVar(name: string): boolean {
    return Ecs002Rule.SAFE_ENV_VARS.has(name.toLowerCase());
  }

  private hasSensitiveName(name: unknown): boolean {
    if (typeof name === 'object' && hasIntrinsicFunction(name)) {
      return Ecs002Rule.SENSITIVE_NAME_PATTERNS.some(pattern => containsPattern(name, pattern));
    }

    if (typeof name === 'string') {
      const lower = name.toLowerCase();
      if (this.matchesSensitivePattern(lower)) return true;
      if (this.matchesCompoundPattern(lower)) return true;
    }

    return false;
  }

  private matchesSensitivePattern(name: string): boolean {
    return Ecs002Rule.SENSITIVE_NAME_PATTERNS.some(pattern => pattern.test(name));
  }

  private matchesCompoundPattern(name: string): boolean {
    const hasKey = name.includes('key');
    const hasAuth = name.includes('auth');
    const hasCert = name.includes('cert');

    if (hasKey && this.hasKeyContext(name)) return true;
    if (hasAuth && this.hasAuthContext(name)) return true;
    if (hasCert && this.hasCertContext(name)) return true;

    return false;
  }

  private hasKeyContext(name: string): boolean {
    return name.includes('api') || name.includes('auth') ||
      name.includes('secret') || name.includes('private') ||
      name.includes('access') || name.includes('encrypt');
  }

  private hasAuthContext(name: string): boolean {
    return name.includes('token') || name.includes('key') ||
      name.includes('secret') || name.includes('pass') ||
      name.includes('cred');
  }

  private hasCertContext(name: string): boolean {
    return name.includes('key') || name.includes('private') || name.includes('secret');
  }

  private hasSensitiveValue(value: unknown): boolean {
    if (typeof value === 'string') return this.isStringValueSensitive(value);
    if (typeof value === 'object' && value !== null && hasIntrinsicFunction(value)) {
      return this.isIntrinsicValueSensitive(value);
    }
    return false;
  }

  private isStringValueSensitive(value: string): boolean {
    if (this.looksLikePrivateKey(value)) return true;
    if (this.looksLikeBase64Secret(value)) return true;
    if (this.looksLikeLongToken(value)) return true;
    if (this.looksLikeConnectionString(value)) return true;
    return false;
  }

  private looksLikePrivateKey(value: string): boolean {
    return value.includes('-----BEGIN') && value.includes('KEY-----');
  }

  private looksLikeBase64Secret(value: string): boolean {
    return /[A-Za-z0-9+/]{40,}={0,2}/.test(value);
  }

  private looksLikeLongToken(value: string): boolean {
    return /[A-Za-z0-9]{20,}/.test(value);
  }

  private looksLikeConnectionString(value: string): boolean {
    return /[a-zA-Z0-9]+:\/\/[^:]+:[^@]+@/.test(value);
  }

  private isIntrinsicValueSensitive(value: unknown): boolean {
    const patterns = [
      /password/i, /passwd/i, /secret/i, /token/i, /cred/i,
      /private[-_]?key/i, /ssh[-_]?key/i, /api[-_]?key/i,
      /conn[-_]?str/i, /connection[-_]?string/i,
      /jdbc:.*@/i, /mongodb:.*@/i, /postgresql:.*@/i,
      /mysql:.*@/i, /redis:.*@/i, /amqp:.*@/i,
      /user(name)?[:=]/i, /pass(word)?[:=]/i
    ];

    if (patterns.some(p => containsPattern(value, p))) return true;
    if (this.hasSensitiveFnSub(value)) return true;
    if (this.hasSensitiveFnJoin(value)) return true;

    return false;
  }

  private hasSensitiveFnSub(value: unknown): boolean {
    const obj = value as Record<string, unknown>;
    if (!obj['Fn::Sub'] || typeof obj['Fn::Sub'] !== 'string') return false;

    const subString = obj['Fn::Sub'];
    const patterns = [
      /\${[^}]*pass(word)?[^}]*}/i,
      /\${[^}]*secret[^}]*}/i,
      /\${[^}]*token[^}]*}/i,
      /\${[^}]*cred[^}]*}/i
    ];

    return patterns.some(p => p.test(subString));
  }

  private hasSensitiveFnJoin(value: unknown): boolean {
    const obj = value as Record<string, unknown>;
    const fnJoin = obj['Fn::Join'];
    if (!Array.isArray(fnJoin) || fnJoin.length !== 2) return false;

    const joinParts = fnJoin[1];
    if (!Array.isArray(joinParts)) return false;

    const joinStr = JSON.stringify(joinParts);
    return joinStr.includes('://') &&
      (joinStr.includes('@') || joinStr.includes('password') || joinStr.includes('Password'));
  }
}

// Export both for backwards compatibility
export { Ecs002Rule as ECS002Rule };
export default new Ecs002Rule();
