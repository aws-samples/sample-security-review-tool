const ELB_TOKEN = 'ELB';
const VPC_LATTICE_TOKEN = 'VPC_LATTICE';

/**
 * True when the health check type names a service whose checks reflect
 * application health: Elastic Load Balancing or VPC Lattice. The type may name
 * several services as a comma-separated list.
 *
 * Both tokens are recognised only in their exact upper-case form, because the
 * service treats any other casing as an unknown type and falls back to instance
 * status checks alone.
 */
export function namesApplicationHealthCheck(healthCheckType: string): boolean {
  return splitTokens(healthCheckType).some(isApplicationHealthCheckToken);
}

function splitTokens(healthCheckType: string): string[] {
  return healthCheckType.split(',').map(token => token.trim());
}

function isApplicationHealthCheckToken(token: string): boolean {
  return token === ELB_TOKEN || token === VPC_LATTICE_TOKEN;
}
