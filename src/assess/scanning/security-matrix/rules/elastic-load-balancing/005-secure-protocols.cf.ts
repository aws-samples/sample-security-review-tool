import { BaseRule, CloudFormationResource } from "../../security-rule-base.js";
import { ScanResult } from "../../../base-scanner.js";

/**
 * ELB5 Rule: Use secure protocols and disable weak SSL/TLS versions
 *
 * Solution ELB listeners should be deployed for secure configurations. Solutions should use HTTPS or SSL protocols
 * to encrypt the communication between the client and your load balancers. SSL protocols should not be enabled
 * and any version of TLS 1.1 or below should not be enabled.
 */
export class Elb005Rule extends BaseRule {
  constructor() {
    super(
      "ELB-005",
      "HIGH",
      "Load balancer listener uses insecure protocols or weak SSL/TLS versions",
      [
        "AWS::ElasticLoadBalancing::LoadBalancer",
        "AWS::ElasticLoadBalancingV2::Listener",
      ]
    );
  }

  //https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html#tls-cipher-policies
  private readonly WEAK_SSL_POLICIES = [
    // Policies that support TLS 1.1 or TLS 1.0 (from AWS documentation)
    "ELBSecurityPolicy-TLS13-1-1-2021-06", // Supports TLS 1.1
    "ELBSecurityPolicy-TLS13-1-0-2021-06", // Supports TLS 1.0 and 1.1
    "ELBSecurityPolicy-TLS-1-1-2017-01", // Supports TLS 1.1
    "ELBSecurityPolicy-2016-08", // Supports TLS 1.0 and 1.1
    "ELBSecurityPolicy-2015-05", // Supports TLS 1.0 and 1.1
    // FIPS policies that support TLS 1.1 or 1.0
    "ELBSecurityPolicy-TLS13-1-1-FIPS-2023-04", // Supports TLS 1.1
    "ELBSecurityPolicy-TLS13-1-0-FIPS-2023-04", // Supports TLS 1.0 and 1.1
    // FS policies that support TLS 1.1 or 1.0
    "ELBSecurityPolicy-FS-1-1-2019-08", // Supports TLS 1.1
    "ELBSecurityPolicy-FS-2018-06", // Supports TLS 1.0 and 1.1
  ];

  public evaluate(
    resource: CloudFormationResource,
    stackName: string
  ): ScanResult | null {
    if (resource.Type === "AWS::ElasticLoadBalancing::LoadBalancer") {
      // Classic Load Balancer
      const listeners = resource.Properties?.Listeners;
      if (!listeners || !Array.isArray(listeners)) {
        return null;
      }

      for (const listener of listeners) {
        const protocol = listener.Protocol;

        // Check for insecure protocols
        if (protocol === "HTTP" || protocol === "TCP") {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Use HTTPS or SSL protocol instead of ${protocol} for secure communication`
          );
        }

        // Check SSL policy for HTTPS/SSL listeners
        if (
          (protocol === "HTTPS" || protocol === "SSL") &&
          listener.SSLCertificateId
        ) {
          const sslPolicy = listener.PolicyNames;
          if (sslPolicy && Array.isArray(sslPolicy)) {
            const hasWeakPolicy = sslPolicy.some((policy: string) =>
              this.WEAK_SSL_POLICIES.includes(policy)
            );
            if (hasWeakPolicy) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Use a secure SSL policy like ELBSecurityPolicy-TLS-1-2-2017-01 or newer`
              );
            }
          }
        }
      }
    } else if (resource.Type === "AWS::ElasticLoadBalancingV2::Listener") {
      // ALB/NLB Listener
      const protocol = resource.Properties?.Protocol;

      // Check for insecure protocols
      if (protocol === "HTTP" || protocol === "TCP") {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Use HTTPS or TLS protocol instead of ${protocol} for secure communication`
        );
      }

      // Check SSL policy for HTTPS/TLS listeners
      if (
        (protocol === "HTTPS" || protocol === "TLS") &&
        resource.Properties?.Certificates
      ) {
        const sslPolicy = resource.Properties?.SslPolicy;
        if (!sslPolicy || this.WEAK_SSL_POLICIES.includes(sslPolicy)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set SslPolicy to ELBSecurityPolicy-TLS-1-2-2017-01 or newer secure policy`
          );
        }
      }
    }

    return null;
  }
}

export default new Elb005Rule();
