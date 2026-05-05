import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { hasIntrinsicFunction, containsPattern } from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * NF2 Rule: Define rules to allow only necessary traffic and default any as implicit rule.
 * Use Security Groups in conjunction with Network Firewall for layered protection.
 * Leverage AWS Firewall Manager to centrally manage and audit firewall policies.
 * Inspect and remediate permissive firewall configurations detected in AWS Security Hub.
 * 
 * Documentation: "Define rules to allow only necessary traffic and default any as implicit rule. 
 * Use Security Groups in conjunction with Network Firewall for layered protection. 
 * Leverage AWS Firewall Manager to centrally manage and audit firewall policies.
 * Inspect and remediate permissive firewall configurations detected in AWS Security Hub."
 * 
 * Note: Basic firewall configuration checks are covered by Checkov rules:
 * - CKV_AWS_232: Checks if Network Firewall has a default stateless action of drop or forward to stateful rule
 * - CKV_AWS_351: Checks if Network Firewall Policy has a stateless default action of drop for both FWP and packets
 */
export class NF002Rule extends BaseRule {
  constructor() {
    super(
      'NF-002',
      'HIGH',
      'Network Firewall has insufficient or permissive configuration',
      ['AWS::NetworkFirewall::Firewall', 'AWS::NetworkFirewall::FirewallPolicy', 'AWS::NetworkFirewall::RuleGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check Network Firewall configuration
    if (resource.Type === 'AWS::NetworkFirewall::Firewall') {
      // Check if the firewall is associated with a policy
      const firewallPolicyArn = resource.Properties?.FirewallPolicyArn;

      // Handle both direct values and intrinsic functions/CDK tokens
      if (!firewallPolicyArn && !hasIntrinsicFunction(resource.Properties?.FirewallPolicyArn)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}: Firewall is not associated with a policy`,
          `Associate the firewall with a properly configured firewall policy.`
        );
      }

      // Check if the firewall is deployed in multiple subnets for high availability
      const subnetMappings = resource.Properties?.SubnetMappings;

      // Handle both direct values and intrinsic functions/CDK tokens
      if (hasIntrinsicFunction(subnetMappings)) {
        // If it's an intrinsic function, we can't determine the exact number of subnets
        // Skip this check as we can't reliably determine the number of subnets
      } else if (!subnetMappings || !Array.isArray(subnetMappings) || subnetMappings.length < 2) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}: Firewall is not deployed in multiple subnets for high availability`,
          `Deploy the firewall in at least two different subnets across different Availability Zones.`
        );
      }

      // Check if logging is enabled
      const loggingConfiguration = resource.Properties?.LoggingConfiguration;

      // Handle both direct values and intrinsic functions/CDK tokens
      if (!loggingConfiguration && !hasIntrinsicFunction(resource.Properties?.LoggingConfiguration)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}: Firewall logging is not configured`,
          `Enable logging to monitor and audit network traffic.`
        );
      }
    }

    // Check Firewall Policy configuration
    if (resource.Type === 'AWS::NetworkFirewall::FirewallPolicy') {
      // Skip basic checks for stateless default actions as they're covered by Checkov

      // Check for integration with Firewall Manager
      const tags = resource.Properties?.Tags;

      // Handle both direct values and intrinsic functions/CDK tokens
      let hasFirewallManagerTag = false;

      if (hasIntrinsicFunction(tags)) {
        // If tags are defined using intrinsic functions, we can't reliably check them
        // Skip this check as we can't determine the tags reliably
      } else if (tags && Array.isArray(tags)) {
        hasFirewallManagerTag = tags.some(tag => {
          // Check for direct key/value pairs
          if (tag.Key === 'aws:cloudformation:stack-name') {
            if (typeof tag.Value === 'string' &&
              (tag.Value.includes('FMS') || tag.Value.includes('FirewallManager'))) {
              return true;
            }

            // Check for intrinsic functions in the tag value
            if (hasIntrinsicFunction(tag.Value)) {
              // If the value is an intrinsic function, check if it might contain FMS or FirewallManager
              return containsPattern(tag.Value, /(FMS|FirewallManager)/);
            }
          }
          return false;
        });
      }

      if (!hasFirewallManagerTag) {
        // This is an enhanced check beyond what Checkov covers
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}: Firewall policy is not managed by AWS Firewall Manager`,
          `Consider using AWS Firewall Manager for centralized management and auditing of firewall policies.`
        );
      }

      // Check for stateful rule groups
      const statefulRuleGroupReferences = resource.Properties?.FirewallPolicy?.StatefulRuleGroupReferences;

      // Handle both direct values and intrinsic functions/CDK tokens
      if (hasIntrinsicFunction(statefulRuleGroupReferences)) {
        // If it's an intrinsic function, we can't determine if there are rule groups
        // Skip this check as we can't reliably determine the rule groups
      } else if (!statefulRuleGroupReferences || !Array.isArray(statefulRuleGroupReferences) || statefulRuleGroupReferences.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}: Firewall policy does not have any stateful rule groups`,
          `Configure stateful rule groups to inspect and filter traffic based on connection state.`
        );
      }

      // Check for Security Hub integration
      const securityHubIntegration = this.checkSecurityHubIntegration(resource, allResources);
      if (!securityHubIntegration) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}: No evidence of Security Hub integration for monitoring firewall configurations`,
          `Enable AWS Security Hub and configure it to monitor Network Firewall configurations.`
        );
      }
    }

    // Check Rule Group configuration
    if (resource.Type === 'AWS::NetworkFirewall::RuleGroup') {
      const ruleGroup = resource.Properties?.RuleGroup;

      // Check if rule group is properly configured
      if (!ruleGroup && !hasIntrinsicFunction(resource.Properties?.RuleGroup)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}: Rule group is not properly configured`,
          `Define appropriate rules in the rule group.`
        );
      }

      // For stateless rule groups, check if there's a default action
      if (resource.Properties?.Type === 'STATELESS') {
        const statelessRules = ruleGroup?.RulesSource?.StatelessRulesAndCustomActions;

        // Handle both direct values and intrinsic functions/CDK tokens
        if (hasIntrinsicFunction(statelessRules)) {
          // If it's an intrinsic function, we can't determine if there are rules
          // Skip this check as we can't reliably determine the rules
        } else if (!statelessRules || !Array.isArray(statelessRules.StatelessRules) || statelessRules.StatelessRules.length === 0) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}: Stateless rule group does not have any rules defined`,
            `Define specific stateless rules to filter traffic.`
          );
        } else {
          // Check if rules are overly permissive
          const hasOverlyPermissiveRule = this.checkForOverlyPermissiveRules(statelessRules.StatelessRules);
          if (hasOverlyPermissiveRule) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}: Rule group contains overly permissive rules`,
              `Review and restrict rules to allow only necessary traffic.`
            );
          }
        }
      }

      // For stateful rule groups, check if there are appropriate rules
      if (resource.Properties?.Type === 'STATEFUL') {
        const rulesSource = ruleGroup?.RulesSource;

        // Handle both direct values and intrinsic functions/CDK tokens
        if (hasIntrinsicFunction(rulesSource)) {
          // If it's an intrinsic function, we can't determine if there are rules
          // Skip this check as we can't reliably determine the rules
        } else if (!rulesSource ||
          (!rulesSource.RulesString &&
            !rulesSource.RulesSourceList &&
            !rulesSource.StatefulRules &&
            !hasIntrinsicFunction(rulesSource.RulesString) &&
            !hasIntrinsicFunction(rulesSource.RulesSourceList) &&
            !hasIntrinsicFunction(rulesSource.StatefulRules))) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}: Stateful rule group does not have any rules defined`,
            `Define specific stateful rules to inspect traffic.`
          );
        }

        // If using domain lists, check if they're restrictive enough
        if (rulesSource?.RulesSourceList) {
          const targets = rulesSource.RulesSourceList.Targets;

          // Handle both direct values and intrinsic functions/CDK tokens
          if (hasIntrinsicFunction(targets)) {
            // If it's an intrinsic function, we can't determine if there are targets
            // Skip this check as we can't reliably determine the targets
          } else if (!targets || !Array.isArray(targets) || targets.length === 0) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}: Domain list in rule group is empty`,
              `Specify target domains to filter.`
            );
          } else {
            // Check if the domain list is too permissive (e.g., contains wildcards)
            const hasTooPermissiveDomain = targets.some(target => {
              if (typeof target === 'string') {
                return target === '*' || target === '.*';
              }
              // Check for wildcard patterns in intrinsic functions
              return containsPattern(target, /(\*|\.\*)/);
            });

            if (hasTooPermissiveDomain) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description}: Domain list contains overly permissive wildcards`,
                `Specify explicit domains instead of using wildcards.`
              );
            }
          }
        }
      }
    }

    return null;
  }

  private checkSecurityHubIntegration(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // Check if Security Hub is enabled in the template
    if (!allResources) return false;

    return allResources.some(res =>
      res.Type === 'AWS::SecurityHub::Hub' ||
      res.Type === 'AWS::SecurityHub::StandardsSubscription' ||
      (res.Type === 'AWS::Events::Rule' &&
        res.Properties?.EventPattern?.source?.includes('aws.securityhub'))
    );
  }

  private checkForOverlyPermissiveRules(rules: any[]): boolean {
    if (!rules || !Array.isArray(rules)) return false;

    return rules.some(rule => {
      // Handle intrinsic functions in rule definition
      if (hasIntrinsicFunction(rule)) {
        // If the rule is defined using intrinsic functions, check for patterns that might indicate permissive rules
        return containsPattern(rule, /(0\.0\.0\.0\/0)|(Protocols.*0)/);
      }

      const match = rule.RuleDefinition?.MatchAttributes;
      if (!match) return false;

      // Check for rules that allow all protocols
      if (match.Protocols) {
        if (Array.isArray(match.Protocols) && match.Protocols.includes(0)) {
          return true;
        }
        // Check for protocol 0 in intrinsic functions
        if (hasIntrinsicFunction(match.Protocols) && containsPattern(match.Protocols, /0/)) {
          return true;
        }
      }

      // Check for rules with overly permissive source or destination
      const sources = match.Sources || [];
      const destinations = match.Destinations || [];

      const hasPermissiveSource = sources.some((src: any) => {
        if (typeof src === 'object' && src !== null) {
          if (typeof src.AddressDefinition === 'string') {
            return src.AddressDefinition === '0.0.0.0/0';
          }
          // Check for 0.0.0.0/0 in intrinsic functions
          return containsPattern(src.AddressDefinition, /0\.0\.0\.0\/0/);
        }
        return false;
      });

      const hasPermissiveDestination = destinations.some((dest: any) => {
        if (typeof dest === 'object' && dest !== null) {
          if (typeof dest.AddressDefinition === 'string') {
            return dest.AddressDefinition === '0.0.0.0/0';
          }
          // Check for 0.0.0.0/0 in intrinsic functions
          return containsPattern(dest.AddressDefinition, /0\.0\.0\.0\/0/);
        }
        return false;
      });

      return hasPermissiveSource && hasPermissiveDestination;
    });
  }
}

export default new NF002Rule();
