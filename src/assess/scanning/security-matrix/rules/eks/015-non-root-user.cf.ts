import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS15 Rule: Ensure that applications within the cluster are running as a non-root user.
 * 
 * Documentation: "Containers run as root by default. While this allows them to read the web identity token file, 
 * running a container as root is not considered a best practice."
 * 
 * Note: This rule is more of a guidance than a strict rule as CloudFormation templates may not contain 
 * all the information needed to fully validate container user configurations.
 */
export class EKS015Rule extends BaseRule {
  constructor() {
    super(
      'EKS-015',
      'HIGH',
      'EKS cluster applications may be running as root user',
      ['AWS::EKS::Cluster', 'Custom::AWSQS-KubernetesResource', 'Custom::KubernetesResource']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Check if this is an EKS cluster
    if (resource.Type === 'AWS::EKS::Cluster') {
      // For EKS clusters, we can only provide general guidance
      // since the actual container configurations are not part of the cluster definition
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (general guidance)`,
        `Ensure all container definitions include 'runAsNonRoot: true' and specify a non-root user ID in the security context.`
      );
    }

    // Check Kubernetes resources for container definitions
    if (resource.Type === 'Custom::AWSQS-KubernetesResource' ||
      resource.Type === 'Custom::KubernetesResource') {

      const manifest = resource.Properties?.Manifest;

      if (manifest) {
        let manifestObj;

        // Parse the manifest if it's a string
        if (typeof manifest === 'string') {
          try {
            manifestObj = JSON.parse(manifest);
          } catch (e) {
            // If it's not valid JSON, it might be YAML or some other format
            // We'll do a simple string search for indicators
            if (manifest.includes('containers:') || manifest.includes('kind: Pod') ||
              manifest.includes('kind: Deployment') || manifest.includes('kind: StatefulSet')) {

              // Check if security context with runAsNonRoot is defined
              if (!manifest.includes('runAsNonRoot: true') &&
                !manifest.includes('runAsUser:') &&
                !manifest.includes('securityContext:')) {

                return this.createScanResult(
                  resource,
                  stackName,
                  `${this.description} (no security context with runAsNonRoot found in manifest)`,
                  `Add securityContext with runAsNonRoot: true and specify a non-root user ID.`
                );
              }
            }

            return null;
          }
        } else {
          manifestObj = manifest;
        }

        // If we have a parsed manifest object, check for container definitions
        if (manifestObj && typeof manifestObj === 'object') {
          const kind = manifestObj.kind;

          if (kind === 'Pod' || kind === 'Deployment' || kind === 'StatefulSet' ||
            kind === 'DaemonSet' || kind === 'Job' || kind === 'CronJob') {

            // Check for security context in the spec
            const spec = manifestObj.spec;
            if (!spec) {
              return null;
            }

            // For CronJob, the spec is nested
            const podSpec = kind === 'CronJob'
              ? spec.jobTemplate?.spec?.template?.spec
              : (kind === 'Deployment' || kind === 'StatefulSet' || kind === 'DaemonSet' || kind === 'Job')
                ? spec.template?.spec
                : spec;

            if (!podSpec) {
              return null;
            }

            // Check pod-level security context
            const podSecurityContext = podSpec.securityContext;
            const hasNonRootAtPodLevel = podSecurityContext &&
              (podSecurityContext.runAsNonRoot === true ||
                (typeof podSecurityContext.runAsUser === 'number' &&
                  podSecurityContext.runAsUser > 0));

            if (!hasNonRootAtPodLevel) {
              // Check container-level security contexts
              const containers = podSpec.containers;

              if (containers && Array.isArray(containers)) {
                const allContainersNonRoot = containers.every(container => {
                  const securityContext = container.securityContext;
                  return securityContext &&
                    (securityContext.runAsNonRoot === true ||
                      (typeof securityContext.runAsUser === 'number' &&
                        securityContext.runAsUser > 0));
                });

                if (!allContainersNonRoot) {
                  return this.createScanResult(
                    resource,
                    stackName,
                    `${this.description} (containers without non-root security context)`,
                    `Add securityContext with runAsNonRoot: true or specify a non-root runAsUser for all containers.`
                  );
                }
              } else {
                return this.createScanResult(
                  resource,
                  stackName,
                  `${this.description} (no pod-level security context with non-root configuration)`,
                  `Add securityContext with runAsNonRoot: true at the pod level or for each container.`
                );
              }
            }
          }
        }
      }
    }

    return null;
  }
}

export default new EKS015Rule();
