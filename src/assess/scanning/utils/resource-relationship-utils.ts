/**
 * Utility functions for analyzing relationships between resources in CloudFormation templates
 */
import { CloudFormationResource } from '../security-matrix/security-rule-base.js';
import { hasIntrinsicFunction, isReferenceToResource, extractResourceIdsFromReference } from './cloudformation-intrinsic-utils.js';

/**
 * Builds a graph of relationships between resources
 * @param resources All resources in the template
 * @returns Map of resource IDs to arrays of referenced resource IDs
 */
export function buildRelationshipGraph(resources: CloudFormationResource[]): Map<string, string[]> {
  const graph = new Map<string, string[]>();

  // Initialize graph with empty arrays for each resource
  for (const resource of resources) {
    if (resource.LogicalId) {
      graph.set(resource.LogicalId, []);
    }
  }

  // Find references between resources
  for (const resource of resources) {
    if (!resource.LogicalId) continue;

    const sourceId = resource.LogicalId;
    const references: string[] = [];

    // Convert resource to string and extract all potential references
    const resourceStr = JSON.stringify(resource);

    // Check for references to other resources
    for (const target of resources) {
      if (!target.LogicalId || target.LogicalId === sourceId) continue;

      if (resourceStr.includes(target.LogicalId)) {
        // Further verify it's a real reference
        const isRealReference = containsReferenceToResource(resource, target.LogicalId);
        if (isRealReference) {
          references.push(target.LogicalId);
        }
      }
    }

    graph.set(sourceId, references);
  }

  return graph;
}

/**
 * Finds all resources that reference a specific resource
 * @param targetId The ID of the resource to find references to
 * @param resources All resources in the template
 * @returns Array of resources that reference the target resource
 */
export function findReferencingResources(targetId: string, resources: CloudFormationResource[]): CloudFormationResource[] {
  return resources.filter(resource => {
    return containsReferenceToResource(resource, targetId);
  });
}

/**
 * Finds all resources that are referenced by a specific resource
 * @param sourceId The ID of the resource to find references from
 * @param resources All resources in the template
 * @returns Array of resources that are referenced by the source resource
 */
export function findReferencedResources(sourceId: string, resources: CloudFormationResource[]): CloudFormationResource[] {
  const source = resources.find(r => r.LogicalId === sourceId);
  if (!source) return [];

  return resources.filter(target => {
    if (target.LogicalId === sourceId) return false;
    return containsReferenceToResource(source, target.LogicalId);
  });
}

/**
 * Checks if a resource contains a reference to another resource
 * @param resource The resource to check
 * @param targetId The ID of the resource to find references to
 * @returns True if the resource contains a reference to the target resource, false otherwise
 */
export function containsReferenceToResource(resource: any, targetId: string): boolean {
  // Handle null or undefined
  if (!resource) return false;

  // Handle primitive types
  if (typeof resource !== 'object') return false;

  // Handle arrays
  if (Array.isArray(resource)) {
    return resource.some(item => containsReferenceToResource(item, targetId));
  }

  // Check if this object is a reference to the target
  if (isReferenceToResource(resource, targetId)) {
    return true;
  }

  // Recursively check all properties
  for (const key in resource) {
    if (containsReferenceToResource(resource[key], targetId)) {
      return true;
    }
  }

  return false;
}

/**
 * Finds resources of specific types that are related to a given resource
 * @param resource The resource to find related resources for
 * @param resourceTypes Array of resource types to look for
 * @param allResources All resources in the template
 * @returns Array of related resources of the specified types
 */
export function findRelatedResourcesByType(
  resource: CloudFormationResource,
  resourceTypes: string[],
  allResources: CloudFormationResource[]
): CloudFormationResource[] {
  if (!resource.LogicalId) return [];

  // Get resources of the specified types
  const typedResources = allResources.filter(r => resourceTypes.includes(r.Type));

  // Find resources that reference this resource
  const referencingResources = typedResources.filter(r =>
    containsReferenceToResource(r, resource.LogicalId)
  );

  // Find resources that are referenced by this resource
  const referencedResources = typedResources.filter(r =>
    r.LogicalId && containsReferenceToResource(resource, r.LogicalId)
  );

  // Combine and deduplicate
  const relatedResources = [...referencingResources, ...referencedResources];
  const uniqueResources = relatedResources.filter((resource, index, self) =>
    index === self.findIndex(r => r.LogicalId === resource.LogicalId)
  );

  return uniqueResources;
}

/**
 * Checks if a resource has a relationship with any resource of specific types
 * @param resource The resource to check relationships for
 * @param resourceTypes Array of resource types to look for relationships with
 * @param allResources All resources in the template
 * @returns True if the resource has a relationship with any resource of the specified types, false otherwise
 */
export function hasRelationshipWithResourceTypes(
  resource: CloudFormationResource,
  resourceTypes: string[],
  allResources: CloudFormationResource[]
): boolean {
  const relatedResources = findRelatedResourcesByType(resource, resourceTypes, allResources);
  return relatedResources.length > 0;
}

/**
 * Finds a chain of references between two resources
 * @param sourceId The ID of the source resource
 * @param targetId The ID of the target resource
 * @param allResources All resources in the template
 * @param maxDepth Maximum depth to search (default: 5)
 * @returns Array of resource IDs forming the chain, or empty array if no chain found
 */
export function findReferenceChain(
  sourceId: string,
  targetId: string,
  allResources: CloudFormationResource[],
  maxDepth: number = 5
): string[] {
  // Build the relationship graph
  const graph = buildRelationshipGraph(allResources);

  // Use breadth-first search to find the shortest path
  const queue: Array<{ id: string, path: string[] }> = [{ id: sourceId, path: [sourceId] }];
  const visited = new Set<string>([sourceId]);

  while (queue.length > 0) {
    const { id, path } = queue.shift()!;

    // Check if we've reached the target
    if (id === targetId) {
      return path;
    }

    // Check if we've reached the maximum depth
    if (path.length > maxDepth) {
      continue;
    }

    // Add all neighbors to the queue
    const neighbors = graph.get(id) || [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push({ id: neighbor, path: [...path, neighbor] });
      }
    }
  }

  return []; // No path found
}
