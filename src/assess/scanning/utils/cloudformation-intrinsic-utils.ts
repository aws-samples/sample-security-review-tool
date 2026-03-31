/**
 * Utility functions for handling CloudFormation intrinsic functions
 */

/**
 * Checks if a value contains CloudFormation intrinsic functions
 * @param obj The value to check
 * @returns True if the value contains intrinsic functions, false otherwise
 */
export function hasIntrinsicFunction(obj: any): boolean {
  if (typeof obj !== 'object' || obj === null) {
    return false;
  }

  // Check for common intrinsic functions
  const intrinsicFunctions = [
    'Ref',
    'Fn::GetAtt',
    'Fn::Sub',
    'Fn::Join',
    'Fn::ImportValue',
    'Fn::If',
    'Fn::Select',
    'Fn::Split',
    'Fn::FindInMap'
  ];

  for (const func of intrinsicFunctions) {
    if (obj[func] !== undefined) {
      return true;
    }
  }

  return false;
}

/**
 * Extracts resource IDs from a reference
 * @param ref The reference to extract from
 * @returns Array of resource IDs or empty array if none found
 */
export function extractResourceIdsFromReference(ref: any): string[] {
  const resourceIds: string[] = [];

  if (!ref) {
    return resourceIds;
  }

  // Direct string reference
  if (typeof ref === 'string') {
    resourceIds.push(ref);
    return resourceIds;
  }

  // CloudFormation intrinsic function: Ref
  if (typeof ref === 'object' && ref.Ref) {
    resourceIds.push(ref.Ref);
    return resourceIds;
  }

  // CloudFormation intrinsic function: Fn::GetAtt
  if (typeof ref === 'object' && ref['Fn::GetAtt'] && Array.isArray(ref['Fn::GetAtt'])) {
    resourceIds.push(ref['Fn::GetAtt'][0]);
    return resourceIds;
  }

  // CloudFormation intrinsic function: Fn::Sub
  if (typeof ref === 'object' && ref['Fn::Sub']) {
    if (typeof ref['Fn::Sub'] === 'string') {
      // Extract resource IDs from ${ResourceId.Attribute} pattern
      const regex = /\${([^.}]+)(?:\.[^}]+)?}/g;
      let match;
      while ((match = regex.exec(ref['Fn::Sub'])) !== null) {
        resourceIds.push(match[1]);
      }
    } else if (Array.isArray(ref['Fn::Sub']) && ref['Fn::Sub'].length === 2) {
      // Handle Fn::Sub with replacement map
      const template = ref['Fn::Sub'][0];
      if (typeof template === 'string') {
        const regex = /\${([^.}]+)(?:\.[^}]+)?}/g;
        let match;
        while ((match = regex.exec(template)) !== null) {
          const varName = match[1];
          // Only add if it's not in the replacement map (those are not resource IDs)
          const replacementMap = ref['Fn::Sub'][1];
          if (typeof replacementMap === 'object' && replacementMap !== null && !(varName in replacementMap)) {
            resourceIds.push(varName);
          }
        }
      }
    }
    return resourceIds;
  }

  // CloudFormation intrinsic function: Fn::Join
  if (typeof ref === 'object' && ref['Fn::Join'] && Array.isArray(ref['Fn::Join']) &&
      ref['Fn::Join'].length === 2 && Array.isArray(ref['Fn::Join'][1])) {
    // Look for Ref or GetAtt within Join parts
    for (const part of ref['Fn::Join'][1]) {
      if (typeof part === 'object' && part !== null) {
        // Recursive call to handle nested intrinsic functions
        const nestedIds = extractResourceIdsFromReference(part);
        resourceIds.push(...nestedIds);
      }
    }
    return resourceIds;
  }

  // CloudFormation intrinsic function: Fn::If
  if (typeof ref === 'object' && ref['Fn::If'] && Array.isArray(ref['Fn::If']) &&
      ref['Fn::If'].length === 3) {
    // Try to extract from the true and false values
    const trueValue = ref['Fn::If'][1];
    const falseValue = ref['Fn::If'][2];

    // Recursive calls to handle nested intrinsic functions
    const trueIds = extractResourceIdsFromReference(trueValue);
    const falseIds = extractResourceIdsFromReference(falseValue);

    resourceIds.push(...trueIds, ...falseIds);
    return resourceIds;
  }

  return resourceIds;
}

/**
 * Checks if a reference points to a specific resource
 * @param reference The reference to check
 * @param resourceId The resource ID to check for
 * @returns True if the reference points to the resource, false otherwise
 */
export function isReferenceToResource(reference: any, resourceId: string): boolean {
  // Direct string reference
  if (typeof reference === 'string' && reference === resourceId) {
    return true;
  }

  // Ref intrinsic function
  if (typeof reference === 'object' && reference?.Ref === resourceId) {
    return true;
  }

  // GetAtt intrinsic function
  if (typeof reference === 'object' &&
      reference?.['Fn::GetAtt'] &&
      Array.isArray(reference['Fn::GetAtt']) &&
      reference['Fn::GetAtt'][0] === resourceId) {
    return true;
  }

  // Sub intrinsic function
  if (typeof reference === 'object' &&
      reference?.['Fn::Sub'] &&
      typeof reference['Fn::Sub'] === 'string' &&
      reference['Fn::Sub'].includes(`\${${resourceId}}`)) {
    return true;
  }

  // Join intrinsic function
  if (typeof reference === 'object' &&
      reference?.['Fn::Join'] &&
      Array.isArray(reference['Fn::Join']) &&
      reference['Fn::Join'].length === 2 &&
      Array.isArray(reference['Fn::Join'][1])) {
    const joinParts = reference['Fn::Join'][1];
    const joinString = JSON.stringify(joinParts);
    if (joinString.includes(resourceId)) {
      return true;
    }
  }

  // Extract all resource IDs and check if any match
  const extractedIds = extractResourceIdsFromReference(reference);
  return extractedIds.includes(resourceId);
}

/**
 * Checks if a value contains a specific pattern, even in intrinsic functions
 * @param value The value to check
 * @param pattern The pattern to check for (string or RegExp)
 * @returns True if the value contains the pattern, false otherwise
 */
export function containsPattern(value: any, pattern: string | RegExp): boolean {
  // Direct string check
  if (typeof value === 'string') {
    if (pattern instanceof RegExp) {
      return pattern.test(value);
    } else {
      return value.includes(pattern);
    }
  }

  // Check in stringified version for intrinsic functions
  if (typeof value === 'object' && value !== null && hasIntrinsicFunction(value)) {
    const valueStr = JSON.stringify(value);
    if (pattern instanceof RegExp) {
      return pattern.test(valueStr);
    } else {
      return valueStr.includes(pattern);
    }
  }

  return false;
}

/**
 * Finds all resources that reference a specific resource
 * @param targetId The ID of the resource to find references to
 * @param resources All resources in the template
 * @returns Array of resources that reference the target resource
 */
export function findReferencingResources(targetId: string, resources: any[]): any[] {
  return resources.filter(resource => {
    // Convert resource to string and check for references
    const resourceStr = JSON.stringify(resource);
    return resourceStr.includes(targetId);
  });
}

/**
 * Checks if a CIDR represents public access (0.0.0.0/0 or ::/0)
 * @param cidr The CIDR to check
 * @returns True if the CIDR represents public access, false otherwise
 */
export function isPublicCidr(cidr: any): boolean {
  // Direct string check
  if (cidr === '0.0.0.0/0' || cidr === '::/0') {
    return true;
  }

  // Check for patterns in intrinsic functions
  return containsPattern(cidr, /(0\.0\.0\.0\/0)|(::\/(0))/);
}
