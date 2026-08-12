const QUERY_STRING_PREFIX = 'method.request.querystring.';
const HEADER_PREFIX = 'method.request.header.';

/**
 * True when the declared request parameters mark at least one query string or header
 * parameter as required. Parameter validation only enforces required parameters.
 */
export function hasRequiredQueryOrHeaderParameter(requestParameters: unknown): boolean {
  if (!isRecord(requestParameters)) return false;
  return Object.entries(requestParameters).some(([name, required]) => isQueryOrHeader(name) && isRequired(required));
}

/**
 * True when a query string or header parameter is declared, required or not. Used to tell a method
 * whose input a validator could be made to check from one that has no such input.
 *
 * Path parameters are deliberately excluded, even though validation nominally covers them: a path
 * parameter is part of the route, so a request missing it does not match the resource and never
 * reaches the method. Validating one cannot reject anything routing has not already rejected.
 */
export function hasQueryOrHeaderParameter(requestParameters: unknown): boolean {
  if (!isRecord(requestParameters)) return false;
  return Object.keys(requestParameters).some(isQueryOrHeader);
}

function isQueryOrHeader(name: string): boolean {
  const lowered = name.toLowerCase();
  return lowered.startsWith(QUERY_STRING_PREFIX) || lowered.startsWith(HEADER_PREFIX);
}

function isRequired(value: unknown): boolean {
  return value === true || value === 'true';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
