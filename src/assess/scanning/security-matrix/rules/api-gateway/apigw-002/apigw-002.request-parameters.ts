const QUERY_STRING_PREFIX = 'method.request.querystring.';
const HEADER_PREFIX = 'method.request.header.';
const METHOD_REQUEST_PREFIX = 'method.request.';

/**
 * True when the declared request parameters mark at least one query string or header
 * parameter as required. Parameter validation only enforces required parameters.
 */
export function hasRequiredQueryOrHeaderParameter(requestParameters: unknown): boolean {
  if (!isRecord(requestParameters)) return false;
  return Object.entries(requestParameters).some(([name, required]) => isQueryOrHeader(name) && isRequired(required));
}

/**
 * True when the method declares any request parameter at all, of any kind and required or not. Used
 * to tell a method that has input a validator could be made to check from one that has none.
 *
 * Deliberately wider than hasRequiredQueryOrHeaderParameter: validation covers required parameters in
 * the URI, query string and headers, so a declared path parameter is input too. Narrowing this to
 * query and header parameters exempted a GET declaring `method.request.path.proxy: true`, which
 * API Gateway can validate.
 */
export function hasAnyRequestParameter(requestParameters: unknown): boolean {
  if (!isRecord(requestParameters)) return false;
  return Object.keys(requestParameters).some(name => name.toLowerCase().startsWith(METHOD_REQUEST_PREFIX));
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
