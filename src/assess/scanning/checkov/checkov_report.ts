interface CheckResult {
  result: string;
  evaluated_keys: string[];
}

interface CodeBlockLine {
  0: number;
  1: string;
}

interface CheckovResults {
  failed_checks: CheckovSecurityCheck[];
}

interface CheckovSummary {
  passed: number;
  failed: number;
  skipped: number;
  parsing_errors: number;
  resource_count: number;
  checkov_version: string;
}

export interface CheckovReport {
  check_type: string;
  results: CheckovResults;
  summary: CheckovSummary;
}

export interface CheckovSecurityCheck {
  check_id: string;
  bc_check_id: string;
  check_name: string;
  check_result: CheckResult;
  code_block: CodeBlockLine[];
  file_path: string;
  file_abs_path: string;
  repo_file_path: string;
  file_line_range: [number, number];
  resource: string;
  evaluations: Record<string, any>;
  check_class: string;
  fixed_definition: any | null;
  entity_tags: any | null;
  caller_file_path: string | null;
  caller_file_line_range: [number, number] | null;
  resource_address: string | null;
  severity: string | null;
  bc_category: string | null;
  benchmarks: string[] | null;
  description: string | null;
  short_description: string | null;
  vulnerability_details: any | null;
  connected_node: any | null;
  guideline: string;
  details: any[];
  check_len: number | null;
  definition_context_file_path: string | null;
}
