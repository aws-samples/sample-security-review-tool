export enum ScanTool {
    CHECKOV = 'checkov',
    SEMGREP = 'semgrep',
    BANDIT = 'bandit',
    SYFT = 'anchore_syft',
    JUPYTER = 'jupyter',
    CFN_LINT = 'cfn-lint'
}

export interface ToolConfig {
    uvPath: string;
}
