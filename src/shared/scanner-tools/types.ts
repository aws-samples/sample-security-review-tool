export enum ScanTool {
    CHECKOV = 'checkov',
    SEMGREP = 'semgrep',
    BANDIT = 'bandit',
    SYFT = 'anchore_syft',
    JUPYTER = 'jupyter'
}

export enum AuxiliaryTool {
    Nbconvert = 'nbconvert',
    Cdk = 'cdk',
    Pip = 'pip',
    Venv = 'venv'
}

export interface VenvConfig {
    rootDir: string;
    venvDir: string;
    binDir: string;
    pythonCmd: string;
    pythonPath: string;
    checkovCmd: string;
    semgrepCmd: string;
    banditCmd: string;
    syftCmd: string;
    jupyterlabCmd: string;
}
