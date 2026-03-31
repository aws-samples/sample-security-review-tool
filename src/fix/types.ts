export interface FixChange {
    filePath: string;
    original: string;
    updated: string;
    startingLineNumber: number;
}

export interface Fix {
    changes: FixChange[];
    comments: string;
}

export interface Progress {
    phase: string;
    details: string;
}

export interface FixResult {
    success: boolean;
    message: string;
}
