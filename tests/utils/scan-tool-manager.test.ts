import { describe, it, expect } from 'vitest';
import { ScannerToolManager } from '../../src/shared/scanner-tools/scanner-tool-manager.js';

describe('ScannerToolManager', () => {
  describe('extractToolName', () => {
    it('should extract ScanTool names correctly', () => {
      expect(ScannerToolManager.extractToolName('checkov --version')).toBe('Checkov');
      expect(ScannerToolManager.extractToolName('semgrep scan')).toBe('Semgrep');
      expect(ScannerToolManager.extractToolName('bandit -r .')).toBe('Bandit');
      expect(ScannerToolManager.extractToolName('syft analyze')).toBe('Syft');
      expect(ScannerToolManager.extractToolName('jupyter notebook')).toBe('Jupyter');
    });

    it('should extract AuxiliaryTool names correctly', () => {
      expect(ScannerToolManager.extractToolName('jupyter nbconvert --to script')).toBe('Jupyter nbconvert');
      expect(ScannerToolManager.extractToolName('cdk synth')).toBe('Cdk');
      expect(ScannerToolManager.extractToolName('pip install package')).toBe('Pip');
      expect(ScannerToolManager.extractToolName('python -m venv')).toBe('Venv');
    });

    it('should return "Scanner" for unknown scanners', () => {
      expect(ScannerToolManager.extractToolName('unknown command')).toBe('Tool');
    });

    it('should handle paths and complex commands', () => {
      expect(ScannerToolManager.extractToolName('"/path/to/venv/bin/checkov" -f file')).toBe('Venv');
      expect(ScannerToolManager.extractToolName('"/path/to/python" "/path/to/semgrep" scan')).toBe('Semgrep');
    });
  });
});
