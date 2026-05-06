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

    it('should detect nbconvert as Jupyter nbconvert', () => {
      expect(ScannerToolManager.extractToolName('jupyter nbconvert --to script')).toBe('Jupyter nbconvert');
    });

    it('should return "Tool" for unknown commands', () => {
      expect(ScannerToolManager.extractToolName('unknown command')).toBe('Tool');
    });

    it('should handle paths and complex commands', () => {
      expect(ScannerToolManager.extractToolName('uv tool run checkov -- -f file')).toBe('Checkov');
      expect(ScannerToolManager.extractToolName('uv tool run semgrep -- scan')).toBe('Semgrep');
    });
  });
});
