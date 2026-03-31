import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { BinaryDownloader } from '../../../src/update/binary/binary-downloader.js';
import { BinaryInstaller } from '../../../src/update/binary/binary-installer.js';
import * as fs from 'fs';
import { execSync, execFileSync } from 'child_process';

vi.mock('fs');
vi.mock('child_process');

describe('BinaryUpdater', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('downloadBinary', () => {
    it('should download binary successfully', async () => {
      vi.mocked(execFileSync).mockImplementation(() => '');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.statSync).mockReturnValue({ size: 1024 } as any);

      const result = await BinaryDownloader.download('https://example.com/file.txt', '/tmp/file');

      expect(result.success).toBe(true);
      expect(execFileSync).toHaveBeenCalledWith(
        'curl',
        expect.arrayContaining(['-L', '-o']),
        expect.objectContaining({ timeout: 30000 })
      );
    });

    it('should handle download failure', async () => {
      vi.mocked(execSync).mockImplementation(() => {
        throw new Error('curl: (7) Failed to connect');
      });

      const result = await BinaryDownloader.download('https://example.com/file', '/tmp/file');

      expect(result.success).toBe(false);
    });

    it('should handle network timeout', async () => {
      vi.mocked(execSync).mockImplementation(() => {
        throw new Error('timeout');
      });

      const result = await BinaryDownloader.download('https://example.com/file', '/tmp/file');

      expect(result.success).toBe(false);
    });
  });



  describe('installNewBinary', () => {
    it('should install binary successfully on Unix', () => {
      // Mock Unix platform
      Object.defineProperty(process, 'platform', { value: 'linux' });
      vi.mocked(fs.chmodSync).mockImplementation(() => {});
      vi.mocked(fs.renameSync).mockImplementation(() => {});

      const result = BinaryInstaller.install('/new/path', '/target/path');

      expect(result.success).toBe(true);
      expect(fs.chmodSync).toHaveBeenCalledWith('/new/path', 0o755);
      expect(fs.renameSync).toHaveBeenCalledWith('/target/path', '/target/path.old');
      expect(fs.renameSync).toHaveBeenCalledWith('/new/path', '/target/path');
    });

    it('should install binary successfully on Windows', () => {
      // Mock Windows platform
      Object.defineProperty(process, 'platform', { value: 'win32' });
      vi.mocked(fs.renameSync).mockImplementation(() => {});

      const result = BinaryInstaller.install('/new/path', '/target/path');

      expect(result.success).toBe(true);
      expect(fs.chmodSync).not.toHaveBeenCalled();
      expect(fs.renameSync).toHaveBeenCalledWith('/target/path', '/target/path.old');
      expect(fs.renameSync).toHaveBeenCalledWith('/new/path', '/target/path');
    });

    it('should handle installation failure', () => {
      vi.mocked(fs.renameSync).mockImplementation(() => {
        throw new Error('Permission denied');
      });

      const result = BinaryInstaller.install('/new/path', '/target/path');

      expect(result.success).toBe(false);
    });
  });

  describe('rollbackBinary', () => {
    it('should rollback successfully', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.unlinkSync).mockImplementation(() => {});
      vi.mocked(fs.renameSync).mockImplementation(() => {});

      const result = BinaryInstaller.rollback('/target/path');

      expect(result.success).toBe(true);
      expect(fs.existsSync).toHaveBeenCalledWith('/target/path.old');
      expect(fs.existsSync).toHaveBeenCalledWith('/target/path');
      expect(fs.unlinkSync).toHaveBeenCalledWith('/target/path');
      expect(fs.renameSync).toHaveBeenCalledWith('/target/path.old', '/target/path');
    });

    it('should handle missing .old file', () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = BinaryInstaller.rollback('/target/path');

      expect(result.success).toBe(false);
      expect(fs.existsSync).toHaveBeenCalledWith('/target/path.old');
    });

    it('should handle rollback failure', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.unlinkSync).mockImplementation(() => {});
      vi.mocked(fs.renameSync).mockImplementation(() => {
        throw new Error('File not found');
      });

      const result = BinaryInstaller.rollback('/target/path');

      expect(result.success).toBe(false);
    });
  });

  describe('testBinary', () => {
    it('should return true for valid binary', () => {
      vi.mocked(execFileSync).mockReturnValue('SRT CLI v1.0.0' as any);

      const result = BinaryInstaller.test('/path/to/binary');

      expect(result.success).toBe(true);
      expect(execFileSync).toHaveBeenCalledWith('/path/to/binary', ['--version'], expect.any(Object));
    });

    it('should return false for invalid binary', () => {
      vi.mocked(execSync).mockImplementation(() => {
        throw new Error('Command failed');
      });

      const result = BinaryInstaller.test('/path/to/binary');

      expect(result.success).toBe(false);
    });
  });
});