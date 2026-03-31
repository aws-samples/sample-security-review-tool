import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ReleaseChecker } from '../../../src/update/release/release-checker.js';
import { PLATFORM_BINARIES } from '../../../src/update/release/types.js';

describe('ReleaseUtils', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  describe('getPlatformBinaryKey', () => {
    it('should return correct key for darwin arm64', () => {
      const originalPlatform = process.platform;
      const originalArch = process.arch;
      
      Object.defineProperty(process, 'platform', { value: 'darwin' });
      Object.defineProperty(process, 'arch', { value: 'arm64' });

      const result = ReleaseChecker.getPlatformBinaryKey();

      expect(result).toBe('darwin-arm64');

      Object.defineProperty(process, 'platform', { value: originalPlatform });
      Object.defineProperty(process, 'arch', { value: originalArch });
    });

    it('should return correct key for linux x64', () => {
      const originalPlatform = process.platform;
      const originalArch = process.arch;
      
      Object.defineProperty(process, 'platform', { value: 'linux' });
      Object.defineProperty(process, 'arch', { value: 'x64' });

      const result = ReleaseChecker.getPlatformBinaryKey();

      expect(result).toBe('linux-x64');

      Object.defineProperty(process, 'platform', { value: originalPlatform });
      Object.defineProperty(process, 'arch', { value: originalArch });
    });

    it('should return null for unsupported platform', () => {
      const originalPlatform = process.platform;
      const originalArch = process.arch;
      
      Object.defineProperty(process, 'platform', { value: 'freebsd' });
      Object.defineProperty(process, 'arch', { value: 'x64' });

      const result = ReleaseChecker.getPlatformBinaryKey();

      expect(result).toBe(null);

      Object.defineProperty(process, 'platform', { value: originalPlatform });
      Object.defineProperty(process, 'arch', { value: originalArch });
    });
  });

  describe('PLATFORM_BINARIES', () => {
    it('should contain expected platform keys', () => {
      expect(PLATFORM_BINARIES).toHaveProperty('darwin-arm64');
      expect(PLATFORM_BINARIES).toHaveProperty('darwin-x64');
      expect(PLATFORM_BINARIES).toHaveProperty('linux-x64');
      expect(PLATFORM_BINARIES).toHaveProperty('win32-x64');
    });

    it('should have correct file patterns', () => {
      expect(PLATFORM_BINARIES['darwin-arm64']).toContain('macos-arm64.tar.gz');
      expect(PLATFORM_BINARIES['win32-x64']).toContain('windows-x64.zip');
    });
  });
});