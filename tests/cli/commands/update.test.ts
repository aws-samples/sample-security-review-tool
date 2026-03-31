import { describe, it, expect, vi, beforeEach } from 'vitest';
import { UpdateCommand } from '../../../src/update/command.js';

describe('UpdateCommand', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  describe('register', () => {
    it('should register update command with program', () => {
      const mockProgram = {
        command: vi.fn().mockReturnThis(),
        description: vi.fn().mockReturnThis(),
        action: vi.fn().mockReturnThis()
      };

      UpdateCommand.register(mockProgram as any);

      expect(mockProgram.command).toHaveBeenCalledWith('update');
      expect(mockProgram.description).toHaveBeenCalledWith('Update to the latest version of SRT');
      expect(mockProgram.action).toHaveBeenCalled();
    });
  });
});