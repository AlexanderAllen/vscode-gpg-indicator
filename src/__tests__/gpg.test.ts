import { strict as assert } from 'assert';
import { parseKeyRecords, isKeyUnlocked } from '../indicator/gpg';
import { binaryHostConfig } from '../common';

describe('The `isKeyUnlocked()` function', () => {

  it("Should should not throw a connection error", async () => {
    const grip = 'EEAE8855537D0EDC1DC17D82DEF72D4A1DC7830B';
    const env: binaryHostConfig = binaryHostConfig.Windows;

    await expect(isKeyUnlocked(env, grip)).resolves.not.toThrow('Fail to parse KEYINFO output');
  });

});
