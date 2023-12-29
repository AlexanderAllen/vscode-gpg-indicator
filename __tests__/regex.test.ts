import { strict as assert } from 'assert';
import { parseKeyRecords } from '../src/indicator/gpg';
import { textSpawn } from '../src/indicator/process';

describe('GPG records are captured', () => {

  test('Static capture test for pub/sub, fgr, grp, uid records)', () => {

    // Static (scrambled) example output from:
    // gpg --fingerprint --fingerprint --with-keygrip --with-colon
    const result: string = `
tru::1:1703741673:0:3:1:5
pub:u:255:22:E654F85F9AAABBBB:1703740764:::u:::scESCA:::::ed25519:::0:
fpr:::::::::BC6C84CF5E8C58987AAAAAAAMOCKFINGERRECORD:
grp:::::::::EEAE8855537D0EDC1BBBBBBBBBMOCKGRIPRECORD:
uid:u::::1703741622::2353A797D15AB4AAA80455C5B5C8B5BD80AXXXX::Richard Allen (Drupal.org Contrib) <alexanderallen@351784.no-reply.drupal.org>::::::::::0:
uid:r::::::AB2233AA5E023BF80CD88B1FBBB73CE37E7BXXXX::AlexanderAllen <14018885+AlexanderAllen@users.noreply.github.com>::::::::::0:
uid:u::::1703741726::BAA45D2F23DAE47B08F1A58F779E16B51BXXXXX::AlexanderAllen (Github Contrib) <14018885+AlexanderAllen@users.noreply.github.com>::::::::::0:
sub:u:255:22:270CEE4C1E9AAAAA:1703740764::::::a:::::ed25519::
fpr:::::::::9307A48220BD32C90BXXXXXXMOCKFINGERRECORD:
grp:::::::::81E2E9E688280C4F26ZZZZZZZZMOCKGRIPRECORD:
sub:u:255:18:3962538BD23AAAAA:1703740764::::::e:::::cv25519::
fpr:::::::::8353E6908D0BBFAFFCZXXXXXXMOCKFINGERRECORD:
grp:::::::::49F3A130A449F00970YYYYYYZZZMOCKGRIPRECORD:
`;
    const records = parseKeyRecords(result);

    assert.equal(3, records.length, 'Results contain three matches.');

    assert.equal(records[0]?.fieldKeyType, 'pub', 'First match is a pub record');
    assert(records[0]?.FingerprintRecordType !== '', 'First match fingerprint record is captured');
    assert(records[0]?.GripRecordType !== '', 'First match grip record is captured');
    assert(records[0]?.IdentityRecordType !== '', 'First match identity record is captured');

  })

  /**
   * Check regex breakage against Windows gpg.exe.
   *
   * Windows output comes with \r\n not \n. Both the original regex by Weida,
   * and the extended regex I did were done on a Linux compabtible platform.
   *
   * After modifying the parseKeyRecords() regex to be cross-platform compatible
   * I'm stoked to report this test is passing.
   *
   * Windows users with WSL might still want to use Windows native GPG binariesr
   * for smart-card support, hence the need for cross-platform compatibility.
   *
   * @see https://stackoverflow.com/a/20056634/467453
   * @see https://regex101.com/r/Gzbx96/1
   *
   * @todo This test does not check the type of host environment before running.
   */
  test('Windows OS: Check record group capture against live "gpg.exe" binary', async () => {
    const gpgOutput: string = await textSpawn('gpg.exe', ['--fingerprint', '--fingerprint', '--with-keygrip', '--with-colon'], '');

    const records = parseKeyRecords(gpgOutput);

    // Don't assume there's multiple keys present in the keychain, test only against one key record.
    assert(records[0]?.KeyRecordType !== undefined, 'First match contains a key record');
    assert.equal(records[0]?.fieldKeyType, 'pub', 'First key record is a pub record');

    assert(records[0]?.FingerprintRecordType !== undefined, 'First match fingerprint record is captured');
    assert(records[0]?.GripRecordType !== undefined, 'First match grip record is captured');
    assert(records[0]?.IdentityRecordType !== undefined, 'First match identity record is captured');

  })

});
