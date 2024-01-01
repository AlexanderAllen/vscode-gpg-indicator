import * as process from './process';
import * as assuan from './assuan';
import type { Logger } from './logger';
import { binaryHostConfig } from '../common';

/**
 * Get the path of socket file for communication with GPG agent.
 *
 * @returns The path of desired GPG agent socket.
 */
async function getSocketPath(): Promise<string> {
    // TODO: Consider supporting other socket files rather than the default one.
    const outputs = await process.textSpawn('gpgconf', ['--list-dir', 'agent-socket'], "");

    return outputs.trim();
}

/**
 * Sign the given hash string with the specified GPG key.
 *
 * @param logger - The logger object for debugging logs.
 * @param socketPath - The path of socket file to communicated with GPG agent.
 * @param keygrip - The keygrip of the GPG key for the signing operation.
 * @param passphrase - The passphrase of the key.
 * @param sha1Hash - The hash string to be signed.
 */
async function sign(logger: Logger, socketPath: string, keygrip: string, passphrase: string, sha1Hash: string): Promise<void> {
    let response: assuan.Response;

    const agent = new assuan.AssuanClient(socketPath);
    logger.info("[Assuan] Initialize Assuan client");
    await agent.initialize();
    try {
        response = await agent.receiveResponse();
        response.checkType(assuan.ResponseType.ok);

        logger.info("[Assuan] Set pinentry-mode loopback");
        await agent.sendRequest(assuan.Request.fromCommand(new assuan.RequestCommand('OPTION', 'pinentry-mode loopback')));
        response = await agent.receiveResponse();
        response.checkType(assuan.ResponseType.ok);

        logger.info(`[Assuan] Specifying keygrip: ${keygrip}`);
        await agent.sendRequest(assuan.Request.fromCommand(new assuan.RequestCommand('SIGKEY', keygrip)));
        response = await agent.receiveResponse();
        response.checkType(assuan.ResponseType.ok);

        logger.info("[Assuan] Set hash value for singing");
        await agent.sendRequest(assuan.Request.fromCommand(new assuan.RequestCommand('SETHASH', `--hash=sha1 ${sha1Hash}`)));
        response = await agent.receiveResponse();
        response.checkType(assuan.ResponseType.ok);

        logger.info("[Assuan] Launch the signing operation");
        await agent.sendRequest(assuan.Request.fromCommand(new assuan.RequestCommand('PKSIGN')));
        response = await agent.receiveResponse();
        let type = response.getType();
        if (type === assuan.ResponseType.rawData) { // Key is already unlocked
            logger.info("[Assuan] Key is already unlocked");
            response = await agent.receiveResponse();
            response.checkType(assuan.ResponseType.ok);
        } else if (type === assuan.ResponseType.information) { // S INQUIRE_MAXLEN 255, key is locked
            logger.info("[Assuan] Got information message, key is still locked");
            response = await agent.receiveResponse();
            response.checkType(assuan.ResponseType.inquire); // INQUIRE PASSPHRASE
            logger.info("[Assuan] Send the pass phrase");
            await agent.sendRequest(assuan.Request.fromRawData(new assuan.RequestRawData(Buffer.from(passphrase))));
            await agent.sendRequest(assuan.Request.fromCommand(new assuan.RequestCommand('END')));
            response = await agent.receiveResponse();
            response.checkType(assuan.ResponseType.rawData);
            logger.info("[Assuan] Receive signed message");
            response = await agent.receiveResponse();
            response.checkType(assuan.ResponseType.ok);
        } else {
            throw new Error('unhandled signing flow');
        }

        logger.info("[Assuan] Singing process done, pass phrase kept by the agent");
        await agent.sendRequest(assuan.Request.fromCommand(new assuan.RequestCommand('BYE')));
        response = await agent.receiveResponse();
        response.checkType(assuan.ResponseType.ok);
    } catch (err) {
        logger.warn(`[Assuan] Something wrong in the process: ${err}`);
        throw err;
    } finally {
        logger.info("[Assuan] Destroy Assuan client");
        agent.dispose();
    }
}

function parseIdentities(rawText: string): Array<IdentityRecord> {
    // Match all non-revoked identities.
    const identityPattern: RegExp = /(?<IdentityRecordType>uid:(?=u)(?<fieldIdentityStatus>[^:]):(?:[^:]*):{3}(?<fieldIdentityCreated>[^:]*)(?:[^:]*):{2}(?<fieldIdentityID>[^:]*)(?:[^:]*):{2}(?<fieldIdentityComment>[^:]*):(?<fieldIdentityRest>[:\d]*)\n?)/gm;
    let matchedIdentities: RegExpExecArray | null;
    let identities: Array<IdentityRecord> = [];

    while ((matchedIdentities = identityPattern.exec(rawText)) !== null) {
        let identityRecord: IdentityRecord = (matchedIdentities?.groups) ? matchedIdentities.groups : {};
        identities.push(identityRecord);
    }
    return identities;
}

/**
 * Represents a parsed GPG key record.
 */
export class KeyRecord {
    constructor(
      public readonly KeyRecordType: string = '',
      public readonly fieldKeyType: string= '',
      public readonly fieldKeyStatus: string = '',
      public readonly fieldLength: string = '',
      public readonly fieldPubKeyAlgo: string = '',
      public readonly fieldKeyID: string = '',
      public readonly fieldCreated: string = '',
      public readonly fieldExpires: string = '',
      public readonly fieldTrust: string = '',
      public readonly fieldOwnerTrust: string = '',
      public readonly fieldUserID: string = '',
      public readonly fieldSigClass: string = '',
      public readonly fieldCapability: string = '',
      public readonly fieldCurveName: string = '',
      public readonly fieldRest: string = '',

      public readonly FingerprintRecordType: string = '',
      public readonly fingerprint: string = '',

      public readonly GripRecordType: string = '',
      public readonly grip: string = '',

      public readonly IdentityRecordType: string = '',
      public readonly fieldIdentityStatus: string = '',
      public readonly fieldIdentityCreated: string = '',
      public readonly fieldIdentityID: string = '',
      public readonly fieldIdentityComment: string = '',
      public readonly fieldIdentityRest: string = '',
      public readonly userId: string = '',
    ) {}
}


/**
 * Parse GPG record fields usign a regular expression.
 *
 * Expects output from command `gpg --fingerprint --fingerprint --with-keygrip --with-colon`
 *
 * @param rawText Raw GPG output.
 *
 * @returns [] Array of parsed GPG records.
 *
 * @see https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
 */
export function parseKeyRecords(rawText: string): Array<KeyRecord> {
    // GpgRecordType

    const recordPattern = /(?<KeyRecordType>(?<fieldKeyType>pub|sub):(?<fieldKeyStatus>[^:]*):(?<fieldLength>[^:]*):(?<fieldPubKeyAlgo>[^:]*):(?<fieldKeyID>[^:]*):(?<fieldCreated>[^:]*):(?<fieldExpires>[^:]*):(?<fieldTrust>[^:]*):(?<fieldOwnerTrust>[^:]*):(?<fieldUserID>[^:]*):(?<fieldSigClass>[^:]*):(?<fieldCapability>[escaD?]+)\w*:(?:[^:]*:){4}(?<fieldCurveName>[^:]*):(?<fieldRest>[:\d]*)(?:\r\n|\n))(?<FingerprintRecordType>(?:fpr|fp2):(?:[^:]*:){8}(?<fingerprint>\w*):(?:[^:]*:)*?(?:\r\n|\n))(?<GripRecordType>grp:(?:[^:]*:){8}(?<grip>\w*):(?:[^:]*:)*?(?:\r\n|\n))(?<IdentityRecordType>uid:(?=u)(?<fieldIdentityStatus>[^:]):(?:[^:]*):{3}(?<fieldIdentityCreated>[^:]*)(?:[^:]*):{2}(?<fieldIdentityID>[^:]*)(?:[^:]*):{2}(?<fieldIdentityComment>[^:]*):(?<fieldIdentityRest>[:\d]*)(\r\n|\n))*/mg;
    let matchedIdentities;
    const records: Array<KeyRecord> = [];

    while ((matchedIdentities = recordPattern.exec(rawText)) !== null) {
        const record: KeyRecord = Object.assign(new KeyRecord(), {
            ...matchedIdentities.groups,
            // Combine and attach the captured identity record to the key record.
            userID: (matchedIdentities.groups?.fieldIdentityID === undefined) ? '' :
             `${matchedIdentities.groups?.fieldIdentityID} ${matchedIdentities.groups?.fieldIdentityComment}`,
        });
        records.push(record);
    }
    return records;
}

/**
 * Get information of all GPG keys available.
 *
 * Caller should cache the results from this function whenever possible.
 *
 * --fingerprint flag is given twice to get fingerprint of subkey
 * --with-colon flag is given to get the key information in a more machine-readable manner
 *
 * @returns key information
 *
 * @see https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
 */
export async function getKeyInfos(env: binaryHostConfig): Promise<KeyRecord[]> {
    // @todo @AlexanderAllen issue #8: config option for executable.
    const gpgOutput: string = await process.textSpawn('gpg.exe', ['--fingerprint', '--fingerprint', '--with-keygrip', '--with-colon'], '');
    const records = parseKeyRecords(gpgOutput);
    return records;
}

/**
 * Executes `process.textSpawn` in a cross-platform compatible manner.
 */
async function exec(env: binaryHostConfig, cmd: string, args: string[] = [], input: string = ''): Promise<string> {
    const target = cmd + (env == 'linux' ? '' : '.exe');
    const result: string = await process.textSpawn(target, args, input);
    return result;
}


/**
 * Asks the current GPG agent whether the specified key `keygrip` is unlocked.
 *
 * @returns Promise<boolean>
 *   Whether the key is unlocked or not.
 */
export async function isKeyUnlocked(env: binaryHostConfig, keygrip: string): Promise<boolean> {

    const outputs = await exec(env, 'gpg-connect-agent', [], `KEYINFO ${keygrip}`);

    const lines = outputs.split(env == 'linux' ? '\n' : '\r\n');
    if (lines.length === 1) {
        throw new Error(lines[0]);
    }
    // second line is OK
    // Sample: S KEYINFO CB18328AD05158F97CC8F33682F7AD291F52CB08 D - - - P - - -
    let line = lines[0];
    let tokens = line.split(' ');
    if (tokens.length !== 11) {
        throw new Error('Fail to parse KEYINFO output');
    }

    let isUnlocked = tokens[6] === '1';
    return isUnlocked;
}

/**
 * Get key information of given ID of GPG key.
 *
 * Caller should cache the results from this function whenever possible.
 *
 * @param keyId - ID of the GPG key
 * @param keyInfos - If caller already had the cache, the cache should be passed to avoid duplicated `getKeyInfos()`
 * @returns key information
 */
export async function getKeyInfo(env: binaryHostConfig, keyId: string, keyInfos?: KeyRecord[]): Promise<KeyRecord> {
    for (let info of (Array.isArray(keyInfos) ? keyInfos : await getKeyInfos(env))) {
        // GPG signing key is usually given as shorter ID
        if (info.fingerprint.includes(keyId)) {
            return info;
        }
    }

    throw new Error(`Cannot find key with ID: ${keyId}`);
}

const SHA1_EMPTY_DIGEST = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

/**
 * Unlock some key with the passphrase.
 *
 * @param logger - The logger for debugging information.
 * @param keygrip - The keygrip of the key to be unlocked
 * @param passphrase - The passphrase for the key.
 */
export async function unlockByKey(logger: Logger, keygrip: string, passphrase: string): Promise<void> {
    const socketPath = await getSocketPath();

    // Hash value is not important here, the only requirement is the length of the hash value.
    await sign(logger, socketPath, keygrip, passphrase, SHA1_EMPTY_DIGEST);
}
