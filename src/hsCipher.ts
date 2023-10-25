/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

// TODO: Remove unnecessary codes

import { Cipher } from '@digitalbazaar/minimal-cipher';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { VerificationKeyTypes, KeyAgreementKeyTypes, IEncryptionRecipents, IEncryptedData } from './Types';

import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { KeyResolver, IRecipents, IEncryptionRequest, IJWE, IDecryptionRequest, IKeyAgreementKey } from './Types';
import HypersignEdvClientEcdsaSecp256k1, { encrypt, multibaseBase58ToBase64 } from './HypersignEdvClientEcdsaSecp256k1';

export default class HypersignCipher {
  private keyResolver: KeyResolver;
  private cipher: Cipher;
  private keyAgreementKey: IKeyAgreementKey;
  constructor({ keyResolver, keyAgreementKey }: { keyResolver: KeyResolver; keyAgreementKey?: X25519KeyAgreementKey2020 }) {
    this.keyResolver = keyResolver;
    this.cipher = new Cipher();
    this.keyAgreementKey = keyAgreementKey;
  }

  private async _getX25519KeyAgreementKey(keyAgreementKey = this.keyAgreementKey): Promise<X25519KeyAgreementKey2020> {
    if ((keyAgreementKey.type as unknown as VerificationKeyTypes) === VerificationKeyTypes.Ed25519VerificationKey2020) {
      const ed25519KeyPair: Ed25519VerificationKey2020 = await Ed25519VerificationKey2020.generate({ ...keyAgreementKey });
      const keyAgreementKeyPair: X25519KeyAgreementKey2020 = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
        keyPair: ed25519KeyPair,
      });
      return keyAgreementKeyPair;
    } else if (keyAgreementKey.type === KeyAgreementKeyTypes.X25519KeyAgreementKey2020) {
      return keyAgreementKey;
    } else {
      throw new Error('Unsupported type  ' + keyAgreementKey.type);
    }
  }

  // TODO: bas way of doing it
  private async _getX25519KeyAgreementResolver(keyResolver = this.keyResolver, id: string): Promise<any> {
    const keypairObj = await keyResolver({ id });

    if (keypairObj.type === VerificationKeyTypes.Ed25519VerificationKey2020) {
      const keyAgreementKeyPair: X25519KeyAgreementKey2020 = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
        keyPair: keypairObj,
      });
      return async () => {
        return keyAgreementKeyPair;
      };
    } else if (keypairObj.type === KeyAgreementKeyTypes.X25519KeyAgreementKey2020) {
      return keyResolver;
    } else {
      throw new Error('Unsupported type  ' + keypairObj.type);
    }
  }

  private async resolver({ id }) {
    const pubkey = id.split('#')[1];
    const keyPair = {
      publicKeyMultibase: '',
    };
    keyPair.publicKeyMultibase = pubkey;

    const keyAgreementKeyPair: X25519KeyAgreementKey2020 = X25519KeyAgreementKey2020.from({
      publicKeyMultibase: keyPair.publicKeyMultibase,
      id,
    });
    return keyAgreementKeyPair;
  }

  // helper to create default recipients
  private _createDefaultRecipients(keyAgreementKey: X25519KeyAgreementKey2020): Array<IRecipents> {
    return keyAgreementKey
      ? ([
          {
            header: {
              kid: keyAgreementKey.id,
              // only supported algorithm
              alg: 'ECDH-ES+A256KW',
            },
          },
        ] as unknown as Array<IRecipents>)
      : ([] as unknown as Array<IRecipents>);
  }

  private _createParticipants(recipients: Array<IEncryptionRecipents>): Array<IRecipents> {
    return recipients.map((recipient) => {
      if (recipient.type === KeyAgreementKeyTypes.X25519KeyAgreementKey2020) {
        const pubkey = recipient.id.split('#')[1];
        const id = recipient.id.split('#')[0];
        const keyPair = {
          publicKeyMultibase: '',
        };
        keyPair.publicKeyMultibase = pubkey;
        const x25519keyAgreementKeyPub = keyPair;

        return {
          header: {
            kid: id + '#' + x25519keyAgreementKeyPub.publicKeyMultibase,
            // only supported algorithm
            alg: 'ECDH-ES+A256KW',
          },
        };
      } else if (recipient.type === KeyAgreementKeyTypes.X25519KeyAgreementKeyEIP5630) {
        return {
          header: {
            kid: recipient.id.split('#')[0] + '#' + recipient.id.split('#')[1],
            alg: 'x25519-xsalsa20-poly1305',
          },
        };
      }
    }) as unknown as Array<IRecipents>;
  }

  private async filterRecipients(recipients: Array<IRecipents>) {
    const JWERecipient = recipients.filter((recipient) => {
      return recipient.header?.alg === 'ECDH-ES+A256KW';
    });

    const Xpoly1305Recipient = recipients.filter((recipient) => {
      if (recipient.header?.alg === 'x25519-xsalsa20-poly1305') {
        const publicKey = recipient.header.kid.split('#')[1];
        const encryptionPublicKeyBase64 = multibaseBase58ToBase64(publicKey);
        recipient['encryptionPublicKeyBase64'] = encryptionPublicKeyBase64;
        return {
          id: recipient.header.kid,
          type: KeyAgreementKeyTypes.X25519KeyAgreementKeyEIP5630,
          encryptionPublicKeyBase64,
        };
      }
    });

    return {
      JWERecipient,
      Xpoly1305Recipient,
    };
  }

  public async encryptObject({
    plainObject,
    recipients = [],
    keyResolver,
    keyAgreementKey = this.keyAgreementKey,
  }: IEncryptionRequest): Promise<{ jwe: IJWE; encryptedData: IEncryptedData }> {
    // worng way of doing it
    const x25519keyAgreementKey = await this._getX25519KeyAgreementKey(keyAgreementKey);
    let allRecipient: Array<IRecipents>;
    if (recipients.length === 0 && x25519keyAgreementKey) {
      allRecipient = this._createDefaultRecipients(x25519keyAgreementKey);
    } else {
      allRecipient = this._createParticipants(recipients);
    }

    const { JWERecipient, Xpoly1305Recipient } = await this.filterRecipients(allRecipient);

    // keyResolver is required because Notice that recipients lists only key IDs, not the keys themselves.
    // A keyResolver is a function that accepts a key ID and resolves to the public key corresponding to it.
    const kr = keyResolver ? await keyResolver : await this.resolver;

    const jwe = await this.cipher.encryptObject({ obj: plainObject, recipients: JWERecipient, keyResolver: kr });

    const cannonizeString = JSON.stringify(plainObject, function (key, value) {
      if (value && typeof value === 'object') {
        const newValue = Array.isArray(value) ? [] : {};
        Object.keys(value)
          .sort()
          .forEach(function (k) {
            newValue[k] = value[k];
          });
        return newValue;
      }
      return value;
    });

    const encryptedData = encrypt(
      cannonizeString,
      Xpoly1305Recipient as unknown as Array<{
        id: string;
        type: string;
        encryptionPublicKeyBase64: string;
      }>,
    );

    return { jwe, encryptedData };
  }

  public async decryptObject({ jwe, keyAgreementKey = this.keyAgreementKey }: IDecryptionRequest): Promise<object> {
    const x25519keyAgreementKey = await this._getX25519KeyAgreementKey(keyAgreementKey);
    const object = await this.cipher.decryptObject({ jwe, keyAgreementKey: x25519keyAgreementKey });
    return object;
  }
}
