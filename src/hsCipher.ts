/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

// TODO: Remove unnecessary codes

import { Cipher } from '@digitalbazaar/minimal-cipher';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { VerificationKeyTypes, KeyAgreementKeyTypes } from './Types';

import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { KeyResolver, IRecipents, IEncryptionRequest, IJWE, IDecryptionRequest, IKeyAgreementKey } from './Types';

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
    let keyPair = {
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

  private _createParticipants(
    recipients: Array<{
      id;
      type;
    }>,
  ): Array<IRecipents> {
    return recipients.map((recipient) => {
      if (recipient.type === 'X25519KeyAgreementKey2020') {
        const pubkey = recipient.id.split('#')[1];
        const id = recipient.id.split('#')[0];
        let keyPair = {
          publicKeyMultibase: '',
        };
        keyPair.publicKeyMultibase = pubkey;
        const x25519keyAgreementKeyPub = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({ keyPair });

        return {
          header: {
            kid: id + '#' + x25519keyAgreementKeyPub.publicKeyMultibase,
            // only supported algorithm
            alg: 'ECDH-ES+A256KW',
          },
        };
      } else {
        throw new Error('Unsupported type  ' + recipient.type);
        // comming soon
      }
    }) as unknown as Array<IRecipents>;
  }

  public async encryptObject({
    plainObject,
    recipients = [],
    keyResolver = this.keyResolver,
    keyAgreementKey = this.keyAgreementKey,
  }: IEncryptionRequest): Promise<IJWE> {
    // worng way of doing it
    const x25519keyAgreementKey = await this._getX25519KeyAgreementKey(keyAgreementKey);

    if (recipients.length === 0 && x25519keyAgreementKey) {
      recipients = this._createDefaultRecipients(x25519keyAgreementKey);
    } else {
      recipients = this._createParticipants(recipients as any as Array<{ id; type }>);
    }

    // keyResolver is required because Notice that recipients lists only key IDs, not the keys themselves.
    // A keyResolver is a function that accepts a key ID and resolves to the public key corresponding to it.
    const kr = await this.resolver;

    const jwe = await this.cipher.encryptObject({ obj: plainObject, recipients, keyResolver: kr });
    return jwe;
  }

  public async decryptObject({ jwe, keyAgreementKey = this.keyAgreementKey }: IDecryptionRequest): Promise<object> {
    const x25519keyAgreementKey = await this._getX25519KeyAgreementKey(keyAgreementKey);
    const object = await this.cipher.decryptObject({ jwe, keyAgreementKey: x25519keyAgreementKey });
    return object;
  }
}
