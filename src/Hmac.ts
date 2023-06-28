/**
 * Hmac.ts
 * Author: Pratap Mridha (Github @pratap2018)
 */

const base64url = require('base64url-universal');

const crypto = globalThis.crypto.subtle;

export default class Hmac {
  id: string;
  type: string;
  algorithm: string;
  key: any;

  /**
   * @param {string} id
   * @param {string} type
   * @param {string} algorithm
   * @param {string} key
   * @returns {Hmac}
   **/
  constructor({ id, type, algorithm, key }) {
    this.id = id;
    this.type = type;
    this.algorithm = algorithm;
    this.key = key;
  }

  /**
   * @param {string} id
   * @param {string} key
   * @returns {Promise<Hmac>}
   * */
  static async create({ id, key }) {
    const type = 'Sha256HmacKey2019';
    const algorithm = 'HS256';
    const extractable = true;
    const secret = base64url.decode(key);
    key = await crypto.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, extractable, ['sign', 'verify']);
    return new Hmac({ id, type, algorithm, key });
  }

  async sign({ data }) {
    const key = this.key;
    const signature = new Uint8Array(await crypto.sign(key.algorithm, key, data));
    return base64url.encode(signature);
  }

  async verify({ data, signature }) {
    const key = this.key;
    signature = base64url.decode(signature);
    return crypto.verify(key.algorithm, key, signature, data);
  }
}
