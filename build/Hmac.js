/**
 * Hmac.ts
 * Author: Pratap Mridha (Github @pratap2018)
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const base64url = require('base64url-universal');
const crypto = globalThis.crypto.subtle;
export default class Hmac {
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
    static create({ id, key }) {
        return __awaiter(this, void 0, void 0, function* () {
            const type = 'Sha256HmacKey2019';
            const algorithm = 'HS256';
            const extractable = true;
            const secret = base64url.decode(key);
            key = yield crypto.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, extractable, ['sign', 'verify']);
            return new Hmac({ id, type, algorithm, key });
        });
    }
    sign({ data }) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = this.key;
            const signature = new Uint8Array(yield crypto.sign(key.algorithm, key, data));
            return base64url.encode(signature);
        });
    }
    verify({ data, signature }) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = this.key;
            signature = base64url.decode(signature);
            return crypto.verify(key.algorithm, key, signature, data);
        });
    }
}
