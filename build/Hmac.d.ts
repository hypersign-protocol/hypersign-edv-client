/**
 * Hmac.ts
 * Author: Pratap Mridha (Github @pratap2018)
 */
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
    constructor({ id, type, algorithm, key }: {
        id: any;
        type: any;
        algorithm: any;
        key: any;
    });
    /**
     * @param {string} id
     * @param {string} key
     * @returns {Promise<Hmac>}
     * */
    static create({ id, key }: {
        id: any;
        key: any;
    }): Promise<Hmac>;
    sign({ data }: {
        data: any;
    }): Promise<any>;
    verify({ data, signature }: {
        data: any;
        signature: any;
    }): Promise<boolean>;
}
//# sourceMappingURL=Hmac.d.ts.map