export default class Hmac {
    id: string;
    type: string;
    algorithm: string;
    key: any;
    constructor({ id, type, algorithm, key }: {
        id: any;
        type: any;
        algorithm: any;
        key: any;
    });
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