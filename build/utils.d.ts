/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
interface IRequest {
    url: string;
    method: string;
    body?: object;
    headers?: any;
}
export default class Utils {
    static _sanitizeURL(url: string): string;
    static _makeAPICall(params: IRequest): Promise<any>;
}
export {};
//# sourceMappingURL=utils.d.ts.map