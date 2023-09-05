/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
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
import axios from 'axios';
export default class Utils {
    static _sanitizeURL(url) {
        if (url.endsWith('/')) {
            url = url.slice(0, -1);
        }
        return url;
    }
    static _makeAPICall(params) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const resp = yield axios(params.url, {
                    method: params.method,
                    data: params.body ? params.body : null,
                    headers: params.headers ? params.headers : null,
                });
                const { data } = resp;
                return data;
            }
            catch (e) {
                const { response } = e;
                const { data, status, statusText } = response;
                if (data) {
                    return data;
                }
                else {
                    throw new Error(statusText);
                }
            }
        });
    }
}
