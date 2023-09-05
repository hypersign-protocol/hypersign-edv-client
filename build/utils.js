"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __importDefault(require("axios"));
class Utils {
    static _sanitizeURL(url) {
        if (url.endsWith('/')) {
            url = url.slice(0, -1);
        }
        return url;
    }
    static async _makeAPICall(params) {
        try {
            const resp = await (0, axios_1.default)(params.url, {
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
    }
}
exports.default = Utils;
