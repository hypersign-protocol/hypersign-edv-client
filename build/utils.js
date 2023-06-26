"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __importDefault(require("axios"));
class Utils {
    static _sanitizeURL(url) {
        return url;
    }
    static _makeAPICall(params) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const resp = yield (0, axios_1.default)(params.url, {
                    method: params.method,
                    data: params.body ? params.body : null,
                    headers: params.headers ? params.headers : null,
                });
                const { data } = resp;
                return data;
            }
            catch (e) {
                console.log(e);
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
exports.default = Utils;
