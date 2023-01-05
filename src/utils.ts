/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

import axios from 'axios';
interface IRequest {
  url: string;
  method: string;
  body?: object;
  headers?: any;
}

export default class Utils {
  static _sanitizeURL(url: string): string {
    return url;
  }

  static async _makeAPICall(params: IRequest): Promise<any> {
    try {
      const resp = await axios(params.url, {
        method: params.method,
        data: params.body ? params.body : null,
        headers: params.headers ? params.headers : null,
      });

      const { data } = resp;
      return data;
    } catch (e: any) {
      const { response } = e;
      const { data, status, statusText } = response;
      if (data) {
        throw new Error(data);
      } else {
        throw new Error(statusText);
      }
    }
  }
}
