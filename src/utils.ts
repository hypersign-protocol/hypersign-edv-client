// import fetch from 'node-fetch';
import axios from 'axios';
import { httpClient, DEFAULT_HEADERS } from '@digitalbazaar/http-client';
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
