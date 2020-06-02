/**
 *
 *   The main idea is to use shared Microsoft keys
 *   to validate incoming token using existing solutions.
 *
 *   Requirements:
 *   jsonwebtoken, jwks-rsa and qs npm libraries are required *
 *
 */

// Simple use in Node.js + express.js:
//
// import { validate } from "./tokenValidation";
//
// express.route("/validate").get((req, res) => {
//     validateMSToken(req.query.token).then((result: any): void => {
//         res.send(`token is ${!!result ? "valid" : "invalid"}`);
//     });
// });
//
// The request string should be looks like {DOMAIN}/validate?token={MS_TOKEN}

import * as jwt from "jsonwebtoken";
import * as jwksClient from "jwks-rsa";
import * as qs from "qs";

export const validateMSToken = (token: string | string[] | qs.ParsedQs | qs.ParsedQs[] | undefined): Promise<void> => {
    const msOpenIdConfigURI: string = "https://login.microsoftonline.com/common/.well-known/openid-configuration";

    return fetch(msOpenIdConfigURI)
        .then((res): object => res.json())
        .then((configURIData: any): Promise<any> => {
        const client = jwksClient({
            jwksUri: configURIData.jwks_uri
        });

        const getKey = (header, callback): void => {
            return client.getSigningKey(header.kid, (err: any, key: any): void => {
                const signingKey = key.publicKey || key.rsaPublicKey;
                return callback(null, signingKey);
            });
        };

        return new Promise((resolve) => {
            jwt.verify(token as string, getKey as any, undefined, (err, decoded): void => resolve(!err || !!decoded));
        });
    });
};
