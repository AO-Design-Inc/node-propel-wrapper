const jwt = require('jsonwebtoken');
const fs = require('fs');
const https = require('https');
const propel_url = process.env.PROPEL_AUTH_URL;
const propel_auth_key = process.env.PROPEL_API_KEY;
const propel_cookie = process.env.PROPEL_COOKIE;

const getDataFromRequestPromiseGenerator = (
    options,
    callback = (response) => {}
) =>
    new Promise((resolve, reject) => {
        const DATA = [];
        const request = https.request(options, (response) => {
            response.on('data', (chunk) => {
                DATA.push(chunk);
            });

            response.on('end', () => {
                const statusCode = response.statusCode;
                if (statusCode >= 200 && statusCode < 300) {
                    callback(response);
                    resolve(JSON.parse(String(DATA)));
                } else if (statusCode === 401) {
                    reject('bruh your access token is wrong');
                }
            });

            response.on('error', (err) => {
                reject(err);
            });
        });
        request.end();
    });
//from https://github.com/PropelAuth/express
function extractBearerToken(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        throw new Error('No authorization header found.');
    }

    const authHeaderParts = authHeader.split(' ');
    if (
        authHeaderParts.length !== 2 ||
        authHeaderParts[0].toLowerCase() !== 'bearer'
    ) {
        throw new Error(
            'Invalid authorization header. Expected: Bearer {accessToken}'
        );
    }

    return authHeaderParts[1];
}

function getTokenMetadata() {
    const DATA = [];

    const options = {
        hostname: propel_url,
        path: '/api/v1/token_verification_metadata',
        method: 'GET',
        headers: { Authorization: 'Bearer ' + propel_auth_key },
    };
    return new Promise((resolve, reject) => {
        const request = https.request(options, (response) => {
            response.on('data', (chunk) => {
                DATA.push(chunk);
            });

            response.on('end', () => {
                resolve(JSON.parse(String(DATA)));
            });

            response.on('error', (err) => {
                reject(err);
            });
        });
        request.end();
    });
}

async function verifyRequestFactory() {
    const TokenMetadata = await getTokenMetadata();
    const reqHandler = (request) => {
        try {
            const bearerToken = extractBearerToken(request);
            const payload = jwt.verify(
                bearerToken,
                TokenMetadata.verifier_key_pem,
                (options = ['RS256'])
            );
            return payload;
        } catch (err) {
            console.error('invalid token!');
            throw err;
        }
    };
    return reqHandler;
}

//also **reset** propel_cookie when doing this
//simplest persistence mechanism is likely a file in the same directory
//then reset the shell script to also include the relevant tempfile
async function* fetchAuthenticationInfo() {
    const curRefreshToken = fs.readFileSync('.cookie');
    const refreshTokenFromCookieRegex = /refresh_token=([^;]+);/;

    const options = {
        hostname: propel_url,
        path: '/api/v1/refresh_token',
        method: 'GET',
        headers: { Cookie: `refresh_token=${curRefreshToken}` },
    };

    try {
        const authInfo = await getDataFromRequestPromiseGenerator(
            options,
            (response) => {
                if (Object.hasOwn(response.headers, 'set-cookie')) {
                    try {
                        fs.writeFileSync(
                            '.cookie',
                            refreshTokenFromCookieRegex.exec(
                                response.headers['set-cookie'][0]
                            )[1]
                        );
                    } catch (err) {
                        throw err;
                    }
                } else throw new Error('no set-cookie!');
            }
        );
        yield authInfo;
        while (authInfo.expires_at_seconds > Date.now() / 1000) {
            yield authInfo;
        }
        yield* fetchAuthenticationInfo();
    } catch (err) {
        throw err;
    }
}

exports.verifyRequestAndGetUser = verifyRequestFactory();
exports.fetchAuthenticationInfo = fetchAuthenticationInfo;
