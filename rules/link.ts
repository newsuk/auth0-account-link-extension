import * as request from "request";
import * as queryString from "querystring";
import * as jwt from "jsonwebtoken";

export function linkSocialProfileEntry(user: Profile, context: Context, callback: RuleCallback) {
    linkSocialProfile(user, context).then(([user, context]) => {
        callback(null, user, context);
    }).catch(error => {
        callback(error);
    })
}

const CONTINUE_PROTOCOL = 'redirect-callback';
const LOG_TAG = '[ACCOUNT_LINK]: ';
const config = {
    endpoints: {
        linking: configuration.AccountLinkExtensionURL.replace(/\/$/g, ''),
        userApi: auth0.baseUrl + '/users',
        usersByEmailApi: auth0.baseUrl + '/users-by-email'
    },
    token: {
        clientId: configuration.AccountLinkClientID,
        clientSecret: configuration.AccountLinkClientSecret,
        issuer: auth0.domain
    }
};

async function linkSocialProfile(user: Profile, context: Context): Promise<[Profile, Context]> {
    console.log(LOG_TAG, 'Entered Account Link Rule');

    // 'query' can be undefined when using '/oauth/token' to log in
    context.request = context.request || {};
    context.request.query = context.request.query || {};


    // If the user does not have an e-mail account,
    // just continue the authentication flow.
    // See newsuk/auth0-account-link-extension#33
    if (user.email === undefined) {
        return [user, context];
    }

    if (shouldLink(context)) {
        return linkAccounts(user, context);
    } else if (shouldLinkWithoutPrompt(user, context)) {
        return linkAccountsWithoutPrompt(user, context);
    } else if (shouldPrompt(context)) {
        return promptUser(user, context);
    }

    return [user, context];
}

function shouldLink(context: Context): boolean {
    return !!context.request!.query!.link_account_token;
}

function shouldLinkWithoutPrompt(user: Profile, context: Context): boolean {
    return context.connection === "google-oauth2" && user.email.endsWith("@gmail.com") && user.email_verified;
}

function shouldPrompt(context: Context): boolean {
    return !insideRedirect() && !redirectingToContinue() && firstLogin();

    // Check if we're inside a redirect
    // in order to avoid a redirect loop
    // TODO: May no longer be necessary
    function insideRedirect() {
        return context.request!.query!.redirect_uri &&
            context.request!.query!.redirect_uri.indexOf(config.endpoints.linking) !== -1;
    }

    // Check if this is the first login of the user
    // since merging already active accounts can be a
    // destructive action
    function firstLogin() {
        return context.stats.loginsCount <= 1;
    }

    // Check if we're coming back from a redirect
    // in order to avoid a redirect loop. User will
    // be sent to /continue at this point. We need
    // to assign them to their primary user if so.
    function redirectingToContinue() {
        return context.protocol === CONTINUE_PROTOCOL;
    }
}

function verifyToken(token: string, secret: jwt.Secret | jwt.GetPublicKeyOrSecret): Promise<jwt.JwtPayload> {
    return new Promise(function (resolve, reject) {
        jwt.verify(token, secret, (err: jwt.VerifyErrors | null, decoded: jwt.JwtPayload | undefined) => {
            if (err) {
                return reject(err);
            }

            return resolve(decoded!);
        });
    });
}

async function linkAccounts(user: Profile, context: Context): Promise<[Profile, Context]> {
    var secondAccountToken = context.request!.query!.link_account_token!;

    const decodedToken = await verifyToken(secondAccountToken, config.token.clientSecret);
    // Redirect early if tokens are mismatched
    if (user.email !== decodedToken.email) {
        console.error(LOG_TAG, 'User: ', decodedToken.email, 'tried to link to account ', user.email);
        context.redirect = {
            url: buildRedirectUrl(secondAccountToken, context.request!.query!, 'accountMismatch')
        };

        return [user, context];
    }

    var linkUri = config.endpoints.userApi + '/' + user.user_id + '/identities';
    var headers = {
        Authorization: 'Bearer ' + auth0.accessToken,
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache'
    };

    const secondaryUser = await apiCall<Profile>({
        method: 'GET',
        url: config.endpoints.userApi + '/' + decodedToken.sub + '?fields=identities',
        headers: headers
    })

    var provider = secondaryUser &&
        secondaryUser.identities &&
        secondaryUser.identities[0] &&
        secondaryUser.identities[0].provider;

    user = await apiCall({
        method: 'POST',
        url: linkUri,
        headers,
        json: { user_id: decodedToken.sub, provider: provider }
    })

    console.info(LOG_TAG, 'Successfully linked accounts for user: ', user.email);

    return [user, context];
}

async function linkAccountsWithoutPrompt(user: Profile, context: Context): Promise<[Profile, Context]> {
    const users = await searchUsersWithSameEmail(user)
    const targetUsers = users.filter(u => u.user_id !== user.user_id).map(u => u.user_id);

    if (targetUsers.length > 0) {
        var linkUri = config.endpoints.userApi + '/' + targetUsers[0] + '/identities';
        var headers = {
            Authorization: 'Bearer ' + auth0.accessToken,
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache'
        };

        user = await apiCall({
            method: 'POST',
            url: linkUri,
            headers,
            json: { user_id: user.user_id, provider: context.connection, connection_id: context.connectionID }
        })

        console.info(LOG_TAG, 'Successfully linked accounts for user: ', user.email);
    }

    return [user, context]
}

async function promptUser(user: Profile, context: Context): Promise<[Profile, Context]> {
    const users = await searchUsersWithSameEmail(user)
    const targetUsers = users.filter(u => u.user_id !== user.user_id);

    if (targetUsers.length > 0) {
        context.redirect = {
            url: buildRedirectUrl(createToken(user), context.request!.query!)
        }
    }

    return [user, context]
}

function createToken(user: Profile): string {
    var options = {
        expiresIn: '5m',
        audience: config.token.clientId,
        issuer: qualifyDomain(config.token.issuer)
    };

    var userSub = {
        sub: user.user_id,
        email: user.email,
        base: auth0.baseUrl
    };

    return jwt.sign(userSub, config.token.clientSecret, options);
}

function searchUsersWithSameEmail(user: Profile): Promise<Profile[]> {
    return apiCall({
        url: config.endpoints.usersByEmailApi,
        qs: {
            email: user.email
        }
    });
}

// Consider moving this logic out of the rule and into the extension
function buildRedirectUrl(token: string, q: Record<string, string>, errorType?: string) {
    var params = {
        child_token: token,
        audience: q.audience,
        client_id: q.client_id,
        redirect_uri: q.redirect_uri,
        scope: q.scope,
        response_type: q.response_type,
        response_mode: q.response_mode,
        auth0Client: q.auth0Client,
        original_state: q.original_state || q.state,
        nonce: q.nonce,
        error_type: errorType
    };

    return config.endpoints.linking + '?' + queryString.encode(params);
}

function qualifyDomain(domain: string) {
    return 'https://' + domain + '/';
}

function apiCall<T>(options: request.RequiredUriUrl & request.CoreOptions): Promise<T> {
    return new Promise(function (resolve, reject) {
        const reqOptions = {
            headers: {
                Authorization: 'Bearer ' + auth0.accessToken,
                Accept: 'application/json'
            },
            json: true,
            ...options
        };

        request(reqOptions, function handleResponse(err, response, body) {
            if (err) {
                reject(err);
            } else if (response.statusCode < 200 || response.statusCode >= 300) {
                console.error(LOG_TAG, 'API call failed: ', body);
                reject(new Error(body));
            } else {
                resolve(response.body);
            }
        });
    });
}
