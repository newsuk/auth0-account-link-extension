declare let configuration: Configuration;

interface Configuration {
    [key: string]: string;
}

declare let auth0: Auth0;
interface Auth0 {
    baseUrl: string;
    domain: string;
    accessToken: string;
}

type ProfileCallback = (error: Error | null, user?: Profile | null) => any;
type BooleanCallback = (error: Error | null, success?: boolean | null | undefined) => any;
type RuleCallback = (error: Error | null, user?: Profile, context?: Context) => any;

interface Profile {
    user_id: string;
    email: string;
    email_verified: boolean;
    metadata?: ProfileMetadata;
    app_metadata?: any;
    identities?: {
        connection: string,
        user_id: string,
        provider: string,
        isSocial: boolean,
    }[]
}

interface ProfileMetadata {
    acs_tokens?: ACSTokens;
    flags: Record<string, boolean>;
}

interface ACSTokens {
    token?: string;
    secure_token?: string;
}

interface User {
    user_id: string;
    email: string;
    password: string;
    tenant: string;
    client_id: string;
}

interface Context {
    stats: {
        loginsCount: number;
    }
    protocol: "oidc-basic-profile" |
    "oidc-implicit-profile" |
    "oauth2-device-code" |
    "oauth2-resource-owner" |
    "oauth2-resource-owner-jwt-bearer" |
    "oauth2-password" |
    "oauth2-refresh-token" |
    "samlp" |
    "wsfed" |
    "wstrust-usernamemixed" |
    "delegation" |
    "redirect-callback";
    idToken?: {
        [key: string]: string;
    }
    clientName?: string;
    request?: {
        query?: Record<string, string>
    }
    redirect?: {
        url: string;
    }
    connection?: string;
    connectionID?: string;
    primaryUser?: string;
}

interface HookUser {
    id: string;
    email: string;
    username: string;
    last_password_reset: string;
}

interface HookContext {
    connection?: {
        id?: string;
        name?: string;
        tenant?: string;
    }
    webtask?: {
        secrets?: {
            [key: string]: string;
        }
    }
}

declare class WrongUsernameOrPasswordError extends Error {
    constructor(email: string, message?: string);
}
