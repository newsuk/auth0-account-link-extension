function main(user, context, callback){
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp.call(b, prop))
      __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(b)) {
      if (__propIsEnum.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    }
  return a;
};
var __markAsModule = (target) => __defProp(target, "__esModule", { value: true });
var __export = (target, all) => {
  __markAsModule(target);
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __reExport = (target, module2, desc) => {
  if (module2 && typeof module2 === "object" || typeof module2 === "function") {
    for (let key of __getOwnPropNames(module2))
      if (!__hasOwnProp.call(target, key) && key !== "default")
        __defProp(target, key, { get: () => module2[key], enumerable: !(desc = __getOwnPropDesc(module2, key)) || desc.enumerable });
  }
  return target;
};
var __toModule = (module2) => {
  return __reExport(__markAsModule(__defProp(module2 != null ? __create(__getProtoOf(module2)) : {}, "default", module2 && module2.__esModule && "default" in module2 ? { get: () => module2.default, enumerable: true } : { value: module2, enumerable: true })), module2);
};

// rules/link/index.ts
__export(exports, {
  default: () => linkSocialProfileEntry
});
var import_request = __toModule(require("request@2.56.0"));
var queryString = __toModule(require("querystring"));
var jwt = __toModule(require("jsonwebtoken@7.1.9"));
function linkSocialProfileEntry(user, context, callback) {
  linkSocialProfile(user, context).then(([user2, context2]) => {
    callback(null, user2, context2);
  }).catch((error) => {
    callback(error);
  });
}
var CONTINUE_PROTOCOL = "redirect-callback";
var LOG_TAG = "[ACCOUNT_LINK]: ";
var config = {
  endpoints: {
    linking: configuration.AccountLinkExtensionURL.replace(/\/$/g, ""),
    userApi: auth0.baseUrl + "/users",
    usersByEmailApi: auth0.baseUrl + "/users-by-email"
  },
  token: {
    clientId: configuration.AccountLinkClientID,
    clientSecret: configuration.AccountLinkClientSecret,
    issuer: auth0.domain
  }
};
async function linkSocialProfile(user, context) {
  console.log(LOG_TAG, "Entered Account Link Rule");
  context.request = context.request || {};
  context.request.query = context.request.query || {};
  if (user.email === void 0) {
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
function shouldLink(context) {
  return !!context.request.query.link_account_token;
}
function shouldLinkWithoutPrompt(user, context) {
  return context.connection === "google-oauth2" && user.email.endsWith("@gmail.com") && user.email_verified;
}
function shouldPrompt(context) {
  return !insideRedirect() && !redirectingToContinue() && firstLogin();
  function insideRedirect() {
    return context.request.query.redirect_uri && context.request.query.redirect_uri.indexOf(config.endpoints.linking) !== -1;
  }
  function firstLogin() {
    return context.stats.loginsCount <= 1;
  }
  function redirectingToContinue() {
    return context.protocol === CONTINUE_PROTOCOL;
  }
}
function verifyToken(token, secret) {
  return new Promise(function(resolve, reject) {
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        return reject(err);
      }
      return resolve(decoded);
    });
  });
}
async function linkAccounts(user, context) {
  var secondAccountToken = context.request.query.link_account_token;
  const decodedToken = await verifyToken(secondAccountToken, config.token.clientSecret);
  if (user.email !== decodedToken.email) {
    console.error(LOG_TAG, "User: ", decodedToken.email, "tried to link to account ", user.email);
    context.redirect = {
      url: buildRedirectUrl(secondAccountToken, context.request.query, "accountMismatch")
    };
    return [user, context];
  }
  var linkUri = config.endpoints.userApi + "/" + user.user_id + "/identities";
  var headers = {
    Authorization: "Bearer " + auth0.accessToken,
    "Content-Type": "application/json",
    "Cache-Control": "no-cache"
  };
  const secondaryUser = await apiCall({
    method: "GET",
    url: config.endpoints.userApi + "/" + decodedToken.sub + "?fields=identities",
    headers
  });
  var provider = secondaryUser && secondaryUser.identities && secondaryUser.identities[0] && secondaryUser.identities[0].provider;
  user = await apiCall({
    method: "POST",
    url: linkUri,
    headers,
    json: { user_id: decodedToken.sub, provider }
  });
  console.info(LOG_TAG, "Successfully linked accounts for user: ", user.email);
  return [user, context];
}
async function linkAccountsWithoutPrompt(user, context) {
  const users = await searchUsersWithSameEmail(user);
  const targetUsers = users.filter((u) => u.user_id !== user.user_id).map((u) => u.user_id);
  if (targetUsers.length > 0) {
    var linkUri = config.endpoints.userApi + "/" + targetUsers[0] + "/identities";
    var headers = {
      Authorization: "Bearer " + auth0.accessToken,
      "Content-Type": "application/json",
      "Cache-Control": "no-cache"
    };
    user = await apiCall({
      method: "POST",
      url: linkUri,
      headers,
      json: { user_id: user.user_id, provider: context.connection, connection_id: context.connectionID }
    });
    console.info(LOG_TAG, "Successfully linked accounts for user: ", user.email);
  }
  return [user, context];
}
async function promptUser(user, context) {
  const users = await searchUsersWithSameEmail(user);
  const targetUsers = users.filter((u) => u.user_id !== user.user_id);
  if (targetUsers.length > 0) {
    context.redirect = {
      url: buildRedirectUrl(createToken(user), context.request.query)
    };
  }
  return [user, context];
}
function createToken(user) {
  var options = {
    expiresIn: "5m",
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
function searchUsersWithSameEmail(user) {
  return apiCall({
    url: config.endpoints.usersByEmailApi,
    qs: {
      email: user.email
    }
  });
}
function buildRedirectUrl(token, q, errorType) {
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
  return config.endpoints.linking + "?" + queryString.encode(params);
}
function qualifyDomain(domain) {
  return "https://" + domain + "/";
}
function apiCall(options) {
  return new Promise(function(resolve, reject) {
    const reqOptions = __spreadValues({
      headers: {
        Authorization: "Bearer " + auth0.accessToken,
        Accept: "application/json"
      },
      json: true
    }, options);
    (0, import_request.default)(reqOptions, function handleResponse(err, response, body) {
      if (err) {
        reject(err);
      } else if (response.statusCode < 200 || response.statusCode >= 300) {
        console.error(LOG_TAG, "API call failed: ", body);
        reject(new Error(body));
      } else {
        resolve(response.body);
      }
    });
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {});

return exports.default(user, context, callback);
}
