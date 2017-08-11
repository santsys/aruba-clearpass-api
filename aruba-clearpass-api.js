'use strict';

const request = require('request');
const URL = require('url');

/**
* @callback doNext
* @param {error} error - If there is an error, it is returned here.
* @param {object} body - An object containing the requested information.
*/

/**
 @typedef legacyInitOptions
 @type {Object}
 @property {string} userName ClearPass User Name for API access.
 @property {string} password ClearPass Password for API access.
*/

/**
 @typedef initOptions
 @type {Object}
 @property {string} host The IP or DNS name of the ClearPass host.
 @property {string} clientId The OAuth2 Client Id.
 @property {string} clientSecret The OAuthe2 Client Secret.
 @property {string} token A valid authentication token. Only used if you do not supply a Client Id and Secret.
 @property {boolean} sslValidation Should SSL Validation be used. Set to false for self signed certificates.
 @property {legacyInitOptions} legacyApi Options specific for legacy APIs. (not needed for basic REST processes)
 */

/**
 @typedef searchOptions
 @type {Object}
 @property {Object|string} filter The search filter.
 @property {string} sort The sort order of the results.
 @property {number} offset The number of items to offset the returned results (for paging).
 @property {number} limit THe number of items to return (for paging).
 */

 /**
 * Internal method for general api response processing.
 */
function processCppmResponse(error, response, body, next) {
    if (error) {
        next(error, null);
    }
    else if (response) {
        if (response.statusCode == 200 || response.statusCode == 201 || response.statusCode == 204) {
            if (body) {
                var bodyJs = JSON.parse(body);

                // remove links
                if (bodyJs['_links']) {
                    delete bodyJs['_links'];
                }

                // move '_embeded' items to root
                if (bodyJs['_embedded'] && bodyJs['_embedded']['items']) {
                    bodyJs.items = bodyJs['_embedded']['items'];
                    delete bodyJs['_embedded'];
                }

                next(null, bodyJs);
            }
            else {
                next(null, null);
            }
        }
        else {
            var additionalInfo = '';

            if (body) {
                var bodyJs = JSON.parse(body);

                if (bodyJs.result && bodyJs.result.message) {
                    additionalInfo += ' Message: ' + bodyJs.result.message;
                }

                if (bodyJs && bodyJs.detail) {
                    next(new Error(bodyJs.detail + additionalInfo + ' (Response Code: ' + response.statusCode + ')'), null);
                    return;
                }
            }
            next(new Error('Invalid response from server.' + additionalInfo + ' (Response Code: ' + response.statusCode + ')'), null);
        }
    }
    else {
        next(new Error('No response from server.'), null);
    }
}

/**
 * Aruba ClearPass API
 * @param {initOptions} options The options for the api (host, clientId, clientSecret, token, sslValidation)
 */
function ClearPassApi(options) {
    this.settings = options || {};
    this.expDate = null;
    this.tempToken = null;

    // if sslValidation is not set, enable it (secure by default)
    if (this.settings.sslValidation == null) {
        this.settings.sslValidation = true;
    }

    this.validateSettings(this.settings);
    this.init();
}

/**
* Validates the settings for the CPPM connection.
*/
ClearPassApi.prototype.validateSettings = function (options) {
    if (!options) {
        throw new Error('No options specified.');
    }

    if (!options.host) {
        throw new Error('The CPPM host must be set.');
    }

    if (!options.token) {
        if (!options.clientId) {
            throw new Error('The CPPM API Client ID (clientId) must be specified.');
        }

        if (!options.clientSecret) {
            throw new Error('The CPPM API Client Secret or a valid Token must be specified.');
        }
    }
}

/**
* Setup any inital stuff from the settings.
*/
ClearPassApi.prototype.init = function () {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = ((this.settings.sslValidation == false) ? "0" : "1");
}

ClearPassApi.prototype.getToken = function (next) {
    var self = this;
    if (self.settings.token) {
        next(null, self.settings.token);
    }
    else {
        var now = new Date();
        if (self.expDate != null && self.expDate > now) {
            next(null, self.tempToken);
        }
        else {
            var rOpts = {
                url: self.getUrl('/oauth'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    'grant_type': 'client_credentials',
                    'client_id': self.settings.clientId,
                    'client_secret': self.settings.clientSecret
                })
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    if (error) {
                        next(error, null);
                    }
                    else {
                        if (bodyJs && bodyJs.access_token && bodyJs.expires_in) {
                            var expSeconds = bodyJs.expires_in;
                            var exp = new Date();
                            exp.setTime(exp.getTime() + (1000 * (expSeconds - 10)));
                            self.expDate = exp;
                            self.tempToken = bodyJs.access_token;

                            next(null, self.tempToken);
                        }
                        else {
                            next(new Error('Bad OAuth2 response from server. ' + body), null);
                        }
                    }
                });
            });
        }
    }
}

/**
* Builds an API URL
*/
ClearPassApi.prototype.getUrl = function (endpoint) {
    var self = this;

    if (!self.settings.host) {
        throw new Error('The host was not set.');
    }

    if (endpoint) {
        if (!endpoint.startsWith('/')) {
            endpoint = '/' + endpoint;
        }
    }

    var rxUrlStart = /^http(s)?:\/\//;
    if (self.settings.host.match(rxUrlStart)) {
        var urlToUse = self.settings.host;

        if (urlToUse.endsWith('/')) {
            urlToUse = urlToUse.substr(0, urlToUse.length - 1);
        }

        return urlToUse + endpoint;
    }
    else {        
        var cppmUrl = URL.resolve('https://' + self.settings.host, '/api' + endpoint);
        return cppmUrl;
    }
}

/**
* Gets the URL for Legacy API Communications
*/
ClearPassApi.prototype.getLegacyUrl = function (endpoint) {
    var self = this;

    if (!self.settings.host) {
        throw new Error('The host was not set.');
    }

    if (endpoint) {
        if (!endpoint.startsWith('/')) {
            endpoint = '/' + endpoint;
        }
    }

    var rxUrlStart = /^http(s)?:\/\//;
    if (self.settings.host.match(rxUrlStart)) {
        return URL.resolve(self.settings.host, endpoint);
    }
    else {
        return URL.resolve('https://' + self.settings.host, endpoint);
    }
}

/****************************************************************************************
API Management
****************************************************************************************/

/**
 @typedef apiClientOptions
 @type {Object}
 @property {string} [access_lifetime] (string, optional): Lifetime of an OAuth2 access token,
 @property {string} [access_token_lifetime] (string): Specify the lifetime of an OAuth2 access token,
 @property {string} access_token_lifetime_units (string): Specify the lifetime of an OAuth2 access token,
 @property {string} [auto_confirm] (integer, optional): Not supported at this time,
 @property {string} [client_description] (string, optional): Use this field to store comments or notes about this API client,
 @property {string} client_id (string): The unique string identifying this API client. Use this value in the OAuth2 “client_id” parameter,
 @property {string} [client_public] (boolean, optional): Public clients have no client secret,
 @property {string} [client_refresh] (boolean, optional): An OAuth2 refresh token may be used to obtain an updated access token. Use grant_type=refresh_token for this,
 @property {string} [client_secret] (string, optional): Use this value in the OAuth2 "client_secret" parameter. NOTE: This value is encrypted when stored and cannot be retrieved.,
 @property {string} [enabled] (boolean, optional): Enable API client,
 @property {string} id (string): The unique string identifying this API client. Use this value in the OAuth2 "client_id" parameter,
 @property {string} grant_types (string): Only the selected authentication method will be permitted for use with this client ID,
 @property {string} [profile_id] (integer): The operator profile applies role-based access control to authorized OAuth2 clients. This determines what API objects and methods are available for use,
 @property {string} [profile_name] (string, optional): Name of operator profile,
 @property {string} [redirect_uri] (string, optional): Not supported at this time,
 @property {string} [refresh_lifetime] (string, optional): Lifetime of an OAuth2 refresh token,
 @property {string} refresh_token_lifetime (string): Specify the lifetime of an OAuth2 refresh token,
 @property {string} [refresh_token_lifetime_units] (string): Specify the lifetime of an OAuth2 refresh token,
 @property {string} [scope] (string, optional): Not supported at this time,
 @property {string} [user_id] (string, optional): Not supported at this time
*/

/**
* Search API Clients.
* @param {searchOptions} options The options for search (filter, sort, offset, limit)
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getApiClients = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/api-client'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Create a new api client.
* @param {apiClientOptions} apiClient The attributes of the API Client.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.createApiClient = function (apiClient, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/api-client'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(apiClient || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get a client by client id.
* @param {string} clientId The client id
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getApiClient = function (clientId, next) {
    var self = this;

    if (!clientId) {
        throw new Error('You must specify a client id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/api-client/' + clientId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a client by client id.
* @param {string} clientId The client id
* @param {apiClientOptions} clientOptions The attributes of the client to update
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.updateApiClient = function (clientId, clientOptions, next) {
    var self = this;

    if (!clientId) {
        throw new Error('You must specify a client id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/api-client/' + clientId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(clientOptions || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a api client by client id.
* @param {string} clientId The client id
* @param {apiClientOptions} clientOptions The new attributes of the client.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.replaceApiClient = function (clientId, clientOptions, next) {
    var self = this;

    if (!clientId) {
        throw new Error('You must specify a client id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/api-client/' + clientId),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(clientOptions || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete an api client.
* @param {string} clientId The client id
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteApiClient = function (clientId, next) {
    var self = this;

    if (!clientId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/api-client/' + clientId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Information
****************************************************************************************/

/**
* Gets the server version information.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getServerVersion = function (next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/server/version'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Gets the servers FIPS mode information.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getFipsStatus = function (next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/server/fips'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Gets the server configuration information
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getServerConfiguration = function (next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/cluster/server'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Guest Manager: Sessions
****************************************************************************************/

/**
* Get Guest Sessions
* @param {searchOptions} options - The options for session search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getGuestSessions = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0){
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/session'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '-id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Disconnect an active Session
* @param {String} sessionId - The session to be disconnected
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.disconnectSession = function (sessionId, next) {
    var self = this;

    if (!sessionId) {
        throw new Error('You must specify a session id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/session/' + sessionId + '/disconnect'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify({
                    confirm_disconnect: true
                })
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Disconnect an active Session
* @param {String} sessionId - The session to be disconnected
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getSessionReauthorizationProfiles = function (sessionId, next) {
    var self = this;

    if (!sessionId) {
        throw new Error('You must specify a session id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/session/' + sessionId + '/reauthorize'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Force the reauth of a session using the specified reauthorization profile
* @param {String} sessionId - The session to be disconnected
* @param {String} reauthProfile - The reauthorization profile to use
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.reauthorizeSession = function (sessionId, reauthProfile, next) {
    var self = this;

    if (!sessionId) {
        throw new Error('You must specify a session id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/session/' + sessionId + '/reauthorize'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify({
                    confirm_reauthorize: true,
                    reauthorize_profile: reauthProfile
                })
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/****************************************************************************************
Guest Manager: Configuration
****************************************************************************************/

/**
 @typedef guestManagerConfig
 @type {Object}
 @property {string} random_username_method (string) = ['nwa_digits_password' or 'nwa_letters_password' or 'nwa_lettersdigits_password' or 'nwa_picture_password' or 'nwa_sequence']: The method used to generate random account usernames,
 @property {string} random_username_multi_prefix (string, optional): Identifier string to prepend to usernames. Dynamic entries based on a user attribute can be entered as '_' + attribute. For example '_role_name'. The username length will determine the length of the numeric sequence only. Recommend 4,
 @property {string} random_username_picture (string, optional): Format picture (see below) describing the usernames that will be created for visitors. • Alphanumeric characters are passed through without modification. • '#' is replaced with a random digit [0-9]. • '$' or '?' is replaced with a random letter [A-Za-z] • '_' is replaced with a random lowercase letter [a-z] • '^' is replaced with a random uppercase letter [A-Z] • '*' is replaced with a random letter or digit [A-Za-z0-9]. • '!' is replaced with a random punctuation symbol [excluding apostrophe, quotes] • '&' is replaced with a random character (union of sets ! and *) • '@' is replaced with a random letter or digit, excluding vowels • '%' is replaced with a random letter or digit, excluding vowels and anything that looks like another (il1, B8, O0, Z2),
 @property {string} random_username_length (integer): The length, in characters, of generated account usernames,
 @property {object} guest_initial_sequence_options (object, optional): Create multi next available sequence number. These values will be used when multi_initial_sequence is set to -1,
 @property {string} random_password_method (string) = ['nwa_digits_password' or 'nwa_letters_password' or 'nwa_lettersdigits_password' or 'nwa_alnum_password' or 'nwa_strong_password' or 'nwa_complex_password' or 'nwa_complexity_password' or 'nwa_words_password' or 'nwa_picture_password']: The method used to generate a random account password,
 @property {string} random_password_picture (string, optional): Format picture (see below) describing the passwords that will be created for visitors. • Alphanumeric characters are passed through without modification. • '#' is replaced with a random digit [0-9]. • '$' or '?' is replaced with a random letter [A-Za-z] • '_' is replaced with a random lowercase letter [a-z] • '^' is replaced with a random uppercase letter [A-Z] • '*' is replaced with a random letter or digit [A-Za-z0-9]. • '!' is replaced with a random punctuation symbol [excluding apostrophe, quotes] • '&' is replaced with a random character (union of sets ! and *) • '@' is replaced with a random letter or digit, excluding vowels • '%' is replaced with a random letter or digit, excluding vowels and anything that looks like another (il1, B8, O0, Z2),
 @property {number} random_password_length (integer): Number of characters to include in randomly-generated account passwords,
 @property {string} guest_password_complexity (string) = ['none' or 'case' or 'number' or 'alphanumeric' or 'casenumeric' or 'punctuation' or 'complex']: Password complexity to enforce for manually-entered guest passwords. Requires the random password type 'A password matching the password complexity requirements' and the field validator 'NwaIsValidPasswordComplexity' for manual password entry,
 @property {string} guest_password_minimum (integer): The minimum number of characters that a guest password must contain,
 @property {string} guest_password_disallowed (string, optional): Characters which cannot appear in a user-generated password,
 @property {string} guest_password_disallowed_words (string, optional): Comma separated list of words disallowed in the random words password generator. Note there is an internal exclusion list built into the server,
 @property {boolean} guest_log_account_password (boolean, optional): Whether to record passwords for guest accounts in the application log,
 @property {boolean} guest_view_account_password (boolean, optional): If selected, guest account passwords may be displayed in the list of guest accounts. This is only possible if operators have the View Passwords privilege,
 @property {number} guest_do_expire (integer) = ['4' or '3' or '2' or '1']: Default action to take when the expire_time is reached. Note that a logout can only occur if the NAS is RFC-3576 compliant,
 @property {object} guest_account_expiry_options (object): The available options to select from when choosing the expiration time of a guest account (expire_after). Expiration times are specified in hours,
 @property {object} guest_modify_expire_time_options (object): The available options to select from when modifying an account's expiration (modify_expire_time). Note some items may be dynamically removed based on the state of the account,
 @property {object} guest_lifetime_options (object): The available options to select from when choosing the lifetime of a guest account (expire_postlogin). Lifetime values are specified in minutes,
 @property {boolean} g_action_notify_account_expire_enabled (boolean, optional): If checked, users will receive an email notification when their device's network credentials are due to expire,
 @property {number} g_action_notify_account_expiration_duration (integer, optional): Account expiration emails are sent this many days before the account expires. Enter a value between 1 and 30,
 @property {string} g_action_notify_account_expire_email_unknown (string, optional) = ['none' or 'fixed' or 'domain']: Specify where to send emails if the user's account doesn't have an email address recorded,
 @property {string} g_action_notify_account_expire_email_unknown_fixed (string, optional): Address used when no email address is known for a user,
 @property {string} g_action_notify_account_expire_email_unknown_domain (string, optional): Domain to append to the username to form an email address,
 @property {string} g_action_notify_account_expire_subject (string, optional): Enter a subject for the notification email,
 @property {number} g_action_notify_account_expire_message (integer, optional) = ['2' or '11' or '5' or '6' or '1' or '3' or '7' or '8' or '10' or '9' or '4']: The plain text or HTML print template to use when generating an email message,
 @property {string} g_action_notify_account_expire_skin (string, optional) = ['' or 'plaintext' or 'html_embedded' or 'receipt' or 'default' or 'Aruba Amigopod Skin' or 'Blank Skin' or 'ClearPass Guest Skin' or 'Custom Skin 1' or 'Custom Skin 2' or 'Galleria Skin' or 'Galleria Skin 2']: The format in which to send email receipts,
 @property {string} g_action_notify_account_expire_copies (string, optional) = ['never' or 'always_cc' or 'always_bcc']: Specify when to send to the recipients in the Copies To list,
 @property {string} g_action_notify_account_expire_copies_to (string, optional): An optional list of email addresses to which copies of expiry notifications will be sent,
 @property {string} site_ssid (string, optional): The SSID of the wireless LAN, if applicable. This will appear on guest account print receipts,
 @property {string} site_wpa_key (string, optional): The WPA key for the wireless LAN, if applicable. This will appear on guest account print receipts,
 @property {boolean} guest_receipt_print_button (boolean, optional): Guest receipts can print simply by selecting the template in the dropdown, or by clicking a link,
 @property {string} guest_account_terms_of_use_url (string, optional): The URL of a terms and conditions page. The URL will appear in any terms checkbox with: {nwa_global name=guest_account_terms_of_use_url} It is recommended to upload your terms in Content Manager, where the files will be referenced with the "public/" prefix. Alternatively, you can edit Terms and Conditions under Configuration > Pages > Web Pages. If your site is hosted externally, be sure the proper access control lists (ACLs) are in place. If terms are not required, it is recommended to edit the terms field on your forms to a UI type "hidden" and an Initial Value of 1,
 @property {number} guest_active_sessions (integer, optional): Enable limiting the number of active sessions a guest account may have. Enter 0 to allow an unlimited number of sessions,
 @property {string} guest_about_guest_network_access (string, optional): Template code to display on the Guest Manager start page, under the “About Guest Network Access” heading. Leave blank to use the default text, or enter a hyphen ("-") to remove the default text and the heading
*/

/**
* Get the guest manager configuration.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getGuestManagerConfiguration = function (next) {
    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guestmanager'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get the guest manager configuration.
* @param {guestManagerConfig} options The server configuration options
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateGuestManagerConfiguration = function (options, next) {
    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guestmanager'),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(options || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Guest Manager: Device
****************************************************************************************/

/**
* Get a list of device details.
* @param {searchOptions} options - The options for session search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getDevices = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '-id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Create a new device.
* @param {object} deviceAttributes - The attributes of the device to update
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.createDevice = function (deviceAttributes, doChangeOfAuth, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(deviceAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get device by device id.
* @param {string} deviceId - The device id
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getDevice = function (deviceId, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must specify a device id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device/' + deviceId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a device by device id.
* @param {string} deviceId - The device id
* @param {object} deviceAttributes - The attributes of the device to update
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.updateDevice = function (deviceId, deviceAttributes, doChangeOfAuth, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must specify a device id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device/' + deviceId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(deviceAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a device by device id.
* @param {string} deviceId - The device id
* @param {object} deviceAttributes - The attributes of the device to update
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.replaceDevice = function (deviceId, deviceAttributes, doChangeOfAuth, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must specify a device id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device/' + deviceId),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(deviceAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a device by device id.
* @param {string} deviceId - The device id
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteDevice = function (deviceId, doChangeOfAuth, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must specify a device id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device/' + deviceId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Guest Manager: Device By Mac
****************************************************************************************/

/**
* Get device by mac address.
* @param {string} macAddress - The MAC Address of the device
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getDeviceByMac = function (macAddress, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a MAC Address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device/mac/' + macAddress),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a device by mac address.
* @param {string} macAddress - The MAC Address of the device
* @param {object} deviceAttributes - The attributes of the device to update
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.updateDeviceByMac = function (macAddress, deviceAttributes, doChangeOfAuth, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a MAC Address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device/mac/' + macAddress),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(deviceAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a device by mac address.
* @param {string} macAddress - The MAC Address of the device
* @param {object} deviceAttributes - The attributes of the device to update
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.replaceDeviceByMac = function (macAddress, deviceAttributes, doChangeOfAuth, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a MAC Address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device/mac/' + macAddress),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(deviceAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a device by mac address.
* @param {string} macAddress - The MAC Address of the device
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteDeviceByMac = function (macAddress, doChangeOfAuth, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a MAC Address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/device/mac/' + macAddress),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/****************************************************************************************
Guest Manager: Guests
****************************************************************************************/

/**
* Get a list of guest accounts.
* @param {searchOptions} options - The options for the guest account search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getGuests = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '-id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Create a new guest account.
* @param {Object} guestAttributes - The attributes of the guest account to update
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.createGuest = function (guestAttributes, doChangeOfAuth, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(guestAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get guest account by guest id.
* @param {string} guestId The guest account id
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getGuest = function (guestId, next) {
    var self = this;

    if (!guestId) {
        throw new Error('You must specify a guest id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/' + guestId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a guest account by guest id.
* @param {string} guestId The guest account id
* @param {Object} guestAttributes The attributes of the device to update
* @param {boolean} doChangeOfAuth Do a Change of Authorization
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateGuest = function (guestId, guestAttributes, doChangeOfAuth, next) {
    var self = this;

    if (!guestId) {
        throw new Error('You must specify a guest id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/' + guestId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(guestAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a guest account by guest id.
* @param {string} guestId The guest account id
* @param {Object} guestAttributes - The attributes of the device to update
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.replaceGuest = function (guestId, guestAttributes, doChangeOfAuth, next) {
    var self = this;

    if (!guestId) {
        throw new Error('You must specify a guest id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/' + guestId),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(guestAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a guest by guest id.
* @param {string} guestId The guest account id
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteGuest = function (guestId, doChangeOfAuth, next) {
    var self = this;

    if (!guestId) {
        throw new Error('You must specify a guest id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/' + guestId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get guest account by user name.
* @param {string} userName The guest user name.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getGuestByUserName = function (userName, next) {
    var self = this;

    if (!userName) {
        throw new Error('You must specify a user name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/username/' + userName),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a guest by user name.
* @param {string} userName The guest user name.
* @param {Object} guestAttributes The attributes of the device to update
* @param {boolean} doChangeOfAuth Do a Change of Authorization
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateGuestByUserName = function (userName, guestAttributes, doChangeOfAuth, next) {
    var self = this;

    if (!userName) {
        throw new Error('You must specify a user name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/username/' + userName),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(guestAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a guest by user name.
* @param {string} userName The guest user name.
* @param {Object} guestAttributes - The attributes of the device to update
* @param {boolean} doChangeOfAuth - Do a Change of Authorization
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.replaceGuestByUserName = function (userName, guestAttributes, doChangeOfAuth, next) {
    var self = this;

    if (!userName) {
        throw new Error('You must specify a user name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/username/' + userName),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                },
                body: JSON.stringify(guestAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a guest by user name.
* @param {string} userName The guest user name.
* @param {boolean} doChangeOfAuth Do a Change of Authorization
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.deleteGuestByUsername = function (userName, doChangeOfAuth, next) {
    var self = this;

    if (!userName) {
        throw new Error('You must specify a user name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/username/' + userName),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    change_of_authorization: (doChangeOfAuth == null ? '' : (doChangeOfAuth == true ? "true" : "false"))
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Guest Manager: Guest Sponsor
****************************************************************************************/

/**
  @typedef guestSponsorResponse
  @type {object}
  @property {string} token (string): Registration token,
  @property {string} register_token (string): Registration token,
  @property {boolean} [register_reject] (boolean, optional): Set to true to reject the sponsorship request,
  @property {number} [role_id] (integer, optional): Override the guest role,
  @property {string} [modify_expire_time] (string, optional): Override the guest expiration time,
  @property {string} [confirm_expire_time] (string, optional): Timestamp for new expiration time; used if modify_expire_time is "expire_time"
*/

/**
* Accept or reject a guest account that is waiting for a sponsor's approval.
* @param {number} guestId The guest account id.
* @param {randomPasswordOptions} [options] The options to be used for the random password generation.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.confirmGuestSponsor = function (guestId, options, next) {
    var self = this;

    if (!guestId) {
        throw new Error('You must specify a guest id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/guest/' + encodeURIComponent(guestId) + '/sponsor'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(options || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Guest Manager: Random Password
****************************************************************************************/

/**
  @typedef randomPasswordOptions
  @type {object}
  @property {string} [random_password_method] The random password method to use.
  @property {number} [random_password_length] The length of the password to be created.
  @property {string} [random_password_picture] The picture to be used for the nwa_picture_password method.
*/

/**
* Generate a random password.
* @param {randomPasswordOptions} [options] The options to be used for the random password generation.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getRandomPassword = function (options, next) {
    var self = this;
    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/random-password'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(options || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/****************************************************************************************
Identity: Endpoints
****************************************************************************************/
/**
  @typedef endpointObject
  @type {object}
  @property {number} [id] The endpoint id.
  @property {string} [mac_address] The endpoints MAC Address.
  @property {string} [description] A description of the endpoint.
  @property {string} [status] The endpoint status (Known, Unknown, Disabled).
  @property {object} [attributes] Additional endpoint attributes.
*/

/**
* Get a list of endpoints.
* @param {searchOptions} options - The options for the guest account search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getEndpoints = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '-id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Create a new endpoint.
* @param {endpointObject} endpointAttributes - The attributes of the endpoint to update
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.createEndpoint = function (endpointAttributes,  next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(endpointAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get an endpoint by id.
* @param {string} endpointId The endpoint id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getEndpoint = function (endpointId, next) {
    var self = this;

    if (!endpointId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint/' + endpointId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update an endpoint by id.
* @param {string} endpointId The endpoint id.
* @param {endpointObject} endpointAttributes - The attributes of the endpoint.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateEndpoint = function (endpointId, endpointAttributes, next) {
    var self = this;

    if (!endpointId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint/' + endpointId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(endpointAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace an endpoint by id.
* @param {string} endpointId The endpoint id.
* @param {endpointObject} endpointAttributes - The attributes of the endpoint.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.replaceEndpoint = function (endpointId, endpointAttributes, next) {
    var self = this;

    if (!endpointId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint/' + endpointId),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(endpointAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete and endpoint by id.
* @param {string} endpointId The endpoint id.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteEndpoint = function (endpointId, next) {
    var self = this;

    if (!endpointId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint/' + endpointId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get an endpoint by mac address.
* @param {string} macAddress The endpoint MAC Address.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getEndpointByMac = function (macAddress, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a MAC Address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint/mac-address/' + macAddress),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update and endpoint by mac address.
* @param {string} macAddress The endpoint MAC Address.
* @param {endpointObject} endpointAttributes - The attributes of the endpoint.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateEndpointByMac = function (macAddress, endpointAttributes, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a MAC Address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint/mac-address/' + macAddress),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(endpointAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace an endpoint by mac address.
* @param {string} macAddress The endpoint MAC Address.
* @param {endpointObject} endpointAttributes - The attributes of the endpoint.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.replaceEndpointByMac = function (macAddress, endpointAttributes, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a MAC Address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint/mac-address/' + macAddress),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(endpointAttributes || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete an endpoint by mac address.
* @param {string} macAddress The endpoint MAC Address.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.deleteEndpointByMac = function (macAddress, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a MAC Address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/endpoint/mac-address/' + macAddress),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Extensions
****************************************************************************************/

/**
  @typedef instanceCreate
  @type {object}
  @property {string} [state] (string, optional) = ['stopped' or 'running']: Desired state of the extension,
  @property {string} store_id (string): ID from the extension store,
  @property {string} [files] (object, optional): Maps extension file IDs to local content items, with "public:" or "private:" prefix
*/

/**
* Get a list of installed extensions.
* @param {searchOptions} options - The options for the extensions search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getExtensions = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+name',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Install a new extension from the extension store.
* @param {instanceCreate} createOptions The options for the extension create.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.installExtension = function (createOptions, next) {
    var self = this;
    
    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(createOptions)
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get an installed extensions.
* @param {string} extensionId The id of the extension
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getExtension = function (extensionId, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update an installed extensions state.
* @param {string} extensionId The id of the extension
* @param {string} extensionState The state of the extension ('stopped', 'running')
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateExtensionState = function (extensionId, extensionState, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify({ state: extensionState })
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete an installed extension.
* @param {string} extensionId The id of the extension
* @param {boolean} force Force extension delete
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.deleteExtension = function (extensionId, force, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    force: force
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get an extensions config.
* @param {string} extensionId The id of the extension
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getExtensionConfig = function (extensionId, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId + '/config'),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update an extensions config.
* @param {string} extensionId The id of the extension
* @param {object} config The extensions configuration
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateExtensionConfig = function (extensionId, config, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId + '/config'),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(config || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Restart an extension.
* @param {string} extensionId The id of the extension
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.restartExtension = function (extensionId, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId + '/restart'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Start an extension.
* @param {string} extensionId The id of the extension
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.startExtension = function (extensionId, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId + '/start'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Stop an extension.
* @param {string} extensionId The id of the extension
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.stopExtension = function (extensionId, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId + '/stop'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
  @typedef extensionLogOptions
  @type {object}
  @property {boolean} stdout Include extension's standard-output messages
  @property {boolean} stderr Include extension's standard-error messages
  @property {number} since Specify a UNIX timestamp to only return log entries since that time
  @property {boolean} timestamps Prefix every log line with its UTC timestamp
  @property {string} tail Return this number of lines at the end of the logs, or "all" for everything
*/

/**
* Get extension logs.
* @param {string} extensionId The id of the extension
* @param {extensionLogOptions} logOptions Log view options
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getExtensionLogs = function (extensionId, logOptions, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/extension/instance/' + extensionId + '/log'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    stdout: logOptions.stdout == false ? false : true,
                    stderr: logOptions.stderr == false ? false : true,
                    since: since,
                    timestamps: logOptions.timestamps == true ? true : false,
                    tail: logOptions.tail || "all"
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Dictionaries
****************************************************************************************/

/****************************************************************************************
Attributes
****************************************************************************************/

/**
  @typedef attributeOptions
  @type {object}
  @property {number} id (integer, optional): Numeric ID of the attribute,
  @property {string} [name] (string, optional): Name of the attribute,
  @property {string} [entity_name] (string, optional) = ['Device' or 'LocalUser' or 'GuestUser' or 'Endpoint' or 'Onboard']: Entity Name of the attribute,
  @property {string} [data_type] (string, optional) = ['Boolean' or 'Date' or 'Date-Time' or 'Day' or 'IPv4Address' or 'Integer' or 'List' or 'MACAddress' or 'String' or 'Text' or 'TimeOfDay']: Data Type of the attribute,
  @property {boolean} [mandatory] (boolean, optional): Enable this to make this attribute mandatory for the entity ,
  @property {string} [default_value] (string, optional): Default Value of the attribute,
  @property {boolean} [allow_multiple] (boolean, optional): To Allow Multiple values of the atribute for Data Type String,
  @property {string} [allowed_value] (string, optional): Allowed Value for Data Type List (e.g., example1,example2,example3)
*/

/**
* Get a list of attributes.
* @param {searchOptions} options - The options for the attribute search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getAttributes = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/**
* Create a new attribute.
* @param {attributeOptions} attribute The options for the attribute.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.createAttribute = function (attribute, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(attribute || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get an attribute by id.
* @param {number} attributeId The attribute id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getAttribute = function (attributeId, next) {
    var self = this;

    if (!attributeId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute/' + attributeId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update an attribute by id.
* @param {number} attributeId The attribute id.
* @param {attributeOptions} attribute The options for the attribute.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.updateAttribute = function (attributeId, attribute, next) {
    var self = this;

    if (!attributeId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute/' + attributeId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(attribute || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace an attribute by id.
* @param {number} attributeId The attribute id.
* @param {attributeOptions} attribute The options for the attribute.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.replaceAttribute = function (attributeId, attribute, next) {
    var self = this;

    if (!attributeId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute/' + deviceId),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(attribute || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete an attribute by id.
* @param {number} attributeId The attribute id.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteAttribute = function (attributeId, next) {
    var self = this;

    if (!attributeId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute/' + attributeId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/**
* Get an attribute by name.
* @param {string} entityName The entity name.
* @param {string} attributeName The attribute name.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getAttributeByName = function (entityName, attributeName, next) {
    var self = this;

    if (!entityName) {
        throw new Error('You must specify an entity name ([Device or LocalUser or GuestUser or Endpoint or Onboard]).');
    }

    if (!attributeName) {
        throw new Error('You must specify an attribute name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute/' + entityName + '/name/' + attributeName),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update an attribute by name.
* @param {string} entityName The entity name.
* @param {string} attributeName The attribute name.
* @param {attributeOptions} attribute The options for the attribute.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateAttributeByName = function (entityName, attributeName, attribute, next) {
    var self = this;

    if (!entityName) {
        throw new Error('You must specify an entity name ([Device or LocalUser or GuestUser or Endpoint or Onboard]).');
    }

    if (!attributeName) {
        throw new Error('You must specify an attribute name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute/' + entityName + '/name/' + attributeName),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(attribute || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace an attribute by name.
* @param {string} entityName The entity name.
* @param {string} attributeName The attribute name.
* @param {attributeOptions} attribute The options for the attribute.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.replaceAttributeByName = function (entityName, attributeName, attribute, next) {
    var self = this;

    if (!entityName) {
        throw new Error('You must specify an entity name ([Device or LocalUser or GuestUser or Endpoint or Onboard]).');
    }

    if (!attributeName) {
        throw new Error('You must specify an attribute name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute/' + entityName + '/name/' + attributeName),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(attribute || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete an attribute by name.
* @param {string} entityName The entity name.
* @param {string} attributeName The attribute name.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteAttributeByName = function (entityName, attributeName, next) {
    var self = this;

    if (!entityName) {
        throw new Error('You must specify an entity name ([Device or LocalUser or GuestUser or Endpoint or Onboard]).');
    }

    if (!attributeName) {
        throw new Error('You must specify an attribute name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/attribute/' + entityName + '/name/' + attributeName),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/****************************************************************************************
Context Server Actions
****************************************************************************************/

/**
  @typedef contextServerAction
  @type {object}
  @property {number} id (integer, optional): Numeric ID of the Context Server Action,
  @property {string} [server_type] (string, optional) = ['Aruba Activate' or 'airwatch' or 'JAMF' or 'MobileIron' or 'MaaS360' or 'SAP Afaria' or 'SOTI' or 'Google Admin Console' or 'Palo Alto Networks Panorama' or 'Palo Alto Networks Firewall' or 'Juniper Networks SRX' or 'XenMobile' or 'Generic HTTP' or 'AirWave' or 'ClearPass Cloud Proxy']: Server Type of the Context Server Action,
  @property {string} [server_name] (string, optional): Server Name of the Context Server Action,
  @property {string} [action_name] (string, optional): Action Name of the Context Server Action,
  @property {string} [description] (string, optional): Description of the Context Server Action,
  @property {string} [http_method] (string, optional) = ['GET' or 'POST' or 'PUT' or 'DELETE']: Http method of the Context Server Action,
  @property {boolean} [skip_http_auth] (boolean, optional): Enable to skip HTTP Basic Authentication,
  @property {string} [url] (string, optional): URL of the Context Server Action,
  @property {string} [content_type] (string, optional) = ['HTML' or 'JSON' or 'PLANE' or 'XML']: Content-Type of the Context Server Action. Note : For CUSTOM type use any string,
  @property {string} [content] (string, optional): Content of the Context Server Action,
  @property {object} [headers] (object, optional): Headers(key/value pairs) of the Context Server Action (e.g., [{"attr_name":"key1","attr_value":"value1"},{"attr_name":"key2","attr_value":"value2"}]),
  @property {object} [attributes] (object, optional): Attributes(key/value pairs) of the Context Server Action (e.g., [{"attr_name":"key1","attr_value":"value1"},{"attr_name":"key2","attr_value":"value2"}])
*/

/**
* Get a list of context server actions.
* @param {searchOptions} options - The options for the context action search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getContextServerActions = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/**
* Create a new context server action.
* @param {contextServerAction} action The options for the action.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.createContextServerAction = function (action, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(action || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get a context server action by id.
* @param {number} csaId The Context Server Action id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getContextServerAction = function (csaId, next) {
    var self = this;

    if (!csaId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action/' + csaId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a context server action by id.
* @param {number} csaId The Context Server Action id.
* @param {contextServerAction} action The options for the action.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.updateContextServerAction = function (csaId, action, next) {
    var self = this;

    if (!csaId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action/' + csaId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(action || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a context server action by id.
* @param {number} csaId The Context Server Action id.
* @param {contextServerAction} action The options for the action.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.replaceContextServerAction = function (csaId, action, next) {
    var self = this;

    if (!csaId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action/' + csaId),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(action || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a context server action by id.
* @param {number} csaId The Context Server Action id.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteContextServerAction = function (csaId, next) {
    var self = this;

    if (!csaId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action/' + csaId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/**
* Get a context server action by name.
* @param {string} serverType The server type.
* @param {string} actionName The action name.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getContextServerActionByName = function (serverType, actionName, next) {
    var self = this;

    if (!serverType) {
        throw new Error('You must specify an entity name ([Aruba Activate or airwatch or JAMF or MobileIron or MaaS360 or SAP Afaria or SOTI or Google Admin Console or Palo Alto Networks Panorama or Palo Alto Networks Firewall or Juniper Networks SRX or XenMobile or Generic HTTP or AirWave or ClearPass Cloud Proxy]).');
    }

    if (!actionName) {
        throw new Error('You must specify an action name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action/' + serverType + '/action-name/' + actionName),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a context server action by name.
* @param {string} serverType The server type.
* @param {string} actionName The action name.
* @param {contextServerAction} action The options for the action.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateContextServerActionByName = function (serverType, actionName, action, next) {
    var self = this;

    if (!serverType) {
        throw new Error('You must specify an entity name ([Aruba Activate or airwatch or JAMF or MobileIron or MaaS360 or SAP Afaria or SOTI or Google Admin Console or Palo Alto Networks Panorama or Palo Alto Networks Firewall or Juniper Networks SRX or XenMobile or Generic HTTP or AirWave or ClearPass Cloud Proxy]).');
    }

    if (!actionName) {
        throw new Error('You must specify an action name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action/' + serverType + '/action-name/' + actionName),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(action || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a context server action by name.
* @param {string} serverType The server type.
* @param {string} actionName The action name.
* @param {contextServerAction} action The options for the action.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.replaceContextServerActionByName = function (serverType, actionName, action, next) {
    var self = this;

    if (!serverType) {
        throw new Error('You must specify an entity name ([Aruba Activate or airwatch or JAMF or MobileIron or MaaS360 or SAP Afaria or SOTI or Google Admin Console or Palo Alto Networks Panorama or Palo Alto Networks Firewall or Juniper Networks SRX or XenMobile or Generic HTTP or AirWave or ClearPass Cloud Proxy]).');
    }

    if (!actionName) {
        throw new Error('You must specify an action name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action/' + serverType + '/action-name/' + actionName),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(action || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a context server action by name.
* @param {string} serverType The server type.
* @param {string} actionName The action name.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteContextServerActionByName = function (serverType, actionName, next) {
    var self = this;

    if (!serverType) {
        throw new Error('You must specify an entity name ([Aruba Activate or airwatch or JAMF or MobileIron or MaaS360 or SAP Afaria or SOTI or Google Admin Console or Palo Alto Networks Panorama or Palo Alto Networks Firewall or Juniper Networks SRX or XenMobile or Generic HTTP or AirWave or ClearPass Cloud Proxy]).');
    }

    if (!actionName) {
        throw new Error('You must specify an action name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/context-server-action/' + serverType + '/action-name/' + actionName),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Fingerprints
****************************************************************************************/

/**
  @typedef fingerprint
  @type {object}
  @property {number} id (integer, optional): Id of the fingerprint,
  @property {string} [category] (string, optional): Category name of the fingerprint,
  @property {string} [family] (string, optional): Family name of the fingerprint,
  @property {string} [name] (string, optional): Unique name of the fingerprint
*/

/**
* Get a list of fingerprints.
* @param {searchOptions} options - The options for the fingerprint search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getFingerprints = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/**
* Create a new fingerprint.
* @param {fingerprint} fingerprint The options for the fingerprint.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.createFingerprint = function (fingerprint, next) {
    var self = this;

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(fingerprint || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get a fingerprint by id.
* @param {number} fId The fingerprint id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getFingerprint = function (fId, next) {
    var self = this;

    if (!fId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint/' + fId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a fingerprint by id.
* @param {number} fId The fingerprint id.
* @param {fingerprint} fingerprint The options for the fingerprint.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.updateFingerprint = function (fId, fingerprint, next) {
    var self = this;

    if (!fId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint/' + fId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(fingerprint || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a fingerprint by id.
* @param {number} fId The fingerprint id.
* @param {fingerprint} fingerprint The options for the fingerprint.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.replaceFingerprint = function (fId, fingerprint, next) {
    var self = this;

    if (!fId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint/' + fId),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(fingerprint || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a fingerprint by id.
* @param {number} fId The fingerprint id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.deleteFingerprint = function (fId, next) {
    var self = this;

    if (!fId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint/' + fId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/**
* Get a fingerprint by name.
* @param {string} category The fingerprint category.
* @param {string} family The fingerprint family.
* @param {string} name The fingerprint name.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getFingerprintByName = function (category, family, name, next) {
    var self = this;

    if (!category) {
        throw new Error('You must specify a category.');
    }

    if (!family) {
        throw new Error('You must specify a family.');
    }

    if (!name) {
        throw new Error('You must specify a name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint/' + category + '/' + family + '/' + name),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a fingerprint by name.
* @param {string} category The fingerprint category.
* @param {string} family The fingerprint family.
* @param {string} name The fingerprint name.
* @param {fingerprint} fingerprint The options for the fingerprint.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateFingerprintByName = function (category, family, name, fingerprint, next) {
    var self = this;

    if (!category) {
        throw new Error('You must specify a category.');
    }

    if (!family) {
        throw new Error('You must specify a family.');
    }

    if (!name) {
        throw new Error('You must specify a name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint/' + category + '/' + family + '/' + name),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(fingerprint || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a fingerprint by name.
* @param {string} category The fingerprint category.
* @param {string} family The fingerprint family.
* @param {string} name The fingerprint name.
* @param {fingerprint} fingerprint The options for the fingerprint.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.replaceFingerprintByName = function (category, family, name, fingerprint, next) {
    var self = this;

    if (!category) {
        throw new Error('You must specify a category.');
    }

    if (!family) {
        throw new Error('You must specify a family.');
    }

    if (!name) {
        throw new Error('You must specify a name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint/' + category + '/' + family + '/' + name),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(fingerprint || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a fingerprint by name.
* @param {string} category The fingerprint category.
* @param {string} family The fingerprint family.
* @param {string} name The fingerprint name.
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.deleteFingerprintByName = function (category, family, name, next) {
    var self = this;

    if (!category) {
        throw new Error('You must specify a category.');
    }

    if (!family) {
        throw new Error('You must specify a family.');
    }

    if (!name) {
        throw new Error('You must specify a name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/fingerprint/' + category + '/' + family + '/' + name),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}


/****************************************************************************************
Identity
****************************************************************************************/

/****************************************************************************************
Identity: Endpoint
****************************************************************************************/

/**
* Lookup an endpoint by mac address.
* @param {string} macAddress The MAC Address to lookup.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getInsightsByMac = function (macAddress, next) {
    var self = this;

    if (!macAddress) {
        throw new Error('You must specify a mac address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/insight/endpoint/mac/' + encodeURIComponent(macAddress)),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Lookup an endpoint by ip address.
* @param {string} ipAddr The ip address to lookup.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getInsightsByIp = function (ipAddr, next) {
    var self = this;

    if (!ipAddr) {
        throw new Error('You must specify an ip address.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/insight/endpoint/ip/' + encodeURIComponent(ipAddr)),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Lookup endpoints by ip address range.
* @param {string} ipAddrRange The ip address range to lookup (e.g. 192.168.1.1-255).
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getInsightsByIpRange = function (ipAddrRange, next) {
    var self = this;

    if (!ipAddrRange) {
        throw new Error('You must specify an ip address range.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/insight/endpoint/ip-range/' + encodeURIComponent(ipAddrRange)),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Lookup endpoints by time range.
* @param {string} startTime The start time as a UNIX timestamp.
* @param {string} endTime The end time as a UNIX timestamp.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getInsightsByTimeRange = function (startTime, endTime, next) {
    var self = this;

    if (!startTime) {
        throw new Error('You must specify a start time.');
    }

    if (!endTime) {
        throw new Error('You must specify a end time.');
    }

    if (startTime instanceof Date) {
        startTime = self.dateToUnixTimestamp(startTime);
    }

    if (endTime instanceof Date) {
        endTime = self.dateToUnixTimestamp(endTime);
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/insight/endpoint/time-range/' + encodeURIComponent(startTime) + '/' + encodeURIComponent(endTime)),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Convert a javascript date to a UNIX timestamp.
* @param {date} date The date to convert to a UNIX timestamp.
*/
ClearPassApi.prototype.dateToUnixTimestamp = function (date) {
    var timestamp = 0;
    if (date) {
        timestamp = date.getTime();
    }
    else {
        date = new Date();
        timestamp = date.getTime();
    }
    return parseInt(timestamp / 1000);
}


/****************************************************************************************
Network
****************************************************************************************/

/****************************************************************************************
Network: Network Device
****************************************************************************************/

/**
  @typedef SNMPReadSettings
  @type {object}
  @property {boolean} force_read (boolean, optional): Enable to always read information from this device,
  @property {boolean} read_arp_info (boolean, optional): Enable to read ARP table from this device,
  @property {string} zone_name (string, optional): Policy Manager Zone name to be associated with the network device,
  @property {string} snmp_version (string, optional) = ['V1' or 'V2C' or 'V3']: SNMP version of the network device,
  @property {string} community_string (string, optional): Community string of the network device,
  @property {string} security_level (string, optional) = ['NOAUTH_NOPRIV' or 'AUTH_NOPRIV' or 'AUTH_PRIV']: Security level of the network device,
  @property {string} user (string, optional): Username of the network device,
  @property {string} auth_protocol (string, optional) = ['MD5' or 'SHA']: Authentication protocol of the network device,
  @property {string} auth_key (string, optional): Authentication key of the network device,
  @property {string} privacy_protocol (string, optional) = ['DES_CBC' or 'AES_128']: Privacy protocol of the network device,
  @property {string} privacy_key (string, optional): Privacy key of the network device
*/

/**
  @typedef SNMPWriteSettings
  @type {object}
  @property {number} default_vlan (integer, optional): Default VLAN for port when SNMP-enforced session expires,
  @property {string} snmp_version (string, optional) = ['V1' or 'V2C' or 'V3']: SNMP version of the network device,
  @property {string} community_string (string, optional): Community string of the network device,
  @property {string} security_level (string, optional) = ['NOAUTH_NOPRIV' or 'AUTH_NOPRIV' or 'AUTH_PRIV']: Security level of the network device,
  @property {string} user (string, optional): Username of the network device,
  @property {string} auth_protocol (string, optional) = ['MD5' or 'SHA']: Authentication protocol of the network device,
  @property {string} auth_key (string, optional): Authentication key of the network device,
  @property {string} privacy_protocol (string, optional) = ['DES_CBC' or 'AES_128']: Privacy protocol of the network device,
  @property {string} privacy_key (string, optional): Privacy key of the network device
*/

/**
  @typedef CLISettings
  @type {object}
  @property {string} type (string, optional) = ['SSH' or 'Telnet']: Access type of the network device,
  @property {number} port (integer, optional): SSH/Telnet port number of the network device,
  @property {string} username (string, optional): Username of the network device,
  @property {string} password (string, optional): Password of the network device,
  @property {string} username_prompt_regex (string, optional): Username prompt regex of the network device,
  @property {string} password_prompt_regex (string, optional): Password prompt regex of the network device,
  @property {string} command_prompt_regex (string, optional): Command prompt regex of the network device,
  @property {string} enable_prompt_regex (string, optional): Enable prompt regex of the network device,
  @property {string} enable_password (string, optional): Enable password of the network device
*/

/**
  @typedef OnConnectEnforcementSettings
  @type {object}
  @property {boolean} enabled (boolean, optional): Flag indicating if the network device is enabled with OnConnect Enforcement. SNMP read configuration and Policy Manager Zone is a must for this to work.,
  @property {string} ports (string, optional): Port names used in OnConnect Enforcement in CSV format (e.g.,FastEthernet 1/0/10).Use empty string to enable for all ports. Ports determined to be uplink or trunk ports will be ignored.
*/

/**
  @typedef NetworkDevice
  @type {object}
  @property {number} id (integer, optional): Numeric ID of the network device,
  @property {string} description (string, optional): Description of the network device,
  @property {string} name (string, optional): Name of the network device,
  @property {string} ip_address (string, optional): IP or Subnet Address of the network device,
  @property {string} radius_secret (string, optional): RADIUS Shared Secret of the network device,
  @property {string} tacacs_secret (string, optional): TACACS+ Shared Secret of the network device,
  @property {string} vendor_name (string, optional): Vendor Name of the network device,
  @property {boolean} coa_capable (boolean, optional): Flag indicating if the network device is capable of CoA,
  @property {number} coa_port (integer, optional): CoA port number of the network device ,
  @property {SNMPReadSettings} snmp_read (SNMPReadSettings, optional): SNMP read settings of the network device,
  @property {SNMPWriteSettings} snmp_write (SNMPWriteSettings, optional): SNMP write settings of the network device,
  @property {CLISettings} cli_config (CLISettings, optional): CLI Configuration details of the network device,
  @property {OnConnectEnforcementSettings} onConnect_enforcement (OnConnectEnforcementSettings, optional): OnConnect Enforcement settings of the network device,
  @property {string} attributes (object, optional): Additional attributes(key/value pairs) may be stored with the network device
*/

/**
* Get a list of network devices.
* @param {searchOptions} options - The options for the netork device search (filter, sort, offset, limit)
* @param {doNext} next - The callback function
*/
ClearPassApi.prototype.getNetworkDevices = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Create a new network device.
* @param {NetworkDevice} device The network device details.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.createNetworkDevice = function (device, next) {
    var self = this;
    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device'),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(device || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get the details of a network device.
* @param {number} deviceId The network device id.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.getNetworkDevice = function (deviceId, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device/' + encodeURIComponent(deviceId)),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a network device.
* @param {number} deviceId The network device id.
* @param {NetworkDevice} device The device options.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.updateNetworkDevice = function (deviceId, device, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device/' + encodeURIComponent(deviceId)),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(device || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a network device.
* @param {number} deviceId The network device id.
* @param {NetworkDevice} device The device options.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.replaceNetworkDevice = function (deviceId, device, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device/' + encodeURIComponent(deviceId)),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(device || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a network device.
* @param {number} deviceId The network device id.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.deleteNetworkDevice = function (deviceId, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must specify an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device/' + encodeURIComponent(deviceId)),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get the details of a network device.
* @param {string} deviceName The network device name.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.getNetworkDeviceByName = function (deviceName, next) {
    var self = this;

    if (!deviceName) {
        throw new Error('You must specify a name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device/name/' + encodeURIComponent(deviceName)),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a network device.
* @param {string} deviceName The network device name.
* @param {NetworkDevice} device The device options.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.updateNetworkDeviceByName = function (deviceName, device, next) {
    var self = this;

    if (!deviceName) {
        throw new Error('You must specify a name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device/name/' + encodeURIComponent(deviceName)),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(device || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Replace a network device.
* @param {string} deviceName The network device name.
* @param {NetworkDevice} device The device options.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.replaceNetworkDeviceByName = function (deviceName, device, next) {
    var self = this;

    if (!deviceName) {
        throw new Error('You must specify a name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device/name/' + encodeURIComponent(deviceName)),
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(device || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a network device.
* @param {string} deviceName The network device name.
* @param {doNext} next The callback function.
*/
ClearPassApi.prototype.deleteNetworkDeviceByName = function (deviceName, next) {
    var self = this;

    if (!deviceName) {
        throw new Error('You must specify a name.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/network-device/name/' + encodeURIComponent(deviceName)),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Onboard
****************************************************************************************/

/****************************************************************************************
Onboard: Certificate
****************************************************************************************/

/**
* Search for certificates.
* @param {searchOptions} options The options for the certificate search (filter, sort, offset, limit)
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getCertificates = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/certificate'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get a certificate.
* @param {number} certId The certificate id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getCertificate = function (certId, next) {
    var self = this;

    if (!certId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/certificate/' + certId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a certificate.
* @param {number} certId The certificate id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.deleteCertificate = function (certId, next) {
    var self = this;

    if (!certId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/certificate/' + certId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get a certificate and its trust chain.
* @param {number} certId The certificate id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getCertificateTrustChain = function (certId, next) {
    var self = this;

    if (!certId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/certificate/' + certId + '/chain'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Onboard: Device
****************************************************************************************/

/**
  @typedef OnboardDevice
  @type {object}
  @property {number} id (integer, optional): Numeric ID of the device,
  @property {string} status (string, optional) = ['allowed' or 'pending' or 'denied']: Determines whether the device is able to enroll and access the network,
  @property {string} device_type (string, optional) = ['Other' or 'Android' or 'iOS' or 'OS X' or 'Windows' or 'Ubuntu' or 'Chromebook' or 'Web' or 'External']: Device type,
  @property {string} device_name (string, optional): Device name,
  @property {string} device_udid (string, optional): Unique device identifier,
  @property {string} device_imei (string, optional): International Mobile Station Equipment Identity, if available,
  @property {string} device_iccid (string, optional): SIM card unique serial number, if available,
  @property {string} device_serial (string, optional): Serial number of the device, if available,
  @property {string} product_name (string, optional): Product name of the device, if available,
  @property {string} product_version (string, optional): Product version string of the device, if available,
  @property {string[]} mac_address (array[string], optional): List of MAC addresses associated with the device,
  @property {string} serial_number (string, optional): Serial number of device certificate, if device type is "External",
  @property {string} usernames (string, optional): Usernames that have enrolled this device,
  @property {boolean} enrolled (boolean, optional): Flag indicating device has been provisioned and currently has a valid certificate,
  @property {string} expanded_type (string, optional): Marketing name for the product,
  @property {string} mdm_managed (string, optional): Mobile device management (MDM) vendor name, if an endpoint context server reports the device as managed,
  @property {string} device_identifier (string, optional): Unique identifier string
*/

/**
* Search for devices
* @param {searchOptions} options The options for the device search (filter, sort, offset, limit)
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getOnboardDevices = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/onboard/device'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get a device.
* @param {number} deviceId The device id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getOnboardDevice = function (deviceId, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/onboard/device/' + deviceId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a device.
* @param {number} deviceId The device id.
* @param {OnboardDevice} options The device options.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateOnboardDevice = function (deviceId, options, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/onboard/device/' + deviceId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(options || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a device.
* @param {number} deviceId The device id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.deleteOnboardDevice = function (deviceId, next) {
    var self = this;

    if (!deviceId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/onboard/device/' + deviceId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Onboard: User
****************************************************************************************/

/**
  @typedef OnboardUser
  @type {object}
  @property {number} id (integer, optional): Numeric ID of the user
  @property {string} status (string, optional): ['allowed' or 'denied']: Determines whether the user can enroll devices
  @property {string} username (string, optional): Username of the user
  @property {number} device_count (undefined, optional): Number of devices enrolled by this user
*/

/**
* Search for users
* @param {searchOptions} options The options for the user search (filter, sort, offset, limit)
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getOnboardUsers = function (options, next) {
    var self = this;

    options.filter = options.filter || {};

    if (!(options.filter instanceof String)) {
        options.filter = JSON.stringify(options.filter);
    }

    if (options.offset <= 0) {
        options.offset = 0;
    }

    if (options.limit <= 0) {
        options.limit = 25;
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/user'),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                qs: {
                    filter: options.filter,
                    sort: options.sort || '+id',
                    offset: options.offset,
                    limit: options.limit,
                    calculate_count: true
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Get a user.
* @param {number} userId The user id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.getOnboardUser = function (userId, next) {
    var self = this;

    if (!userId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/user/' + userId),
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Update a user.
* @param {number} userId The user id.
* @param {OnboardUser} options The user options.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.updateOnboarduser = function (userId, options, next) {
    var self = this;

    if (!userId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/user/' + userId),
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                },
                body: JSON.stringify(options || {})
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/**
* Delete a user.
* @param {number} userId The user id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.deleteOnboardDevice = function (userId, next) {
    var self = this;

    if (!userId) {
        throw new Error('You must enter an id.');
    }

    self.getToken(function (e, t) {
        if (e) {
            next(e, null);
        }
        else {
            var rOpts = {
                url: self.getUrl('/user/' + userId),
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + t
                }
            };
            request(rOpts, function (error, response, body) {
                processCppmResponse(error, response, body, function (error, bodyJs) {
                    next(error, bodyJs);
                });
            });
        }
    });
}

/****************************************************************************************
Legacy: Profiler API
****************************************************************************************/

/**
  @typedef DeviceProfileDhcp
  @type {object}
  @property {string} option55 (string, optional)
  @property {string} option60 (string, optional)
  @property {string} options (string, optional)
*/

/**
  @typedef DeviceProfileActiveSync
  @type {object}
  @property {string} device_type (string, optional)
  @property {string} user_agent (string, optional)
*/

/**
  @typedef DeviceProfileHost
  @type {object}
  @property {string} os_type (string, optional)
  @property {string} user_agent (string, optional)
*/

/**
  @typedef DeviceProfileSnmp
  @type {object}
  @property {string} sys_descr (string, optional)
  @property {string} device_type (string, optional)
  @property {string} cdp_cache_platform (string, optional)
*/

/**
  @typedef DeviceProfileDevice
  @type {object}
  @property {string} category (string, optional)
  @property {string} family (string, optional)
  @property {string} name (string, optional)
*/

/**
  @typedef DeviceProfile
  @type {object}
  @property {string} mac (string, optional): MAC Address of the Endpoint
  @property {string} ip (string, optional) IP Address of the Endpoint
  @property {DeviceProfileDhcp} dhcp (object, optional): dhcp information for the Endpoint
  @property {string} hostname (string, optional): Hostname of the Endpoint
  @property {DeviceProfileActiveSync} active_sync (object, optional): Active Sync details of the Endpoint
  @property {DeviceProfileHost} host (object, optional): Host details of the Endpoint
  @property {DeviceProfileSnmp} snmp (object, optional): SNMP details of the Endpoint
  @property {DeviceProfileDevice} device (object, optional): Device details of the Endpoint
*/

/**
* Submit an Endpoint to the profiling system. (Uses Legacy APIs)
* @param {DeviceProfile} endpointInfo The user id.
* @param {doNext} next The callback function
*/
ClearPassApi.prototype.profileEndpoint = function (endpointInfo, next) {
    var self = this;

    if (!endpointInfo) {
        throw new Error('You must enter endpoint information.');
    }

    if (!self.settings.legacyApi) {
        throw new Error('You must configure the legacy api options (legacyApi) to use this method.');
    }

    var rOpts = {
        url: self.getLegacyUrl('/async_netd/deviceprofiler/endpoints'),
        method: 'POST',
        auth: {
            username: self.settings.legacyApi.userName,
            password: self.settings.legacyApi.password
        },
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify((endpointInfo || {}))
    };
    request(rOpts, function (error, response, body) {
        processCppmResponse(error, response, null, function (error, bodyJs) {
            next(error, body);
        });
    });
}

module.exports = ClearPassApi;