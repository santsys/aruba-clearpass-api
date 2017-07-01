'use strict';

const request = require('request');
const URL = require('url');

/**
* @callback doNext
* @param {error} error - If there is an error, it is returned here.
* @param {object} body - An object containing the requested information.
*/

/**
 @typedef initOptions
 @type {Object}
 @property {string} host The IP or DNS name of the ClearPass host.
 @property {string} clientId The OAuth2 Client Id.
 @property {string} clientSecret The OAuthe2 Client Secret.
 @property {string} token A valid authentication token. Only used if you do not supply a Client Id and Secret.
 @property {boolean} sslValidation Should SSL Validation be used. Set to false for self signed certificates.
 */

/**
 @typedef searchOptions
 @type {Object}
 @property {Object|string} filter The search filter.
 @property {string} sort The sort order of the results.
 @property {number} offset The number of items to offset the returned results (for paging).
 @property {number} limit THe number of items to return (for paging).
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

                // mov '_embeded' items to root
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

ClearPassApi.prototype.getUrl = function (endpoint) {
    var self = this;

    if (endpoint) {
        if (!endpoint.startsWith('/')) {
            endpoint = '/' + endpoint;
        }
    }

    var cppmUrl = URL.resolve('https://' + self.settings.host, '/api' + endpoint);
    return cppmUrl;
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
Sessions
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
Device
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
Device By Mac
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
Guest
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
Random Password
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
Endpoints
****************************************************************************************/
/**
  @typedef endpointObject
  @type {object}
  @property {number} [id] The endpoint id.
  @property {string} [mac_address] The endpoints MAC Address.
  @property {string} [description] A description of the endpoint.
  @property {string} [status] The endpoint status (Known, Unknown, Disabled).
  @property {Obect} [attributes] Additional endpoint attributes.
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

module.exports = ClearPassApi;