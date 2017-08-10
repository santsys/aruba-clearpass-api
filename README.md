# aruba-clearpass-api

[![NPM](https://nodei.co/npm/aruba-clearpass-api.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/aruba-clearpass-api/)

This library is a simple "helper" library for interfacing with the Aruba ClearPass API. It is still very much in development, but updates will come as requested or needed.


## Example

```js
const CppmApi = require('aruba-clearpass-api');

var client = new CppmApi({
    host: '127.0.0.1',
    clientId: 'CPPM-API',
    clientSecret: 'cyvD9...JbAE',
    sslValidation: false
});

// Get a list of devices from CPPM.
var o = {
    filter: {},
    sort: '-id',
    offset: 0,
    limit: 1
};

client.getDevices(o, function (error, data) {
    if (error) {
        console.log(error);
    }
    else {
        console.log(JSON.stringify(data, null, 2));
    }
});
```

---

## Installation

With [npm](https://www.npmjs.com/) do:
```cmd
npm install -g aruba-clearpass-api
```

---

## Supported Methods

## Platform: System Information
#### ClearPassApi.getServerVersion
Gets the server version information.

ClearPassApi.getServerVersion(callback(error, json))

#### ClearPassApi.getFipsStatus
Gets the current FIPS status of the server.

ClearPassApi.getFipsStatus(callback(error, json))

#### ClearPassApi.getServerConfiguration
Gets the servers basic configuration information.

ClearPassApi.getServerConfiguration(callback(error, json))

---

## API Framework: Clients
#### ClearPassApi.getApiClients
Search for API Clients.

ClearPassApi.getApiClients([options](#searchOptions), callback(error, json))

#### ClearPassApi.createApiClient
Create a new API Client.

ClearPassApi.createApiClient([apiClient](#apiClientOptions), callback(error, json))

#### ClearPassApi.getApiClient
Get the details of an API Client.

ClearPassApi.getApiClient(clientId, callback(error, json))

#### ClearPassApi.updateApiClient
Update an API Client.

ClearPassApi.updateApiClient(clientId, [clientOptions](#apiClientOptions), callback(error, json))

#### ClearPassApi.replaceApiClient
Replace an API Client.

ClearPassApi.replaceApiClient(clientId, [clientOptions](#apiClientOptions), callback(error, json))

#### ClearPassApi.deleteApiClient
Delete an API Client.

ClearPassApi.deleteApiClient(clientId, callback(error, json))

---

## Guest Manager: Configuration
#### ClearPassApi.getGuestManagerConfiguration
Get the current Guest Manager configuration.

ClearPassApi.getGuestManagerConfiguration(callback(error, json))

#### ClearPassApi.updateGuestManagerConfiguration
Update the Guest Manager configuration.

ClearPassApi.updateGuestManagerConfiguration([options](#guestManagerConfig), callback(error, json))

---

## Guest Manager: Sessions
#### ClearPassApi.getGuestSessions
Search for guest sessions.

ClearPassApi.getGuestSessions([options](#searchOptions), callback(error, json))

#### ClearPassApi.disconnectSession
Disconnect an active session.

ClearPassApi.disconnectSession(sessionId, callback(error, json))

#### ClearPassApi.getSessionReauthorizationProfiles
Get reauthorization profiles for an active session.

ClearPassApi.getSessionReauthorizationProfiles(sessionId, callback(error, json))

#### ClearPassApi.reauthorizeSession
Force an active session to reauthorize. Optionally specify a reauthorization profile.

ClearPassApi.reauthorizeSession(sessionId, reauthProfile, callback(error, json))

---

## Guest Manager: Devices
#### ClearPassApi.getDevices
Search for device accounts.

ClearPassApi.getDevices([options](#searchOptions), callback(error, json))

#### ClearPassApi.createDevice
Create a device account.

ClearPassApi.createDevice(deviceAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.getDevice
Get a device account by device id.

ClearPassApi.getDevice(deviceId, next)

#### ClearPassApi.updateDevice
Update or add device account attributes using the device id.

ClearPassApi.updateDevice(deviceId, deviceAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.replaceDevice
Replace the attributes of a device account using the device id.

ClearPassApi.replaceDevice(deviceId, deviceAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.deleteDevice
Delete a device account using the device id.

ClearPassApi.deleteDevice(deviceId, doChangeOfAuth, callback(error, json))

#### ClearPassApi.getDeviceByMac
Get a device account by MAC Address.

ClearPassApi.getDeviceByMac(macAddress, callback(error, json))

#### ClearPassApi.updateDeviceByMac
Update or add device account attributes using the MAC Address.

ClearPassApi.updateDeviceByMac(macAddress, deviceAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.replaceDeviceByMac
Replace the attributes of a device account using the MAC Address.

ClearPassApi.replaceDeviceByMac(macAddress, deviceAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.deleteDeviceByMac
Delete a device account using the MAC Address.

ClearPassApi.deleteDeviceByMac(macAddress, doChangeOfAuth, callback(error, json))

---

## Guest Manager: Guests
#### ClearPassApi.getGuests
Search for guest accounts.

ClearPassApi.getGuests([options](#searchOptions), callback(error, json))

#### ClearPassApi.createGuest
Create a new guest account.

ClearPassApi.createGuest(guestAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.getGuest
Get a guest account by guest id.

ClearPassApi.getGuest(guestId, callback(error, json))

#### ClearPassApi.updateGuest
Update a guest account using the guest id.

ClearPassApi.updateGuest(guestId, guestAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.replaceGuest
Replace the attributes of a guest account using the guest id.

ClearPassApi.replaceGuest(guestId, guestAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.deleteGuest
Delete a guest account using the guest id.

ClearPassApi.deleteGuest(guestId, doChangeOfAuth, callback(error, json))

#### ClearPassApi.getGuestByUserName
Get a guest account by user name.

ClearPassApi.getGuestByUserName(userName, callback(error, json))

#### ClearPassApi.updateGuestByUserName
Update a guest account using the user name.

ClearPassApi.updateGuestByUserName(userName, guestAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.replaceGuestByUserName
Replace the attributes of a guest account using the user name.

ClearPassApi.replaceGuestByUserName(userName, guestAttributes, doChangeOfAuth, callback(error, json))

#### ClearPassApi.deleteGuestByUserName
Delete a guest account using the user name.

ClearPassApi.deleteGuestByUserName(userName, doChangeOfAuth, callback(error, json))

---

## Guest Manager: Random Password
#### ClearPassApi.getRandomPassword
Generate a random password.

ClearPassApi.getRandomPassword([options](#randomPasswordOptions), callback(error, json))

---

## Guest Manager: Guest Sponsor
#### ClearPassApi.confirmGuestSponsor
Accept or Reject a guest account that is waiting for sponsor approval.

ClearPassApi.confirmGuestSponsor(guestId, [options](#randomPasswordOptions), callback(error, json))

*Requires a guest self-registration page that has been configured for sponsor confirmation.*

---

## Identity: Endpoints
#### ClearPassApi.getEndpoints
Search for endpoints.

ClearPassApi.getEndpoints([options](#searchOptions), callback(error, json))

#### ClearPassApi.createEndpoint
Create a new endpoint.

ClearPassApi.createEndpoint([endpointAttributes](#endpointObject),  callback(error, json))

#### ClearPassApi.getEndpoint
Get an endpoint by id.

ClearPassApi.getEndpoint(endpointId, callback(error, json))

#### ClearPassApi.updateEndpoint
Update an endpoints attributes by id.

ClearPassApi.updateEndpoint(endpointId, [endpointAttributes](#endpointObject), callback(error, json))

#### ClearPassApi.replaceEndpoint
Replace an endpoint by id.

ClearPassApi.replaceEndpoint(endpointId, [endpointAttributes](#endpointObject), callback(error, json))

#### ClearPassApi.deleteEndpoint
Delete an endpoint by id.

ClearPassApi.deleteEndpoint(endpointId, callback(error, json))

#### ClearPassApi.getEndpointByMac
Get an endpoint by MAC Address.

ClearPassApi.getEndpointByMac(macAddress, callback(error, json))

#### ClearPassApi.updateEndpointByMac
Update an endpoints attributes by MAC Address.

ClearPassApi.updateEndpointByMac(macAddress, [endpointAttributes](#endpointObject), callback(error, json))

#### ClearPassApi.replaceEndpointByMac
Replace an endpoint by MAC Address.

ClearPassApi.replaceEndpointByMac(macAddress, [endpointAttributes](#endpointObject), callback(error, json))

#### ClearPassApi.deleteEndpointByMac
Delete an endpoint by MAC Address.

ClearPassApi.deleteEndpointByMac(macAddress, callback(error, json))

---

## Extensions
#### ClearPassApi.getExtensions
Get a list of installed extensions.

ClearPassApi.getExtensions([options](#searchOptions), callback(error, json))

#### ClearPassApi.installExtension
Install a new extension from the extension store.

ClearPassApi.installExtension([createOptions](#instanceCreate), callback(error, json))

#### ClearPassApi.getExtension
Get information about an installed extension.

ClearPassApi.getExtension(extensionId, callback(error, json))

#### ClearPassApi.updateExtensionState
Update the running state of an extension.

ClearPassApi.updateExtensionState(extensionId, extensionState, callback(error, json))

#### ClearPassApi.deleteExtension
Delete an installed extension.

ClearPassApi.deleteExtension(extensionId, force, callback(error, json))

#### ClearPassApi.getExtensionConfig
Get the configuration of an installed extension.

ClearPassApi.getExtensionConfig(extensionId, next)

#### ClearPassApi.updateExtensionConfig
Update the configuration of an installed extension.

ClearPassApi.updateExtensionConfig(extensionId, config, callback(error, json))

#### ClearPassApi.restartExtension
Restart an installed extension.

ClearPassApi.restartExtension(extensionId, callback(error, json))

#### ClearPassApi.startExtension
Start an installed extension.

ClearPassApi.startExtension(extensionId, callback(error, json))

#### ClearPassApi.stopExtension
Stop an installed extension.

ClearPassApi.stopExtension(extensionId, callback(error, json))

#### ClearPassApi.getExtensionLogs
Get the logs for an installed extension.

ClearPassApi.getExtensionLogs(extensionId, [logOptions](#extensionLogOptions), callback(error, json))

---

## Dictionaries: Attributes
#### ClearPassApi.getAttributes
Search for attributes.

ClearPassApi.getAttributes([options](#searchOptions), callback(error, json))

#### ClearPassApi.createAttribute
Create a new attribute.

ClearPassApi.createAttribute([attribute](#attributeOptions), callback(error, json))

#### ClearPassApi.getAttribute
Get an attribute by id.

ClearPassApi.getAttribute(attributeId, callback(error, json))

#### ClearPassApi.updateAttribute
Update an attributes information.

ClearPassApi.updateAttribute(attributeId, [attribute](#attributeOptions), callback(error, json))

#### ClearPassApi.replaceAttribute
Replace an attribute.

ClearPassApi.replaceAttribute(attributeId, [attribute](#attributeOptions), callback(error, json))

#### ClearPassApi.deleteAttribute
Delete an attribute.

ClearPassApi.deleteAttribute(attributeId, callback(error, json))

#### ClearPassApi.getAttributeByName
Get an attribute by name.

ClearPassApi.getAttributeByName(entityName, attributeName, callback(error, json))

#### ClearPassApi.updateAttributeByName
Update an attribute.

ClearPassApi.updateAttributeByName(entityName, attributeName, [attribute](#attributeOptions), callback(error, json))

#### ClearPassApi.replaceAttributeByName
Replace an attribute.

ClearPassApi.replaceAttributeByName(entityName, attributeName, [attribute](#attributeOptions), callback(error, json))

#### ClearPassApi.deleteAttributeByName
Delete an attribute.

ClearPassApi.deleteAttributeByName(entityName, attributeName, callback(error, json))

---

## Dictionaries: Context Server Actions
#### ClearPassApi.getContextServerActions
Search for context server actions.

ClearPassApi.getContextServerActions([options](#searchOptions), callback(error, json))

#### ClearPassApi.createContextServerAction
Create a new context server action.

ClearPassApi.createContextServerAction([action](#contextServerAction), callback(error, json))

#### ClearPassApi.getContextServerAction
Get a context server action by id.

ClearPassApi.getContextServerAction(csaId, callback(error, json))

#### ClearPassApi.updateContextServerAction
Update a context server action.

ClearPassApi.updateContextServerAction(csaId, [action](#contextServerAction), callback(error, json))

#### ClearPassApi.replaceContextServerAction
Replace a context server action.

ClearPassApi.replaceContextServerAction(csaId, [action](#contextServerAction), callback(error, json))

#### ClearPassApi.deleteContextServerAction
Delete a context server action.

ClearPassApi.deleteContextServerAction(csaId, callback(error, json))

#### ClearPassApi.getContextServerActionByName
Get a context server action by name.

ClearPassApi.getContextServerActionByName(serverType, actionName, callback(error, json))

#### ClearPassApi.updateContextServerActionByName
Update a context server action.

ClearPassApi.updateContextServerActionByName(serverType, actionName, [action](#contextServerAction), callback(error, json))

#### ClearPassApi.replaceContextServerActionByName
Replace a context server action.

ClearPassApi.replaceContextServerActionByName(serverType, actionName, [action](#contextServerAction), callback(error, json))

#### ClearPassApi.deleteContextServerActionByName
Delete a context server action.

ClearPassApi.deleteContextServerActionByName(serverType, actionName, callback(error, json))

---

## Dictionaries: Fingerprint
#### ClearPassApi.getFingerprints
Search for fingerprints.

ClearPassApi.getFingerprints([options](#searchOptions), callback(error, json))

#### ClearPassApi.createFingerprint
Create a new fingerprint.

ClearPassApi.createFingerprint([fingerprint](#fingerprint), callback(error, json))

#### ClearPassApi.getFingerprint
Get a fingerprint by id.

ClearPassApi.getFingerprint(fId, callback(error, json))

#### ClearPassApi.updateFingerprint
Update a fingerprint.

ClearPassApi.updateFingerprint(fId, [fingerprint](#fingerprint), callback(error, json))

#### ClearPassApi.replaceFingerprint
Replace a fingerprint.

ClearPassApi.replaceFingerprint(fId, [fingerprint](#fingerprint), callback(error, json))

#### ClearPassApi.deleteFingerprint
Delete a fingerprint.

ClearPassApi.deleteFingerprint(fId, callback(error, json))

#### ClearPassApi.getFingerprintByName
Get a fingerprint by name.

ClearPassApi.getFingerprintByName(category, family, name, callback(error, json))

#### ClearPassApi.updateFingerprintByName
Update a fingerprint.

ClearPassApi.updateFingerprintByName(category, family, name, [fingerprint](#fingerprint), callback(error, json))

#### ClearPassApi.replaceFingerprintByName
Replace a fingerprint.

ClearPassApi.replaceFingerprintByName(category, family, name, [fingerprint](#fingerprint), callback(error, json))

#### ClearPassApi.deleteFingerprintByName
Delete a fingerprint.

ClearPassApi.deleteFingerprintByName(category, family, name, callback(error, json))

---

## Insights: Endpoint
#### ClearPassApi.getInsightsByMac
Get insights for a specific MAC Address.

ClearPassApi.getInsightsByMac(macAddress, callback(error, json))

#### ClearPassApi.getInsightsByIp
Get insights for a specific IP Address. 

ClearPassApi.getInsightsByIp(ipAddr, callback(error, json))

#### ClearPassApi.getInsightsByIpRange
Get insights by IP Address range. e.g. '192.168.1.1-254', '10.1.1.100-200'

ClearPassApi.getInsightsByIpRange(ipAddrRange, callback(error, json))

#### ClearPassApi.getInsightsByTimeRange
Get insights for a specific time range. Start Time and End Time can be either UNIX timestamp or a javascript Date.

ClearPassApi.getInsightsByTimeRange(startTime, endTime, callback(error, json))

```js
var startTime = new Date();
startTime.setMonth(startTime.getMonth() - 1);
var endTime = new Date();

console.log('Start Time: ' + startTime.toString());
console.log('End Time: ' + endTime.toString());
client.getInsightsByTimeRange(startTime, endTime, function (error, data) {
    if (error) {
        console.log(error);
    }
    else {
        console.log(JSON.stringify(data, null, 2));
    }
});
```

#### ClearPassApi.dateToUnixTimestamp
Convert a date to a UNIX timestamp.

ClearPassApi.dateToUnixTimestamp(date)

---

# Network: Network Device
### ClearPassApi.getNetworkDevices
Search for a network device.

ClearPassApi.getNetworkDevices([options](#searchOptions), callback(error, json))

### ClearPassApi.createNetworkDevice
Create a new network device.

ClearPassApi.createNetworkDevice([device](#networkdevice), callback(error, json))

#### ClearPassApi.getNetworkDevice
Get a network device.

ClearPassApi.getNetworkDevice(deviceId, callback(error, json))

#### ClearPassApi.updateNetworkDevice
Update a network device.

ClearPassApi.updateNetworkDevice(deviceId, [device](#networkdevice), callback(error, json))

#### ClearPassApi.replaceNetworkDevice
Replace a network device.

ClearPassApi.replaceNetworkDevice(deviceId, [device](#networkdevice), callback(error, json))

#### ClearPassApi.deleteNetworkDevice
Delete a network device.

ClearPassApi.deleteNetworkDevice(deviceId, callback(error, json))

#### ClearPassApi.getNetworkDeviceByName
Get a network device.

ClearPassApi.getNetworkDeviceByName(deviceName, callback(error, json))

#### ClearPassApi.updateNetworkDeviceByName
Update a network device.

ClearPassApi.updateNetworkDeviceByName(deviceName, [device](#networkdevice), callback(error, json))

#### ClearPassApi.replaceNetworkDeviceByName
Replace a network device.

ClearPassApi.replaceNetworkDeviceByName(deviceName, [device](#networkdevice), callback(error, json))

#### ClearPassApi.deleteNetworkDeviceByName
Delete a network device.

ClearPassApi.deleteNetworkDeviceByName(deviceName, callback(error, json))

---

## Onboard: Certificates
#### ClearPassApi.getCertificates
Search for installed certificates.

ClearPassApi.getCertificates([options](#searchOptions), callback(error, json))

#### ClearPassApi.getCertificate
Get a certificate.

ClearPassApi.getCertificate(certId, callback(error, json))

#### ClearPassApi.deleteCertificate
Delete a certificate.

ClearPassApi.deleteCertificate(certId, callback(error, json))

#### ClearPassApi.getCertificateTrustChain
Get a certificate and its trust chain.

ClearPassApi.getCertificateTrustChain(certId, callback(error, json))

---

## Onboard: Devices
#### ClearPassApi.getOnboardDevices
Search for onboarded devices.

ClearPassApi.getOnboardDevices([options](#searchOptions), callback(error, json))

#### ClearPassApi.getOnboardDevice
Get an onboarded device.

ClearPassApi.getOnboardDevice(deviceId, callback(error, json))

#### ClearPassApi.updateOnboardDevice
Update an onboarded device.

ClearPassApi.updateOnboardDevice(deviceId, [options](#OnboardDevice), callback(error, json))

#### ClearPassApi.deleteOnboardDevice
Delete an onboarded device.

ClearPassApi.deleteOnboardDevice(deviceId, callback(error, json))

---

## Onboard: Users
#### ClearPassApi.getOnboardUsers
Search for onboarded users.

ClearPassApi.getOnboardUsers([options](#searchOptions), callback(error, json))

#### ClearPassApi.getOnboardUser
Get an onboarded user.

ClearPassApi.getOnboardUser(userId, callback(error, json))

#### ClearPassApi.updateOnboardUser
Update an onboarded user.

ClearPassApi.updateOnboardUser(userId, [options](#OnboardUser), callback(error, json))

#### ClearPassApi.deleteOnboardUser
Delete an onboarded user.

ClearPassApi.deleteOnboardUser(userId, callback(error, json))

---

## Authentication
This system supports OAuth2 authentication, or the supplying of a valid token.

To use standard OAuth2, you must supply a Client Id and Client Secret, if you are just planning to supply a token, all you need to do is pass it in.

```js
// OAuth2
var client = new CppmApi({
    host: '127.0.0.1',
    clientId: 'CPPM-API',
    clientSecret: 'cyvD9...JbAE',
    sslValidation: false
});

// Token Only
var client = new CppmApi({
    host: '127.0.0.1',
    token: '4c85...0fd8',
    sslValidation: false
});
```

---

## Filters
Filters are used in various API calls to limit data, here are the basic information for what is supported.

A filter is specified as a JSON object, where the properties of the object specify the type of query to be performed.

| Description | JSON Filter Syntax |
| ----------- | ------------------ |
| No filter, matches everything | \{\} |
| Field is equal to "value" | \{"fieldName":"value"} or \{"fieldName":\{"$eq":"value"}} |
| Field is one of a list of values | \{"fieldName":["value1", "value2"]} or \{"fieldName":\{"$in":["value1", "value2"]}} |
| Field is not one of a list of values | \{"fieldName":\{"$nin":["value1", "value2"]}} |
| Field contains a substring "value" | \{"fieldName":\{"$contains":"value"}} |
| Field is not equal to "value" | \{"fieldName":\{"$ne":"value"}} |
| Field is greater than "value" | \{"fieldName":\{"$gt":"value"}} |
| Field is greater than or equal to "value" | \{"fieldName":\{"$gte":"value"}} |
| Field is less than "value" | \{"fieldName":\{"$lt":"value"}} |
| Field is less than or equal to "value" | \{"fieldName":\{"$lte":"value"}} |
| Field matches a regular expression (case-sensitive) | \{"fieldName":\{"$regex":"regex"}} |
| Field matches a regular expression (case-insensitive) | \{"fieldName":\{"$regex":"regex", "$options":"i"}} |
| Field exists (does not contain a null value) | \{"fieldName":\{"$exists":true}} |
| Field is NULL | \{"fieldName":\{"$exists":false}} |
| Combining filter expressions with AND | \{"$and":[ filter1, filter2, ... ]} |
| Combining filter expressions with OR | \{"$or":[ filter1, filter2, ... ]} |
| Inverting a filter expression | {"$not":\{ filter \}} |
| Field is greater than or equal to 2 and less than 5 | \{"fieldName":\{"$gte":2, "$lt":5}} or \{"$and":[ \{"fieldName":\{"$gte":2}}, \{"fieldName":\{"$lt":5}} ]} |

**Some Methods that use Filters**
* [ClearPassApi.getGuestSessions](#ClearPassApi.getGuestSessions)
* [ClearPassApi.getDevices](#ClearPassApi.getDevices)
* [ClearPassApi.getGuests](#ClearPassApi.getGuests)
* [ClearPassApi.getEndpoints](#ClearPassApi.getEndpoints)
* [ClearPassApi.getExtensions](#ClearPassApi.getExtensions)
* [ClearPassApi.getAttributes](#ClearPassApi.getAttributes)
* [ClearPassApi.getContextServerActions](#ClearPassApi.getContextServerActions)
* [ClearPassApi.getFingerprints](#ClearPassApi.getFingerprints)
* [ClearPassApi.getNetworkDevices](#ClearPassApi.getNetworkDevices)
* [ClearPassApi.getCertificates](#ClearPassApi.getCertificates)
* [ClearPassApi.getOnboardDevices](#ClearPassApi.getOnboardDevices)
* [ClearPassApi.getOnboardUsers](#ClearPassApi.getOnboardUsers)

**Filter JSON Example**
```js
var fieldEquals = {
    filter: { "id": "3002" }
};

var fieldIsNull = {
    filter: { "acctstoptime": { "$exists": false } }
};

var simpleOr = {
    filter: { '$or': [{ 'username': 'email@address.com' }, {'sponsor_name': 'admin' }] }
}

```

---

# Data Types

## initOptions
| Type | Name | Description |
| ---- | ---- | ----------- |
| string | host | The IP or DNS name of the ClearPass host. |
| string | clientId | The OAuth2 Client Id. |
| string | clientSecret | The OAuthe2 Client Secret. |
| string | token | A valid authentication token. Only used if you do not supply a Client Id and Secret. |
| boolean | sslValidation | Should SSL Validation be used. Set to false for self signed certificates. |

## searchOptions
| Type | Name | Description |
| ---- | ---- | ----------- |
| object / string | filter | The search filter. |
| string | sort | The sort order of the results. |
| number | offset | The number of items to offset the returned results (for paging). |
| number | limit | THe number of items to return (for paging). |

## apiClientOptions
| Type | Name | Description |
| ---- | ---- | ----------- |
| string | [access_lifetime] | (string, optional): Lifetime of an OAuth2 access token |
| string | [access_token_lifetime] | (string): Specify the lifetime of an OAuth2 access token |
| string | access_token_lifetime_units | (string): Specify the lifetime of an OAuth2 access token |
| string | [auto_confirm] | (integer, optional): Not supported at this time |
| string | [client_description] | (string, optional): Use this field to store comments or notes about this API client |
| string | client_id | (string): The unique string identifying this API client. Use this value in the OAuth2 “client_id” parameter |
| string | [client_public] | (boolean, optional): Public clients have no client secret |
| string | [client_refresh] | (boolean, optional): An OAuth2 refresh token may be used to obtain an updated access token. Use grant_type=refresh_token for this |
| string | [client_secret] | (string, optional): Use this value in the OAuth2 "client_secret" parameter. NOTE: This value is encrypted when stored and cannot be retrieved. |
| string | [enabled] | (boolean, optional): Enable API client |
| string | id | (string): The unique string identifying this API client. Use this value in the OAuth2 "client_id" parameter |
| string | grant_types | (string): Only the selected authentication method will be permitted for use with this client ID |
| string | [profile_id] | (integer): The operator profile applies role-based access control to authorized OAuth2 clients. This determines what API objects and methods are available for use |
| string | [profile_name] | (string, optional): Name of operator profile |
| string | [redirect_uri] | (string, optional): Not supported at this time |
| string | [refresh_lifetime] | (string, optional): Lifetime of an OAuth2 refresh token |
| string | refresh_token_lifetime | (string): Specify the lifetime of an OAuth2 refresh token |
| string | [refresh_token_lifetime_units] | (string): Specify the lifetime of an OAuth2 refresh token |
| string | [scope] | (string, optional): Not supported at this time |
| string | [user_id] | (string, optional): Not supported at this time |

## guestManagerConfig
| Type | Name | Description |
| ---- | ---- | ----------- |
| string | random_username_method | (string) = ['nwa_digits_password' or 'nwa_letters_password' or 'nwa_lettersdigits_password' or 'nwa_picture_password' or 'nwa_sequence']: The method used to generate random account usernames |
| string | random_username_multi_prefix | (string, optional): Identifier string to prepend to usernames. Dynamic entries based on a user attribute can be entered as '_' + attribute. For example '_role_name'. The username length will determine the length of the numeric sequence only. Recommend 4 |
| string | random_username_picture | (string, optional): Format picture (see below) describing the usernames that will be created for visitors. • Alphanumeric characters are passed through without modification. • '#' is replaced with a random digit [0-9]. • '$' or '?' is replaced with a random letter [A-Za-z] • '_' is replaced with a random lowercase letter [a-z] • '^' is replaced with a random uppercase letter [A-Z] • '*' is replaced with a random letter or digit [A-Za-z0-9]. • '!' is replaced with a random punctuation symbol [excluding apostrophe, quotes] • '&' is replaced with a random character (union of sets ! and *) • '@' is replaced with a random letter or digit, excluding vowels • '%' is replaced with a random letter or digit, excluding vowels and anything that looks like another (il1, B8, O0, Z2) |
| string | random_username_length | (integer): The length, in characters, of generated account usernames |
| object | guest_initial_sequence_options | (object, optional): Create multi next available sequence number. These values will be used when multi_initial_sequence is set to -1 |
| string | random_password_method | (string) = ['nwa_digits_password' or 'nwa_letters_password' or 'nwa_lettersdigits_password' or 'nwa_alnum_password' or 'nwa_strong_password' or 'nwa_complex_password' or 'nwa_complexity_password' or 'nwa_words_password' or 'nwa_picture_password']: The method used to generate a random account password |
| string | random_password_picture | (string, optional): Format picture (see below) describing the passwords that will be created for visitors. • Alphanumeric characters are passed through without modification. • '#' is replaced with a random digit [0-9]. • '$' or '?' is replaced with a random letter [A-Za-z] • '_' is replaced with a random lowercase letter [a-z] • '^' is replaced with a random uppercase letter [A-Z] • '*' is replaced with a random letter or digit [A-Za-z0-9]. • '!' is replaced with a random punctuation symbol [excluding apostrophe, quotes] • '&' is replaced with a random character (union of sets ! and *) • '@' is replaced with a random letter or digit, excluding vowels • '%' is replaced with a random letter or digit, excluding vowels and anything that looks like another (il1, B8, O0, Z2) |
| number | random_password_length | (integer): Number of characters to include in randomly-generated account passwords |
| string | guest_password_complexity | (string) = ['none' or 'case' or 'number' or 'alphanumeric' or 'casenumeric' or 'punctuation' or 'complex']: Password complexity to enforce for manually-entered guest passwords. Requires the random password type 'A password matching the password complexity requirements' and the field validator 'NwaIsValidPasswordComplexity' for manual password entry |
| string | guest_password_minimum | (integer): The minimum number of characters that a guest password must contain |
| string | guest_password_disallowed | (string, optional): Characters which cannot appear in a user-generated password |
| string | guest_password_disallowed_words | (string, optional): Comma separated list of words disallowed in the random words password generator. Note there is an internal exclusion list built into the server |
| boolean | guest_log_account_password | (boolean, optional): Whether to record passwords for guest accounts in the application log |
| boolean | guest_view_account_password | (boolean, optional): If selected, guest account passwords may be displayed in the list of guest accounts. This is only possible if operators have the View Passwords privilege |
| number | guest_do_expire | (integer) = ['4' or '3' or '2' or '1']: Default action to take when the expire_time is reached. Note that a logout can only occur if the NAS is RFC-3576 compliant |
| object | guest_account_expiry_options | (object): The available options to select from when choosing the expiration time of a guest account (expire_after). Expiration times are specified in hours |
| object | guest_modify_expire_time_options | (object): The available options to select from when modifying an account's expiration (modify_expire_time). Note some items may be dynamically removed based on the state of the account |
| object | guest_lifetime_options | (object): The available options to select from when choosing the lifetime of a guest account (expire_postlogin). Lifetime values are specified in minutes |
| boolean | g_action_notify_account_expire_enabled | (boolean, optional): If checked, users will receive an email notification when their device's network credentials are due to expire |
| number | g_action_notify_account_expiration_duration | (integer, optional): Account expiration emails are sent this many days before the account expires. Enter a value between 1 and 30 |
| string | g_action_notify_account_expire_email_unknown | (string, optional) = ['none' or 'fixed' or 'domain']: Specify where to send emails if the user's account doesn't have an email address recorded |
| string | g_action_notify_account_expire_email_unknown_fixed | (string, optional): Address used when no email address is known for a user |
| string | g_action_notify_account_expire_email_unknown_domain | (string, optional): Domain to append to the username to form an email address |
| string | g_action_notify_account_expire_subject | (string, optional): Enter a subject for the notification email |
| number | g_action_notify_account_expire_message | (integer, optional) = ['2' or '11' or '5' or '6' or '1' or '3' or '7' or '8' or '10' or '9' or '4']: The plain text or HTML print template to use when generating an email message |
| string | g_action_notify_account_expire_skin | (string, optional) = ['' or 'plaintext' or 'html_embedded' or 'receipt' or 'default' or 'Aruba Amigopod Skin' or 'Blank Skin' or 'ClearPass Guest Skin' or 'Custom Skin 1' or 'Custom Skin 2' or 'Galleria Skin' or 'Galleria Skin 2']: The format in which to send email receipts |
| string | g_action_notify_account_expire_copies | (string, optional) = ['never' or 'always_cc' or 'always_bcc']: Specify when to send to the recipients in the Copies To list |
| string | g_action_notify_account_expire_copies_to | (string, optional): An optional list of email addresses to which copies of expiry notifications will be sent |
| string | site_ssid | (string, optional): The SSID of the wireless LAN, if applicable. This will appear on guest account print receipts |
| string | site_wpa_key | (string, optional): The WPA key for the wireless LAN, if applicable. This will appear on guest account print receipts |
| boolean | guest_receipt_print_button | (boolean, optional): Guest receipts can print simply by selecting the template in the dropdown, or by clicking a link |
| string | guest_account_terms_of_use_url | (string, optional): The URL of a terms and conditions page. The URL will appear in any terms checkbox with: {nwa_global name=guest_account_terms_of_use_url} It is recommended to upload your terms in Content Manager, where the files will be referenced with the "public/" prefix. Alternatively, you can edit Terms and Conditions under Configuration > Pages > Web Pages. If your site is hosted externally, be sure the proper access control lists (ACLs) are in place. If terms are not required, it is recommended to edit the terms field on your forms to a UI type "hidden" and an Initial Value of 1 |
| number | guest_active_sessions | (integer, optional): Enable limiting the number of active sessions a guest account may have. Enter 0 to allow an unlimited number of sessions |
| string | guest_about_guest_network_access | (string, optional): Template code to display on the Guest Manager start page, under the “About Guest Network Access” heading. Leave blank to use the default text, or enter a hyphen ("-") to remove the default text and the heading |

## guestSponsorResponse
| Type | Name | Description |
| ---- | ---- | ----------- |
| string | token | (string): Registration token |
| string | register_token | (string): Registration token |
| boolean | [register_reject] | (boolean, optional): Set to true to reject the sponsorship request |
| number | [role_id] | (integer, optional): Override the guest role |
| string | [modify_expire_time] | (string, optional): Override the guest expiration time |
| string | [confirm_expire_time] | (string, optional): Timestamp for new expiration time; used if modify_expire_time is "expire_time" |

## randomPasswordOptions
| Type | Name | Description |
| ---- | ---- | ----------- |
| string | [random_password_method] | The random password method to use. |
| number | [random_password_length] | The length of the password to be created. |
| string | [random_password_picture] | The picture to be used for the nwa_picture_password method. |

## endpointObject
| Type | Name | Description |
| ---- | ---- | ----------- |
| number | [id] | The endpoint id. |
| string | [mac_address] | The endpoints MAC Address. |
| string | [description] | A description of the endpoint. |
| string | [status] | The endpoint status (Known, Unknown, Disabled). |
| object | [attributes] | Additional endpoint attributes. |

## instanceCreate
| Type | Name | Description |
| ---- | ---- | ----------- |
| string | [state] | (string, optional) = ['stopped' or 'running']: Desired state of the extension |
| string | store_id | (string): ID from the extension store |
| string | [files] | (object, optional): Maps extension file IDs to local content items, with "public:" or "private:" prefix |

## extensionLogOptions
| Type | Name | Description |
| ---- | ---- | ----------- |
| boolean | stdout | Include extension's standard-output messages |
| boolean | stderr | Include extension's standard-error messages |
| number | since | Specify a UNIX timestamp to only return log entries since that time |
| boolean | timestamps | Prefix every log line with its UTC timestamp |
| string | tail | Return this number of lines at the end of the logs, or "all" for everything |

## attributeOptions
| Type | Name | Description |
| ---- | ---- | ----------- |
| number | id | (integer, optional): Numeric ID of the attribute |
| string | [name] | (string, optional): Name of the attribute |
| string | [entity_name] | (string, optional) = ['Device' or 'LocalUser' or 'GuestUser' or 'Endpoint' or 'Onboard']: Entity Name of the attribute |
| string | [data_type] | (string, optional) = ['Boolean' or 'Date' or 'Date-Time' or 'Day' or 'IPv4Address' or 'Integer' or 'List' or 'MACAddress' or 'String' or 'Text' or 'TimeOfDay']: Data Type of the attribute |
| boolean | [mandatory] | (boolean, optional): Enable this to make this attribute mandatory for the entity  |
| string | [default_value] | (string, optional): Default Value of the attribute |
| boolean | [allow_multiple] | (boolean, optional): To Allow Multiple values of the atribute for Data Type String |
| string | [allowed_value] | (string, optional): Allowed Value for Data Type List (e.g., example1,example2,example3) |

## contextServerAction
| Type | Name | Description |
| ---- | ---- | ----------- |
| number | id | (integer, optional): Numeric ID of the Context Server Action |
| string | [server_type] | (string, optional) = ['Aruba Activate' or 'airwatch' or 'JAMF' or 'MobileIron' or 'MaaS360' or 'SAP Afaria' or 'SOTI' or 'Google Admin Console' or 'Palo Alto Networks Panorama' or 'Palo Alto Networks Firewall' or 'Juniper Networks SRX' or 'XenMobile' or 'Generic HTTP' or 'AirWave' or 'ClearPass Cloud Proxy']: Server Type of the Context Server Action |
| string | [server_name] | (string, optional): Server Name of the Context Server Action |
| string | [action_name] | (string, optional): Action Name of the Context Server Action |
| string | [description] | (string, optional): Description of the Context Server Action |
| string | [http_method] | (string, optional) = ['GET' or 'POST' or 'PUT' or 'DELETE']: Http method of the Context Server Action |
| boolean | [skip_http_auth] | (boolean, optional): Enable to skip HTTP Basic Authentication |
| string | [url] | (string, optional): URL of the Context Server Action |
| string | [content_type] | (string, optional) = ['HTML' or 'JSON' or 'PLANE' or 'XML']: Content-Type of the Context Server Action. Note : For CUSTOM type use any string |
| string | [content] | (string, optional): Content of the Context Server Action |
| object | [headers] | (object, optional): Headers(key/value pairs) of the Context Server Action (e.g., [{"attr_name":"key1","attr_value":"value1"},{"attr_name":"key2","attr_value":"value2"}]) |
| object | [attributes] | (object, optional): Attributes(key/value pairs) of the Context Server Action (e.g., [{"attr_name":"key1","attr_value":"value1"},{"attr_name":"key2","attr_value":"value2"}]) |

## fingerprint
| Type | Name | Description |
| ---- | ---- | ----------- |
| number | id | (integer, optional): Id of the fingerprint |
| string | [category] | (string, optional): Category name of the fingerprint |
| string | [family] | (string, optional): Family name of the fingerprint |
| string | [name] | (string, optional): Unique name of the fingerprint |

## SNMPReadSettings
| Type | Name | Description |
| ---- | ---- | ----------- |
| boolean | force_read | (boolean, optional): Enable to always read information from this device |
| boolean | read_arp_info | (boolean, optional): Enable to read ARP table from this device |
| string | zone_name | (string, optional): Policy Manager Zone name to be associated with the network device |
| string | snmp_version | (string, optional) = ['V1' or 'V2C' or 'V3']: SNMP version of the network device |
| string | community_string | (string, optional): Community string of the network device |
| string | security_level | (string, optional) = ['NOAUTH_NOPRIV' or 'AUTH_NOPRIV' or 'AUTH_PRIV']: Security level of the network device |
| string | user | (string, optional): Username of the network device |
| string | auth_protocol | (string, optional) = ['MD5' or 'SHA']: Authentication protocol of the network device |
| string | auth_key | (string, optional): Authentication key of the network device |
| string | privacy_protocol | (string, optional) = ['DES_CBC' or 'AES_128']: Privacy protocol of the network device |
| string | privacy_key | (string, optional): Privacy key of the network device |

## SNMPWriteSettings
| Type | Name | Description |
| ---- | ---- | ----------- |
| number | default_vlan | (integer, optional): Default VLAN for port when SNMP-enforced session expires |
| string | snmp_version | (string, optional) = ['V1' or 'V2C' or 'V3']: SNMP version of the network device |
| string | community_string | (string, optional): Community string of the network device |
| string | security_level | (string, optional) = ['NOAUTH_NOPRIV' or 'AUTH_NOPRIV' or 'AUTH_PRIV']: Security level of the network device |
| string | user | (string, optional): Username of the network device |
| string | auth_protocol | (string, optional) = ['MD5' or 'SHA']: Authentication protocol of the network device |
| string | auth_key | (string, optional): Authentication key of the network device |
| string | privacy_protocol | (string, optional) = ['DES_CBC' or 'AES_128']: Privacy protocol of the network device |
| string | privacy_key | (string, optional): Privacy key of the network device |

## CLISettings
| Type | Name | Description |
| ---- | ---- | ----------- |
| string | type | (string, optional) = ['SSH' or 'Telnet']: Access type of the network device |
| number | port | (integer, optional): SSH/Telnet port number of the network device |
| string | username | (string, optional): Username of the network device |
| string | password | (string, optional): Password of the network device |
| string | username_prompt_regex | (string, optional): Username prompt regex of the network device |
| string | password_prompt_regex | (string, optional): Password prompt regex of the network device |
| string | command_prompt_regex | (string, optional): Command prompt regex of the network device |
| string | enable_prompt_regex | (string, optional): Enable prompt regex of the network device |
| string | enable_password | (string, optional): Enable password of the network device |

## OnConnectEnforcementSettings
| Type | Name | Description |
| ---- | ---- | ----------- |
| boolean | enabled | (boolean, optional): Flag indicating if the network device is enabled with OnConnect Enforcement. SNMP read configuration and Policy Manager Zone is a must for this to work. |
| string | ports | (string, optional): Port names used in OnConnect Enforcement in CSV format (e.g.,FastEthernet 1/0/10).Use empty string to enable for all ports. Ports determined to be uplink or trunk ports will be ignored. |

## NetworkDevice
| Type | Name | Description |
| ---- | ---- | ----------- |
| number | id | (integer, optional): Numeric ID of the network device |
| string | description | (string, optional): Description of the network device |
| string | name | (string, optional): Name of the network device |
| string | ip_address | (string, optional): IP or Subnet Address of the network device |
| string | radius_secret | (string, optional): RADIUS Shared Secret of the network device |
| string | tacacs_secret | (string, optional): TACACS+ Shared Secret of the network device |
| string | vendor_name | (string, optional): Vendor Name of the network device |
| boolean | coa_capable | (boolean, optional): Flag indicating if the network device is capable of CoA |
| number | coa_port | (integer, optional): CoA port number of the network device  |
| [SNMPReadSettings](#SNMPReadSettings) | snmp_read | (SNMPReadSettings, optional): SNMP read settings of the network device |
| [SNMPWriteSettings](#SNMPWriteSettings) | snmp_write | (SNMPWriteSettings, optional): SNMP write settings of the network device |
| [CLISettings](#CLISettings) | cli_config | (CLISettings, optional): CLI Configuration details of the network device |
| [OnConnectEnforcementSettings](#OnConnectEnforcementSettings) | onConnect_enforcement | (OnConnectEnforcementSettings, optional): OnConnect Enforcement settings of the network device |
| string | attributes | (object, optional): Additional attributes(key/value pairs) may be stored with the network device |

## OnboardDevice
| Type | Name | Description |
| ---- | ---- | ----------- |
| number | id | (integer, optional): Numeric ID of the device |
| string | status | (string, optional) = ['allowed' or 'pending' or 'denied']: Determines whether the device is able to enroll and access the network |
| string | device_type | (string, optional) = ['Other' or 'Android' or 'iOS' or 'OS X' or 'Windows' or 'Ubuntu' or 'Chromebook' or 'Web' or 'External']: Device type |
| string | device_name | (string, optional): Device name |
| string | device_udid | (string, optional): Unique device identifier |
| string | device_imei | (string, optional): International Mobile Station Equipment Identity, if available |
| string | device_iccid | (string, optional): SIM card unique serial number, if available |
| string | device_serial | (string, optional): Serial number of the device, if available |
| string | product_name | (string, optional): Product name of the device, if available |
| string | product_version | (string, optional): Product version string of the device, if available |
| string[] | mac_address | (array[string], optional): List of MAC addresses associated with the device |
| string | serial_number | (string, optional): Serial number of device certificate, if device type is "External" |
| string | usernames | (string, optional): Usernames that have enrolled this device |
| boolean | enrolled | (boolean, optional): Flag indicating device has been provisioned and currently has a valid certificate |
| string | expanded_type | (string, optional): Marketing name for the product |
| string | mdm_managed | (string, optional): Mobile device management (MDM) vendor name, if an endpoint context server reports the device as managed |
| string | device_identifier | (string, optional): Unique identifier string |

## OnboardUser
| Type | Name | Description |
| ---- | ---- | ----------- |
| number | id | (integer, optional): Numeric ID of the user |
| string | status | (string, optional) = ['allowed' or 'denied']: Determines whether the user can enroll devices |
| string | username | (string, optional): Username of the user |
| number | device_count | (undefined, optional): Number of devices enrolled by this user |



---
# Samples 

### Get ClearPass Version Information

```js
var client = new CppmApi({
    host: '127.0.0.1',
    clientId: 'CPPM-API',
    clientSecret: 'cyvD9...JbAE',
    sslValidation: false
});

client.getServerVersion(function (error, data) {
    if (error) {
        console.log(error);
    }
    else {
        console.log(JSON.stringify(data, null, 2));
    }
});
```

**Response**
```json
{
  "cppm_version": "6.6.5.93247",
  "guest_version": "6.6.5.33851",
  "installed_patches": [
    {
      "name": "20160415-vulnerability-fixes",
      "description": "ClearPass patch to fix Samba vulnerability CVE-2016-2118",
      "installed": "2016-05-12T13:24:33+00:00"
    },
    ...
  ]
}
```

### Get and Disconnect an Active Session

```js
var client = new CppmApi({
    host: '127.0.0.1',
    clientId: 'CPPM-API',
    clientSecret: 'cyvD9...JbAE',
    sslValidation: false
});

var o = {
    filter: { "acctstoptime": { "$exists": false } },
    sort: '-id',
    offset: 0,
    limit: 1
};

client.getGuestSessions(o, function (error, data) {
    if (error) {
        console.log(error);
    }
    else {
        console.log(JSON.stringify(data, null, 2));

        if (data.items && data.items.length > 0) {
            var sessionId = data.items[0].id;

            console.log('Attempting to disconnect session "' + sessionId + '".');

            client.disconnectSession(sessionId, function (error, resp) {
                if (error) {
                    console.log(error);
                }
                else {
                    console.log(JSON.stringify(resp, null, 2));
                }
            });
        }
    }
});
```

### Get Information About an Installed Extension

```js
var client = new CppmApi({
    host: '127.0.0.1',
    clientId: 'CPPM-API',
    clientSecret: 'cyvD9...JbAE',
    sslValidation: false
});

client.getExtension('5b8f5597-0dac-4b44-b97e-f2cbf684e705', function (error, data) {
    if (error) {
        console.log(error);
    }
    else {
        console.log(JSON.stringify(data, null, 2));
    }
});
```

**Response**
```json
{
  "id": "5b8f5597-0dac-4b44-b97e-f2cbf684e705",
  "state": "running",
  "state_details": "Started 10 days ago",
  "store_id": "0c1b...d4e",
  "name": "auth-proxy",
  "version": "1.0.0",
  "description": "Generic Auth Proxy (OAuth2, JWT)",
  "icon_href": "...",
  "hostname": "6586daf514c7",
  "network_ports": [],
  "extension_hrefs": [],
  "files": [],
  "internal_ip_address": "172.17.0.2"
}
```