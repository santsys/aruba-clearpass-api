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

#### ClearPassApi.getFipsStatus
Gets the current FIPS status of the server.

#### ClearPassApi.getServerConfiguration
Gets the servers basic configuration information.

---

## API Framework: Clients
#### ClearPassApi.getApiClients
Search for API Clients.

#### ClearPassApi.createApiClient
Create a new API Client.

#### ClearPassApi.getApiClient
Get the details of an API Client.

#### ClearPassApi.updateApiClient
Update an API Client.

#### ClearPassApi.replaceApiClient
Replace an API Client.

#### ClearPassApi.deleteApiClient
Delete an API Client.

---

## Guest Manager: Configuration
#### ClearPassApi.getGuestManagerConfiguration
Get the current Guest Manager configuration.

#### ClearPassApi.updateGuestManagerConfiguration
Update the Guest Manager configuration.

---

## Guest Manager: Sessions
#### ClearPassApi.getGuestSessions
Search for guest sessions.

#### ClearPassApi.disconnectSession
Disconnect an active session.

#### ClearPassApi.getSessionReauthorizationProfiles
Get reauthorization profiles for an active session.

#### ClearPassApi.reauthorizeSession
Force an active session to reauthorize. Optionally specify a reauthorization profile.

---

## Guest Manager: Devices
#### ClearPassApi.getDevices
Search for device accounts.

#### ClearPassApi.createDevice
Create a device account.

#### ClearPassApi.getDevice
Get a device account by device id.

#### ClearPassApi.updateDevice
Update or add device account attributes using the device id.

#### ClearPassApi.replaceDevice
Replace the attributes of a device account using the device id.

#### ClearPassApi.deleteDevice
Delete a device account using the device id.

#### ClearPassApi.getDeviceByMac
Get a device account by MAC Address.

#### ClearPassApi.updateDeviceByMac
Update or add device account attributes using the MAC Address.

#### ClearPassApi.replaceDeviceByMac
Replace the attributes of a device account using the MAC Address.

#### ClearPassApi.deleteDeviceByMac
Delete a device account using the MAC Address.

---

## Guest Manager: Guests
#### ClearPassApi.getGuests
Search for guest accounts.

#### ClearPassApi.createGuest
Create a new guest account.

#### ClearPassApi.getGuest
Get a guest account by guest id.

#### ClearPassApi.updateGuest
Update a guest account using the guest id.

#### ClearPassApi.replaceGuest
Replace the attributes of a guest account using the guest id.

#### ClearPassApi.deleteGuest
Delete a guest account using the guest id.

#### ClearPassApi.getGuestByUserName
Get a guest account by user name.

#### ClearPassApi.updateGuestByUserName
Update a guest account using the user name.

#### ClearPassApi.replaceGuestByUserName
Replace the attributes of a guest account using the user name.

#### ClearPassApi.deleteGuestByUserName
Delete a guest account using the user name.

---

## Guest Manager: Random Password
#### ClearPassApi.getRandomPassword
Generate a random password.

---

## Guest Manager: Guest Sponsor
#### ClearPassApi.confirmGuestSponsor
Accept or Reject a guest account that is waiting for sponsor approval.

*Requires a guest self-registration page that has been configured for sponsor confirmation.*

---

## Identity: Endpoints
#### ClearPassApi.getEndpoints
Search for endpoints.

#### ClearPassApi.createEndpoint
Create a new endpoint.

#### ClearPassApi.getEndpoint
Get an endpoint by id.

#### ClearPassApi.updateEndpoint
Update an endpoints attributes by id.

#### ClearPassApi.replaceEndpoint
Replace an endpoint by id.

#### ClearPassApi.deleteEndpoint
Delete an endpoint by id.

#### ClearPassApi.getEndpointByMac
Get an endpoint by MAC Address.

#### ClearPassApi.updateEndpointByMac
Update an endpoints attributes by MAC Address.

#### ClearPassApi.replaceEndpointByMac
Replace an endpoint by MAC Address.

#### ClearPassApi.deleteEndpointByMac
Delete an endpoint by MAC Address.

---

## Extensions
#### ClearPassApi.getExtensions
Get a list of installed extensions.

#### ClearPassApi.installExtension
Install a new extension from the extension store.

#### ClearPassApi.getExtension
Get information about an installed extension.

#### ClearPassApi.updateExtensionState
Update the running state of an extension.

#### ClearPassApi.deleteExtension
Delete an installed extension.

#### ClearPassApi.getExtensionConfig
Get the configuration of an installed extension.

#### ClearPassApi.updateExtensionConfig
Update the configuration of an installed extension.

#### ClearPassApi.restartExtension
Restart an installed extension.

#### ClearPassApi.startExtension
Start an installed extension.

#### ClearPassApi.stopExtension
Stop an installed extension.

#### ClearPassApi.getExtensionLogs
Get the logs for an installed extension.

---

## Dictionaries: Attributes
#### ClearPassApi.getAttributes
Search for attributes.

#### ClearPassApi.createAttribute
Create a new attribute.

#### ClearPassApi.getAttribute
Get an attribute by id.

#### ClearPassApi.updateAttribute
Update an attributes information.

#### ClearPassApi.replaceAttribute
Replace an attribute.

#### ClearPassApi.deleteAttribute
Delete an attribute.

#### ClearPassApi.getAttributeByName
Get an attribute by name.

#### ClearPassApi.updateAttributeByName
Update an attribute.

#### ClearPassApi.replaceAttributeByName
Replace an attribute.

#### ClearPassApi.deleteAttributeByName
Delete an attribute.

---

## Dictionaries: Context Server Actions
#### ClearPassApi.getContextServerActions
Search for context server actions.

#### ClearPassApi.createContextServerAction
Create a new context server action.

#### ClearPassApi.getContextServerAction
Get a context server action by id.

#### ClearPassApi.updateContextServerAction
Update a context server action.

#### ClearPassApi.replaceContextServerAction
Replace a context server action.

#### ClearPassApi.deleteContextServerAction
Delete a context server action.

#### ClearPassApi.getContextServerActionByName
Get a context server action by name.

#### ClearPassApi.updateContextServerActionByName
Update a context server action.

#### ClearPassApi.replaceContextServerActionByName
Replace a context server action.

#### ClearPassApi.deleteContextServerActionByName
Delete a context server action.

---

## Dictionaries: Fingerprint
#### ClearPassApi.getFingerprints
Search for fingerprints.

#### ClearPassApi.createFingerprint
Create a new fingerprint.

#### ClearPassApi.getFingerprint
Get a fingerprint by id.

#### ClearPassApi.updateFingerprint
Update a fingerprint.

#### ClearPassApi.replaceFingerprint
Replace a fingerprint.

#### ClearPassApi.deleteFingerprint
Delete a fingerprint.

#### ClearPassApi.getFingerprintByName
Get a fingerprint by name.

#### ClearPassApi.updateFingerprintByName
Update a fingerprint.

#### ClearPassApi.replaceFingerprintByName
Replace a fingerprint.

#### ClearPassApi.deleteFingerprintByName
Delete a fingerprint.

---

## Insights: Endpoint
#### ClearPassApi.getInsightsByMac
Get insights for a specific MAC Address.

#### ClearPassApi.getInsightsByIp
Get insights for a specific IP Address. 

#### ClearPassApi.getInsightsByIpRange
Get insights by IP Address range. e.g. '192.168.1.1-254', '10.1.1.100-200'

#### ClearPassApi.getInsightsByTimeRange
Get insights for a specific time range. Start Time and End Time can be either UNIX timestamp or a javascript Date.

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

---

## Network: Network Device
#### ClearPassApi.getNetworkDevices
Search for a network device.

#### ClearPassApi.createNetworkDevice
Create a new network device.

#### ClearPassApi.getNetworkDevice
Get a network device.

#### ClearPassApi.updateNetworkDevice
Update a network device.

#### ClearPassApi.replaceNetworkDevice
Replace a network device.

#### ClearPassApi.deleteNetworkDevice
Delete a network device.

#### ClearPassApi.getNetworkDeviceByName
Get a network device.

#### ClearPassApi.updateNetworkDeviceByName
Update a network device.

#### ClearPassApi.replaceNetworkDeviceByName
Replace a network device.

#### ClearPassApi.deleteNetworkDeviceByName
Delete a network device.

---

## Onboard: Certificates
#### ClearPassApi.getCertificates
Search for installed certificates.

#### ClearPassApi.getCertificate
Get a certificate.

#### ClearPassApi.deleteCertificate
Delete a certificate.

#### ClearPassApi.getCertificateTrustChain
Get a certificate and its trust chain.

---

## Onboard: Devices
#### ClearPassApi.getOnboardDevices
Search for onboarded devices.

#### ClearPassApi.getOnboardDevice
Get an onboarded device.

#### ClearPassApi.updateOnboardDevice
Update an onboarded device.

#### ClearPassApi.deleteOnboardDevice
Delete an onboarded device.

---

## Onboard: Users
#### ClearPassApi.getOnboardUsers
Search for onboarded users.

#### ClearPassApi.getOnboardUser
Get an onboarded user.

#### ClearPassApi.updateOnboardUser
Update an onboarded user.

#### ClearPassApi.deleteOnboardUser
Delete an onboarded user.

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