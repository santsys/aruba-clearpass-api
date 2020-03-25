'use strict';

const axios = require('axios');
const https = require('https');
const EventEmitter = require('events');

/**
* @callback doNext
* @param {error} error - If there is an error, it is returned here.
* @param {object} body - An object containing the requested information.
* @param {number} statusCode - The response status code
*/

/**
* @callback tokenNext
* @param {error} error - If there is an error, it is returned here.
* @param {string} token - The token to use for API calls.
*/

/**
* @typedef legacyInitOptions
* @type {Object}
* @property {string} userName ClearPass User Name for API access.
* @property {string} password ClearPass Password for API access.
*/

/**
* @typedef initOptions
* @type {Object}
* @property {string} host The IP or DNS name of the ClearPass host.
* @property {string} clientId The OAuth2 Client Id.
* @property {string} clientSecret The OAuthe2 Client Secret.
* @property {string} token A valid authentication token. Only used if you do not supply a Client Id and Secret.
* @property {boolean} sslValidation Should SSL Validation be used. Set to false for self signed certificates.
* @property {legacyInitOptions} legacyApi Options specific for legacy APIs. (not needed for basic REST processes)
*/

/**
* @typedef searchOptions
* @type {Object}
* @property {Object|string} filter The search filter.
* @property {string} sort The sort order of the results.
* @property {number} offset The number of items to offset the returned results (for paging).
* @property {number} limit The number of items to return (for paging).
*/

/**
* @typedef apiClientOptions
* @type {Object}
* @property {string} [access_lifetime] (string, optional): Lifetime of an OAuth2 access token,
* @property {string} [access_token_lifetime] (string): Specify the lifetime of an OAuth2 access token,
* @property {string} access_token_lifetime_units (string): Specify the lifetime of an OAuth2 access token,
* @property {string} [auto_confirm] (integer, optional): Not supported at this time,
* @property {string} [client_description] (string, optional): Use this field to store comments or notes about this API client,
* @property {string} client_id (string): The unique string identifying this API client. Use this value in the OAuth2 “client_id” parameter,
* @property {string} [client_public] (boolean, optional): Public clients have no client secret,
* @property {string} [client_refresh] (boolean, optional): An OAuth2 refresh token may be used to obtain an updated access token. Use grant_type=refresh_token for this,
* @property {string} [client_secret] (string, optional): Use this value in the OAuth2 "client_secret" parameter. NOTE: This value is encrypted when stored and cannot be retrieved.,
* @property {string} [enabled] (boolean, optional): Enable API client,
* @property {string} id (string): The unique string identifying this API client. Use this value in the OAuth2 "client_id" parameter,
* @property {string} grant_types (string): Only the selected authentication method will be permitted for use with this client ID,
* @property {string} [profile_id] (integer): The operator profile applies role-based access control to authorized OAuth2 clients. This determines what API objects and methods are available for use,
* @property {string} [profile_name] (string, optional): Name of operator profile,
* @property {string} [redirect_uri] (string, optional): Not supported at this time,
* @property {string} [refresh_lifetime] (string, optional): Lifetime of an OAuth2 refresh token,
* @property {string} refresh_token_lifetime (string): Specify the lifetime of an OAuth2 refresh token,
* @property {string} [refresh_token_lifetime_units] (string): Specify the lifetime of an OAuth2 refresh token,
* @property {string} [scope] (string, optional): Not supported at this time,
* @property {string} [user_id] (string, optional): Not supported at this time
*/

/**
* @typedef guestManagerConfig
* @type {Object}
* @property {string} random_username_method (string) = ['nwa_digits_password' or 'nwa_letters_password' or 'nwa_lettersdigits_password' or 'nwa_picture_password' or 'nwa_sequence']: The method used to generate random account usernames,
* @property {string} random_username_multi_prefix (string, optional): Identifier string to prepend to usernames. Dynamic entries based on a user attribute can be entered as '_' + attribute. For example '_role_name'. The username length will determine the length of the numeric sequence only. Recommend 4,
* @property {string} random_username_picture (string, optional): Format picture (see below) describing the usernames that will be created for visitors. • Alphanumeric characters are passed through without modification. • '#' is replaced with a random digit [0-9]. • '$' or '?' is replaced with a random letter [A-Za-z] • '_' is replaced with a random lowercase letter [a-z] • '^' is replaced with a random uppercase letter [A-Z] • '*' is replaced with a random letter or digit [A-Za-z0-9]. • '!' is replaced with a random punctuation symbol [excluding apostrophe, quotes] • '&' is replaced with a random character (union of sets ! and *) • '@' is replaced with a random letter or digit, excluding vowels • '%' is replaced with a random letter or digit, excluding vowels and anything that looks like another (il1, B8, O0, Z2),
* @property {string} random_username_length (integer): The length, in characters, of generated account usernames,
* @property {object} guest_initial_sequence_options (object, optional): Create multi next available sequence number. These values will be used when multi_initial_sequence is set to -1,
* @property {string} random_password_method (string) = ['nwa_digits_password' or 'nwa_letters_password' or 'nwa_lettersdigits_password' or 'nwa_alnum_password' or 'nwa_strong_password' or 'nwa_complex_password' or 'nwa_complexity_password' or 'nwa_words_password' or 'nwa_picture_password']: The method used to generate a random account password,
* @property {string} random_password_picture (string, optional): Format picture (see below) describing the passwords that will be created for visitors. • Alphanumeric characters are passed through without modification. • '#' is replaced with a random digit [0-9]. • '$' or '?' is replaced with a random letter [A-Za-z] • '_' is replaced with a random lowercase letter [a-z] • '^' is replaced with a random uppercase letter [A-Z] • '*' is replaced with a random letter or digit [A-Za-z0-9]. • '!' is replaced with a random punctuation symbol [excluding apostrophe, quotes] • '&' is replaced with a random character (union of sets ! and *) • '@' is replaced with a random letter or digit, excluding vowels • '%' is replaced with a random letter or digit, excluding vowels and anything that looks like another (il1, B8, O0, Z2),
* @property {number} random_password_length (integer): Number of characters to include in randomly-generated account passwords,
* @property {string} guest_password_complexity (string) = ['none' or 'case' or 'number' or 'alphanumeric' or 'casenumeric' or 'punctuation' or 'complex']: Password complexity to enforce for manually-entered guest passwords. Requires the random password type 'A password matching the password complexity requirements' and the field validator 'NwaIsValidPasswordComplexity' for manual password entry,
* @property {string} guest_password_minimum (integer): The minimum number of characters that a guest password must contain,
* @property {string} guest_password_disallowed (string, optional): Characters which cannot appear in a user-generated password,
* @property {string} guest_password_disallowed_words (string, optional): Comma separated list of words disallowed in the random words password generator. Note there is an internal exclusion list built into the server,
* @property {boolean} guest_log_account_password (boolean, optional): Whether to record passwords for guest accounts in the application log,
* @property {boolean} guest_view_account_password (boolean, optional): If selected, guest account passwords may be displayed in the list of guest accounts. This is only possible if operators have the View Passwords privilege,
* @property {number} guest_do_expire (integer) = ['4' or '3' or '2' or '1']: Default action to take when the expire_time is reached. Note that a logout can only occur if the NAS is RFC-3576 compliant,
* @property {object} guest_account_expiry_options (object): The available options to select from when choosing the expiration time of a guest account (expire_after). Expiration times are specified in hours,
* @property {object} guest_modify_expire_time_options (object): The available options to select from when modifying an account's expiration (modify_expire_time). Note some items may be dynamically removed based on the state of the account,
* @property {object} guest_lifetime_options (object): The available options to select from when choosing the lifetime of a guest account (expire_postlogin). Lifetime values are specified in minutes,
* @property {boolean} g_action_notify_account_expire_enabled (boolean, optional): If checked, users will receive an email notification when their device's network credentials are due to expire,
* @property {number} g_action_notify_account_expiration_duration (integer, optional): Account expiration emails are sent this many days before the account expires. Enter a value between 1 and 30,
* @property {string} g_action_notify_account_expire_email_unknown (string, optional) = ['none' or 'fixed' or 'domain']: Specify where to send emails if the user's account doesn't have an email address recorded,
* @property {string} g_action_notify_account_expire_email_unknown_fixed (string, optional): Address used when no email address is known for a user,
* @property {string} g_action_notify_account_expire_email_unknown_domain (string, optional): Domain to append to the username to form an email address,
* @property {string} g_action_notify_account_expire_subject (string, optional): Enter a subject for the notification email,
* @property {number} g_action_notify_account_expire_message (integer, optional) = ['2' or '11' or '5' or '6' or '1' or '3' or '7' or '8' or '10' or '9' or '4']: The plain text or HTML print template to use when generating an email message,
* @property {string} g_action_notify_account_expire_skin (string, optional) = ['' or 'plaintext' or 'html_embedded' or 'receipt' or 'default' or 'Aruba Amigopod Skin' or 'Blank Skin' or 'ClearPass Guest Skin' or 'Custom Skin 1' or 'Custom Skin 2' or 'Galleria Skin' or 'Galleria Skin 2']: The format in which to send email receipts,
* @property {string} g_action_notify_account_expire_copies (string, optional) = ['never' or 'always_cc' or 'always_bcc']: Specify when to send to the recipients in the Copies To list,
* @property {string} g_action_notify_account_expire_copies_to (string, optional): An optional list of email addresses to which copies of expiry notifications will be sent,
* @property {string} site_ssid (string, optional): The SSID of the wireless LAN, if applicable. This will appear on guest account print receipts,
* @property {string} site_wpa_key (string, optional): The WPA key for the wireless LAN, if applicable. This will appear on guest account print receipts,
* @property {boolean} guest_receipt_print_button (boolean, optional): Guest receipts can print simply by selecting the template in the dropdown, or by clicking a link,
* @property {string} guest_account_terms_of_use_url (string, optional): The URL of a terms and conditions page. The URL will appear in any terms checkbox with: {nwa_global name=guest_account_terms_of_use_url} It is recommended to upload your terms in Content Manager, where the files will be referenced with the "public/" prefix. Alternatively, you can edit Terms and Conditions under Configuration > Pages > Web Pages. If your site is hosted externally, be sure the proper access control lists (ACLs) are in place. If terms are not required, it is recommended to edit the terms field on your forms to a UI type "hidden" and an Initial Value of 1,
* @property {number} guest_active_sessions (integer, optional): Enable limiting the number of active sessions a guest account may have. Enter 0 to allow an unlimited number of sessions,
* @property {string} guest_about_guest_network_access (string, optional): Template code to display on the Guest Manager start page, under the “About Guest Network Access” heading. Leave blank to use the default text, or enter a hyphen ("-") to remove the default text and the heading
*/

/**
* @typedef contextServerAction
* @type {object}
* @property {number} id (integer, optional): Numeric ID of the Context Server Action,
* @property {string} [server_type] (string, optional) = ['Aruba Activate' or 'airwatch' or 'JAMF' or 'MobileIron' or 'MaaS360' or 'SAP Afaria' or 'SOTI' or 'Google Admin Console' or 'Palo Alto Networks Panorama' or 'Palo Alto Networks Firewall' or 'Juniper Networks SRX' or 'XenMobile' or 'Generic HTTP' or 'AirWave' or 'ClearPass Cloud Proxy']: Server Type of the Context Server Action,
* @property {string} [server_name] (string, optional): Server Name of the Context Server Action,
* @property {string} [action_name] (string, optional): Action Name of the Context Server Action,
* @property {string} [description] (string, optional): Description of the Context Server Action,
* @property {string} [http_method] (string, optional) = ['GET' or 'POST' or 'PUT' or 'DELETE']: Http method of the Context Server Action,
* @property {boolean} [skip_http_auth] (boolean, optional): Enable to skip HTTP Basic Authentication,
* @property {string} [url] (string, optional): URL of the Context Server Action,
* @property {string} [content_type] (string, optional) = ['HTML' or 'JSON' or 'PLANE' or 'XML']: Content-Type of the Context Server Action. Note : For CUSTOM type use any string,
* @property {string} [content] (string, optional): Content of the Context Server Action,
* @property {object} [headers] (object, optional): Headers(key/value pairs) of the Context Server Action (e.g., [{"attr_name":"key1","attr_value":"value1"},{"attr_name":"key2","attr_value":"value2"}]),
* @property {object} [attributes] (object, optional): Attributes(key/value pairs) of the Context Server Action (e.g., [{"attr_name":"key1","attr_value":"value1"},{"attr_name":"key2","attr_value":"value2"}])
*/


/**
* @typedef fingerprint
* @type {object}
* @property {number} id (integer, optional): Id of the fingerprint,
* @property {string} [category] (string, optional): Category name of the fingerprint,
* @property {string} [family] (string, optional): Family name of the fingerprint,
* @property {string} [name] (string, optional): Unique name of the fingerprint
*/

/**
* @typedef guestAccountAttributes
* @type {Object}
* @property {string} create_time (string, optional): Time at which the account was created
* @property {string} current_state (string, optional) = ['active' or 'disabled' or 'expired' or 'pending']: Read-only property indicating the current state of the account
* @property {number} do_expire (integer, optional): Action to take when the expire_time is reached
* @property {string} email (string, optional): Email address for the account
* @property {boolean} enabled (boolean, optional): Flag indicating if the account is enabled
* @property {string} expire_time (string, optional): Time at which the account will expire
* @property {number} id (integer, optional): Numeric ID of the guest account
* @property {string} mac (string, optional): MAC address of the guest’s device
* @property {string} notes (string, optional): Comments or notes stored with the account
* @property {string} password (string, optional): Password for the account
* @property {number} role_id (integer, optional): Role to assign to the account
* @property {string} simultaneous_use (integer, optional): Number of simultaneous sessions allowed for the account
* @property {string} sponsor_email (string, optional): Email address of the sponsor
* @property {string} sponsor_name (string, optional): Name of the sponsor of the account
* @property {string} start_time (string, optional): Time at which the account will be enabled
* @property {string} username (string, optional): Username of the account
* @property {string} visitor_company (string, optional): The guest’s company name
* @property {string} visitor_name (string, optional): The guest’s contact telephone number
*/

/**
* @typedef guestDeviceAttributes
* @type {Object}
* @property {string} create_time (string, optional): Time at which the account was created,
* @property {string} current_state (string) = ['active' or 'disabled' or 'expired' or 'pending']: Read-only property indicating the current state of the account,
* @property {boolean} enabled (boolean): Flag indicating if the account is enabled,
* @property {string} expire_time (string): Time at which the account will expire,
* @property {number} id (integer): Numeric ID of the device account,
* @property {string} mac (string): MAC address of the device,
* @property {boolean} mac_auth (boolean): Flag indicating the account is a device, always set to true,
* @property {string} notes (string, optional): Comments or notes stored with the account,
* @property {string} password (string, optional),
* @property {number} role_id (integer): Role to assign to the account,
* @property {string} role_name (string): Name of the role assigned to the account,
* @property {string} source (string, optional): Origin of the account,
* @property {string} sponsor_name (string): Name of the sponsor of the account,
* @property {string} sponsor_profile (string): Numeric operator profile ID for the account’s sponsor,
* @property {string} sponsor_profile_name (string, optional): Name of the operator profile for the account’s sponsor,
* @property {string} start_time (string): Time at which the account will be enabled,
* @property {string} username (string),
* @property {string} visitor_name (string, optional): Name to display for the account,
*/

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
  @typedef endpointObject
  @type {object}
  @property {number} [id] The endpoint id.
  @property {string} [mac_address] The endpoints MAC Address.
  @property {string} [description] A description of the endpoint.
  @property {string} [status] The endpoint status (Known, Unknown, Disabled).
  @property {object} [attributes] Additional endpoint attributes.
*/

/**
  @typedef randomPasswordOptions
  @type {object}
  @property {string} [random_password_method] The random password method to use.
  @property {number} [random_password_length] The length of the password to be created.
  @property {string} [random_password_picture] The picture to be used for the nwa_picture_password method.
*/

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
  @typedef OnboardUser
  @type {object}
  @property {number} id (integer, optional): Numeric ID of the user
  @property {string} status (string, optional): ['allowed' or 'denied']: Determines whether the user can enroll devices
  @property {string} username (string, optional): Username of the user
  @property {number} device_count (undefined, optional): Number of devices enrolled by this user
*/


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
* @typedef ExtensionInstanceNetworkPort
* @type {object}
* @property {string} description (string, optional): Description of the service provided on this port,
* @property {string} protocol (string) = ['tcp' or 'udp']: Network protocol,
* @property {number} host_port (integer): Port number for the server,
* @property {number} extension_port (integer): Port number internal to the extension
*/

/**
* @typedef ExtensionInstanceHref
* @type {object}
* @property {string} description (string, optional): Description of the URL,
* @property {string} href (string): Server-relative URL path
*/

/**
* @typedef ExtensionInstance
* @type {object}
* @property {string} id (string, optional): ID of the extension instance,
* @property {string} state (string, optional) = ['preparing' or 'downloading' or 'stopped' or 'running' or 'failed']: Current state of the extension,
* @property {string} state_details (string, optional): Additional information about the current state of the extension,
* @property {string} store_id (string, optional): ID of the extension in the store,
* @property {string} name (string, optional): Name of the extension,
* @property {string} version (string, optional): Version number of the extension,
* @property {string} description (string, optional): Description of the extension,
* @property {string} icon_href (string, optional): URL for the extension’s icon,
* @property {string} about_href (string, optional): URL for the extension’s documentation,
* @property {string} hostname (string, optional): Hostname assigned to the extension,
* @property {ExtensionInstanceNetworkPort[]} network_ports (array[InstanceNetworkPort], optional): List of network ports provided by the extension,
* @property {ExtensionInstanceHref[]} extension_hrefs (array[InstanceHref], optional): List of URLs provided by the extension,
* @property {object} files (object, optional): Map of extension file IDs to local content items, with ‘public:’ or ‘private:’ prefix,
* @property {object} file_descriptions (object, optional): Contains a description of each extension file ID,
* @property {string} internal_ip_address (string, optional): Internal IP address of the extension,
* @property {boolean} needs_reinstall (boolean, optional): Indicates that the extension is out-of-date and should be reinstalled,
* @property {string} reinstall_details (string, optional): State details for any background reinstall operation that is in progress,
* @property {boolean} has_config (boolean, optional): Indicates that the extension has configuration settings,
* @property {string} install_time (string, optional): Time at which the extension was installed
*/

/**
* @typedef LocalUser
* @type {object}
* @property {number} id (integer, optional): Numeric ID of the local user,
* @property {string} user_id (string, optional): Unique user id of the local user,
* @property {string} password (string, optional): Password of the local user,
* @property {string} username (string, optional): User name of the local user,
* @property {string} role_name (string, optional): Role name of the local user,
* @property {boolean} enabled (boolean, optional): Flag indicating if the account is enabled,
* @property {boolean} change_pwd_next_login (boolean, optional): Flag indicating if the password change is required in next login,
* @property {object} attributes (object, optional): Additional attributes(key/value pairs) may be stored with the local user account
*/

/**
* Internal method for general api response processing.
*/

function processAsyncCppmResponse(resp) {
    if (resp.data) {
        if (resp.data._links) {
            delete resp.data._links;
        }

        if (resp.data._embedded && resp.data._embedded.items) {
            resp.data.items = resp.data._embedded.items;
            delete resp.data._embedded;
        }
    }
    return resp;
}

/**
* Validates the settings for the CPPM connection.
*/
function validateSettings(options) {
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


class ClearPassApi extends EventEmitter {

    /**
     * Aruba ClearPass API
     * @param {initOptions} options The options for the api (host, clientId, clientSecret, token, sslValidation)
     */
    constructor(options) {
        super();

        this.settings = options || {};
        this.internalTokenExp = null;
        this.internalToken = null;

        // if sslValidation is not set, enable it (secure by default)
        if (this.settings.sslValidation == null) {
            this.settings.sslValidation = true;
        }

        this.httpsAgent = new https.Agent({ rejectUnauthorized: this.settings.sslValidation });

        validateSettings(this.settings);
        this.init();

        this.tokenWaitSync = null;
        this.TOKEN_UPDATE_COMPLETE = 'token-update-complete';
    }

    /**
    * Setup any inital stuff from the settings.
    */
    init() {
        //todo: other init stuff here
    }


    /**
     * Processes an error to update descriptions, etc.
     * @param {Error} e
     */
    _responseErrorProcessing(e) {
        if (e) {
            e.shortMessage = e.message;

            if (e.response && e.response.data) {
                var { detail } = e.response.data;
                if (detail) {
                    e.message += ` - ${detail}`;
                }
            }
        }
        return e;
    }

    /**
     * Gets the Bearer token for the ClearPass API.
     *  @returns {Promise} Returns a promise.
     */
    getTokenAsync() {
        return new Promise(async (resolve, reject) => {
            // in case multiple processes attempt to get a token but a token update is already happening, lets wait it out.
            if (this.tokenWaitSync) {
                await this.tokenWaitSync;
                this.tokenWaitSync = null;
            }

            // if a token is supplied to the system, just use it.
            if (this.settings.token) {
                resolve(this.settings.token);
            }
            else {
                // if a token has already been generated, try and use it. Otherwise get a new one.
                if (this.internalToken && this.internalTokenExp > Date.now()) {
                    resolve(this.internalToken);
                }
                else {
                    this.tokenWaitSync = new Promise((t) => this.once(this.TOKEN_UPDATE_COMPLETE, t));

                    var options = {
                        baseURL: `https://${this.settings.host}/api`,
                        url: '/oauth',
                        method: 'POST',
                        httpsAgent: this.httpsAgent,
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        },
                        data: {
                            'grant_type': 'client_credentials',
                            'client_id': this.settings.clientId,
                            'client_secret': this.settings.clientSecret
                        }
                    };
                    axios(options)
                        .then((resp) => {
                            if (resp && resp.data && resp.data.access_token) {
                                var { expires_in, access_token } = resp.data;

                                this.internalTokenExp = ((expires_in - 5) * 1000) + Date.now();
                                this.internalToken = access_token;

                                resolve(access_token);
                            }
                            else {
                                var e = new Error('Unable to get token from ClearPass.');
                                e.response = resp;
                                reject(e);
                            }
                        })
                        .catch((e) => {
                            reject(this._responseErrorProcessing(e));
                        })
                        .finally(() => {
                            // once a token update is complete, emit a notification
                            this.emit(this.TOKEN_UPDATE_COMPLETE);
                        });
                }
            }
        });
    }

    /**
     * Gets the Bearer token for the ClearPass API.
     * @param {tokenNext} next The callback function
     */
    getToken(next) {
        this.getTokenAsync()
            .then((token) => {
                next(null, token);
            })
            .catch((e) => {
                next(e, null);
            });
    }

    _baseLegacyActionAsync(url, method, params, data) {
        return new Promise((resolve, reject) => {
            if (!this.settings.legacyApi) {
                reject(new Error('You must configure the legacy api options (legacyApi) to use this method.'));
                return
            }

            var headers = {
                'Accept': 'application/json',
            };

            if (data) {
                headers['Content-Type'] = 'application/json';
            }

            var rOptions = {
                baseURL: `https://${this.settings.host}`,
                url: url,
                method: method,
                httpsAgent: this.httpsAgent,
                headers: headers,
                auth: {
                    username: self.settings.legacyApi.userName || self.settings.legacyApi.username,
                    password: self.settings.legacyApi.password
                },
                params: params,
                data: data
            };
            axios(rOptions)
                .then((resp) => {
                    resolve(processAsyncCppmResponse(resp));
                })
                .catch((e) => {
                    reject(this._responseErrorProcessing(e));
                });
        });
    }

    _baseActionAsync(url, method, params, data) {
        return new Promise((resolve, reject) => {
            this.getTokenAsync()
                .then((token) => {

                    var headers = {
                        'Accept': 'application/json',
                        'Authorization': 'Bearer ' + token
                    };

                    if (data) {
                        headers['Content-Type'] = 'application/json';
                    }

                    var rOptions = {
                        baseURL: `https://${this.settings.host}/api`,
                        url: url,
                        method: method,
                        httpsAgent: this.httpsAgent,
                        headers: headers,
                        params: params,
                        data: data
                    };
                    axios(rOptions)
                        .then((resp) => {
                            resolve(processAsyncCppmResponse(resp));
                        })
                        .catch((e) => {
                            reject(this._responseErrorProcessing(e));
                        });
                })
                .catch((e) => {
                    reject(e);
                });
        });
    }

    _baseGetAsync(url, params) {
        return this._baseActionAsync(url, 'GET', params, null);
    }

    _basePostAsync(url, params, data) {
        return this._baseActionAsync(url, 'POST', params, data);
    }

    _basePatchAsync(url, params, data) {
        return this._baseActionAsync(url, 'PATCH', params, data);
    }

    _basePutAsync(url, params, data) {
        return this._baseActionAsync(url, 'PUT', params, data);
    }

    _baseDeleteAsync(url, params) {
        return this._baseActionAsync(url, 'DELETE', params, null);
    }

    _baseGetLookupAsync(url, options) {

        if (!options) {
            options = {};
        }

        if (options.offset <= 0) {
            options.offset = 0;
        }

        if (options.limit <= 0) {
            options.limit = 25;
        }

        var params = {
            filter: options.filter || {},
            sort: options.sort || '+id',
            offset: options.offset,
            limit: options.limit,
            calculate_count: options.calculate_count === false ? false : true
        };

        return this._baseActionAsync(url, 'GET', params, null);
    }

    /**
    * Get details about the currently authenticated user [/oauth/me]
    * @returns {Promise}
    */
    getMyInfoAsync() {
        return this._baseGetAsync('/oauth/me');
    }

    /**
     * Get details about the currently authenticated user [/oauth/me]
     * @param {doNext} next The callback function
     */
    getMyInfo(next) {
        this.getMyInfoAsync()
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get the privileges for the currently authenticated user [/oauth/privileges]
    * @returns {Promise}
    */
    getMyPrivilegesAsync() {
        return this._baseGetAsync('/oauth/privileges');
    }

    /**
     * Get the privileges for the currently authenticated user [/oauth/privileges]
     * @param {doNext} next The callback function
     */
    getMyPrivileges(next) {
        this.getMyPrivilegesAsync()
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    API Management
    ****************************************************************************************/

    /**
    * Search API Clients. [/api-client]
    * @param {searchOptions} options The options for search (filter, sort, offset, limit) [/api-client]
    * @returns {Promise}
    */
    getApiClientsAsync(options) {
        return this._baseGetLookupAsync('/api-client', options);
    }

    /**
    * Search API Clients. [/api-client]
    * @param {searchOptions} options The options for search (filter, sort, offset, limit) [/api-client]
    * @param {doNext} next The callback function
    */
    getApiClients(options, next) {
        this.getApiClientsAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Create a new api client. [/api-client]
    * @param {apiClientOptions} apiClient The attributes of the API Client. [/api-client]
    * @returns {Promise}
    */
    createApiClientAsync(apiClient) {
        return this._basePostAsync(`/api-client`, null, apiClient);
    }

    /**
    * Create a new api client. [/api-client]
    * @param {apiClientOptions} apiClient The attributes of the API Client. [/api-client]
    * @param {doNext} next The callback function
    */
    createApiClient(apiClient, next) {
        this.createApiClientAsync(apiClient)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a client by client id. [/api-client/{id}]
    * @param {string} clientId The client id
    * @returns {Promise}
    */
    getApiClientAsync(clientId) {
        return new Promise((resolve, reject) => {
            if (!clientId) {
                reject(new Error('You must specify a client id.'));
                return;
            }

            this._baseGetAsync(`/api-client/${encodeURIComponent(clientId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a client by client id. [/api-client/{id}]
    * @param {string} clientId The client id
    * @param {doNext} next The callback function
    */
    getApiClient(clientId, next) {
        this.getApiClient(clientId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
   * Update a client by client id. [/api-client/{id}]
   * @param {string} clientId The client id
   * @param {apiClientOptions} clientOptions The attributes of the client to update
   * @returns {Promise}
   */
    updateApiClientAsync(clientId, clientOptions) {
        return new Promise((resolve, reject) => {

            if (!clientId) {
                reject(new Error('You must specify a client id.'));
                return;
            }

            this._basePatchAsync(`/api-client/${encodeURIComponent(clientId)}`, null, clientOptions)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a client by client id. [/api-client/{id}]
    * @param {string} clientId The client id
    * @param {apiClientOptions} clientOptions The attributes of the client to update
    * @param {doNext} next - The callback function
    */
    updateApiClient(clientId, clientOptions, next) {
        this.updateApiClientAsync(clientId, clientOptions)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a api client by client id. [/api-client/{id}]
    * @param {string} clientId The client id
    * @param {apiClientOptions} clientOptions The new attributes of the client.
    * @returns {Promise} next The callback function
    */
    replaceApiClientAsync(clientId, clientOptions) {
        return new Promise((resolve, reject) => {

            if (!clientId) {
                reject(new Error('You must specify a client id.'));
                return;
            }

            this._basePutAsync(`/api-client/${encodeURIComponent(clientId)}`, null, clientOptions)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a api client by client id. [/api-client/{id}]
    * @param {string} clientId The client id
    * @param {apiClientOptions} clientOptions The new attributes of the client.
    * @param {doNext} next The callback function
    */
    replaceApiClient(clientId, clientOptions, next) {
        this.replaceApiClientAsync(clientId, clientOptions)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete an api client. [/api-client/{id}]
    * @param {string} clientId The client id
    * @returns {Promise} next The callback function
    */
    deleteApiClientAsync(clientId) {
        return new Promise((resolve, reject) => {
            if (!clientId) {
                reject(new Error('You must specify a client id.'));
                return;
            }

            this._baseDeleteAsync(`/api-client/${encodeURIComponent(clientId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete an api client. [/api-client/{id}]
    * @param {string} clientId The client id
    * @param {doNext} next - The callback function
    */
    deleteApiClient(clientId, next) {
        this.deleteApiClientAsync(clientId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Information
    ****************************************************************************************/

    /**
    * Gets the server version information. [/server/version]
    * @returns {Promise}
    */
    getServerVersionAsync() {
        return new Promise((resolve, reject) => {
            this._baseGetAsync(`/server/version`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Gets the server version information. [/server/version]
    * @param {doNext} next - The callback function
    */
    getServerVersion(next) {
        this.getServerVersionAsync()
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Gets the servers FIPS mode information. [/server/fips]
    * @returns {Promise}
    */
    getFipsStatusAsync() {
        return new Promise((resolve, reject) => {
            this._baseGetAsync(`/server/fips`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Gets the servers FIPS mode information. [/server/fips]
    * @param {doNext} next - The callback function
    */
    getFipsStatus(next) {
        this.getFipsStatusAsync()
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
   * Gets the server configuration information. [/cluster/server]
   * @returns {Promise}
   */
    getServerConfigurationAsync() {
        return new Promise((resolve, reject) => {
            this._baseGetAsync(`/cluster/server`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Gets the server configuration information [/cluster/server]
    * @param {doNext} next - The callback function
    */
    getServerConfiguration(next) {
        this.getServerConfigurationAsync()
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Guest Manager: Sessions
    ****************************************************************************************/

    /**
    * Get Guest Sessions. [/session]
    * @param {searchOptions} options - The options for session search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getGuestSessionsAsync(options) {
        return this._baseGetLookupAsync('/session', options);
    }

    /**
    * Get Guest Sessions. [/session]
    * @param {searchOptions} options - The options for session search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getGuestSessions(options, next) {
        this.getGuestSessionsAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Disconnect an active Session. [/session/{id}/disconnect]
    * @param {String} sessionId - The session to be disconnected
    * @returns {Promise}
    */
    disconnectSessionAsync(sessionId) {
        return new Promise((resolve, reject) => {

            if (!sessionId) {
                reject(new Error('You must specify a session id.'));
                return;
            }

            var data = {
                confirm_disconnect: true
            };

            this._basePostAsync(`/session/${encodeURIComponent(sessionId)}/disconnect`, null, data)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Disconnect an active Session. [/session/{id}/disconnect]
    * @param {String} sessionId - The session to be disconnected
    * @param {doNext} next - The callback function
    */
    disconnectSession(sessionId, next) {
        this.disconnectSessionAsync(sessionId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Disconnect an active Session. [/session/{id}/reauthorize]
    * @param {String} sessionId - The session to be disconnected
    * @returns {Promise}
    */
    getSessionReauthorizationProfilesAsync(sessionId) {
        return new Promise((resolve, reject) => {

            if (!sessionId) {
                reject(new Error('You must specify a session id.'));
                return;
            }

            this._baseGetAsync(`/session/${encodeURIComponent(sessionId)}/reauthorize`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Disconnect an active Session. [/session/{id}/reauthorize]
    * @param {String} sessionId - The session to be disconnected
    * @param {doNext} next - The callback function
    */
    getSessionReauthorizationProfiles(sessionId, next) {
        this.getSessionReauthorizationProfilesAsync(sessionId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Force the reauth of a session using the specified reauthorization profile. [/session/{id}/reauthorize]
    * @param {String} sessionId - The session to be disconnected
    * @param {String} reauthProfile - The reauthorization profile to use
    * @returns {Promise}
    */
    reauthorizeSessionAsync(sessionId, reauthProfile) {
        return new Promise((resolve, reject) => {

            if (!sessionId) {
                reject(new Error('You must specify a session id.'));
                return;
            }

            var data = {
                confirm_reauthorize: true,
                reauthorize_profile: reauthProfile
            };

            this._basePostAsync(`/session/${encodeURIComponent(sessionId)}/reauthorize`, null, data)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Force the reauth of a session using the specified reauthorization profile. [/session/{id}/reauthorize]
    * @param {String} sessionId - The session to be disconnected
    * @param {String} reauthProfile - The reauthorization profile to use
    * @param {doNext} next - The callback function
    */
    reauthorizeSession(sessionId, reauthProfile, next) {
        this.reauthorizeSessionAsync(sessionId, reauthProfile)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Guest Manager: Configuration
    ****************************************************************************************/

    /**
    * Get the guest manager configuration. [/guestmanager]
    * @returns {Promise}
    */
    getGuestManagerConfigurationAsync() {
        return this._baseGetAsync(`/guestmanager`);
    }

    /**
    * Get the guest manager configuration. [/guestmanager]
    * @param {doNext} next The callback function
    */
    getGuestManagerConfiguration(next) {
        this.getGuestManagerConfigurationAsync()
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get the guest manager configuration. [/guestmanager]
    * @param {guestManagerConfig} options The server configuration options
    * @returns {Promise}
    */
    updateGuestManagerConfigurationAsync(options) {
        return this._basePatchAsync(`/guestmanager`, null, options);
    }

    /**
    * Get the guest manager configuration. [/guestmanager]
    * @param {guestManagerConfig} options The server configuration options
    * @param {doNext} next The callback function
    */
    updateGuestManagerConfiguration(options, next) {
        this.updateGuestManagerConfigurationAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /****************************************************************************************
    Guest Manager: Device
    ****************************************************************************************/

    /**
    * Get a list of device details. [/device]
    * @param {searchOptions} options - The options for session search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getDevicesAsync(options) {
        return this._baseGetLookupAsync('/device', options);
    }

    /**
    * Get a list of device details. [/device]
    * @param {searchOptions} options - The options for session search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getDevices(options, next) {
        this.getDevicesAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Create a new device. [/device]
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization (true: Updates the network state using Disconnect-Request or CoA-Request, depending on the changes made. false: No action is taken. blank or unset: Use the default setting from Configuration » Authentication » Dynamic Authorization)
    * @returns {Promise}
    */
    createDeviceAsync(deviceAttributes, doChangeOfAuth) {
        var params = { change_of_authorization: doChangeOfAuth };
        return this._basePostAsync(`/device`, params, deviceAttributes);
    }

    /**
    * Create a new device. [/device]
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to create
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization (true: Updates the network state using Disconnect-Request or CoA-Request, depending on the changes made. false: No action is taken. blank or unset: Use the default setting from Configuration » Authentication » Dynamic Authorization)
    * @param {doNext} next - The callback function
    */
    createDevice(deviceAttributes, doChangeOfAuth, next) {
        this.createDeviceAsync(deviceAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a guest device by device id. [/device/{id}]
    * @param {number} deviceId - The device id
    * @returns {Promise}
    */
    getDeviceAsync(deviceId) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must specify a device id.'));
                return;
            }

            this._baseGetAsync(`/device/${encodeURIComponent(deviceId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a guest device by device id. [/device/{id}]
    * @param {number} deviceId - The device id
    * @param {doNext} next - The callback function
    */
    getDevice(deviceId, next) {
        this.getDeviceAsync(deviceId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a device by device id. [/device/{id}]
    * @param {string} deviceId - The device id
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    updateDeviceAsync(deviceId, deviceAttributes, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must specify a device id.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePatchAsync(`/device/${encodeURIComponent(deviceId)}`, params, deviceAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a device by device id. [/device/{id}]
    * @param {string} deviceId - The device id
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    updateDevice(deviceId, deviceAttributes, doChangeOfAuth, next) {
        this.updateDeviceAsync(deviceId, deviceAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a device by device id. [/device/{id}]
    * @param {string} deviceId - The device id
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    replaceDeviceAsync(deviceId, deviceAttributes, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must specify a device id.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePutAsync(`/device/${encodeURIComponent(deviceId)}`, params, deviceAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a device by device id. [/device/{id}]
    * @param {string} deviceId - The device id
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    replaceDevice(deviceId, deviceAttributes, doChangeOfAuth, next) {
        this.replaceDeviceAsync(deviceId, deviceAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a device by device id. [/device/{id}]
    * @param {string} deviceId - The device id
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    deleteDeviceAsync(deviceId, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must specify a device id.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._baseDeleteAsync(`/device/${encodeURIComponent(deviceId)}`, params)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a device by device id. [/device/{id}]
    * @param {string} deviceId - The device id
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    deleteDevice(deviceId, doChangeOfAuth, next) {
        this.deleteDeviceAsync(deviceId, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /****************************************************************************************
    Guest Manager: Device By Mac
    ****************************************************************************************/

    /**
    * Get device by mac address. [/device/mac/{mac_address}]
    * @param {string} macAddress - The MAC Address of the device
    * @returns {Promise}
    */
    getDeviceByMacAsync(macAddress) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            this._baseGetAsync(`/device/mac/${encodeURIComponent(macAddress)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get device by mac address. [/device/mac/{mac_address}]
    * @param {string} macAddress - The MAC Address of the device
    * @param {doNext} next - The callback function
    */
    getDeviceByMac(macAddress, next) {
        this.getDeviceByMacAsync(macAddress)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /**
    * Update a device by mac address. [/device/mac/{mac_address}]
    * @param {string} macAddress - The MAC Address of the device
    * @param {guestDeviceAttributes} options - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    updateDeviceByMacAsync(macAddress, options, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePatchAsync(`/device/mac/${encodeURIComponent(macAddress)}`, params, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a device by mac address. [/device/mac/{mac_address}]
    * @param {string} macAddress - The MAC Address of the device
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    updateDeviceByMac(macAddress, deviceAttributes, doChangeOfAuth, next) {
        this.updateDeviceByMacAsync(macAddress, deviceAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /**
    * Replace a device by mac address. [/device/mac/{mac_address}]
    * @param {string} macAddress - The MAC Address of the device
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    updateDeviceByMacAsync(macAddress, deviceAttributes, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePutAsync(`/device/mac/${encodeURIComponent(macAddress)}`, params, deviceAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a device by mac address. [/device/mac/{mac_address}]
    * @param {string} macAddress - The MAC Address of the device
    * @param {guestDeviceAttributes} deviceAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    replaceDeviceByMac(macAddress, deviceAttributes, doChangeOfAuth, next) {
        this.replaceDeviceByMacAsync(macAddress, deviceAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a device by mac address. [/device/mac/{mac_address}]
    * @param {string} macAddress - The MAC Address of the device
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    deleteDeviceByMacAsync(macAddress, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            this._baseDeleteAsync(`/device/mac/${encodeURIComponent(macAddress)}`, { change_of_authorization: doChangeOfAuth })
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a device by mac address. [/device/mac/{mac_address}]
    * @param {string} macAddress - The MAC Address of the device
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    deleteDeviceByMac(macAddress, doChangeOfAuth, next) {
        this.deleteDeviceByMacAsync(macAddress, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Guest Manager: Guests
    ****************************************************************************************/

    /**
    * Get a list of guest accounts. [/guest]
    * @param {searchOptions} options - The options for the guest account search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getGuestsAsync(options) {
        return this._baseGetLookupAsync('/guest', options);
    }

    /**
    * Get a list of guest accounts. [/guest]
    * @param {searchOptions} options - The options for the guest account search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getGuests(options, next) {
        this.getGuestsAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Create a new guest account. [/guest]
    * @param {guestAccountAttributes} guestAttributes - The attributes of the guest account to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    createGuestAsync(guestAttributes, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePostAsync(`/guest`, params, guestAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Create a new guest account. [/guest]
    * @param {guestAccountAttributes} guestAttributes - The attributes of the guest account to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    createGuest(guestAttributes, doChangeOfAuth, next) {
        this.createGuestAsync(guestAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get guest account by guest id. [/guest/{id}]
    * @param {number} guestId The guest account id
    * @returns {Promise}
    */
    getGuestAsync(guestId) {
        return new Promise((resolve, reject) => {

            if (!guestId) {
                reject(new Error('You must specify a Guest ID.'));
                return;
            }

            this._baseGetAsync(`/guest/${encodeURIComponent(guestId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get guest account by guest id. [/guest/{id}]
    * @param {number} guestId The guest account id
    * @param {doNext} next The callback function
    */
    getGuest(guestId, next) {
        this.getGuestAsync(guestId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a guest account by guest id. [/guest/{id}]
    * @param {number} guestId The guest account id
    * @param {guestAccountAttributes} guestAttributes The attributes of the device to update
    * @param {boolean=} doChangeOfAuth Do a Change of Authorization
    * @returns {Promise}
    */
    updateGuestAsync(guestId, guestAttributes, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!guestId) {
                reject(new Error('You must specify a Guest ID.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePatchAsync(`/guest/${encodeURIComponent(guestId)}`, params, guestAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a guest account by guest id. [/guest/{id}]
    * @param {number} guestId The guest account id
    * @param {guestAccountAttributes} guestAttributes The attributes of the device to update
    * @param {boolean=} doChangeOfAuth Do a Change of Authorization
    * @param {doNext} next The callback function
    */
    updateGuest(guestId, guestAttributes, doChangeOfAuth, next) {
        this.updateGuestAsync(guestId, guestAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a guest account by guest id. [/guest/{id}]
    * @param {string} guestId The guest account id
    * @param {guestAccountAttributes} guestAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    replaceGuestAsync(guestId, guestAttributes, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!guestId) {
                reject(new Error('You must specify a Guest ID.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePutAsync(`/guest/${encodeURIComponent(guestId)}`, params, guestAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a guest account by guest id. [/guest/{id}]
    * @param {string} guestId The guest account id
    * @param {guestAccountAttributes} guestAttributes - The attributes of the device to update
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    replaceGuest(guestId, guestAttributes, doChangeOfAuth, next) {
        this.replaceGuestAsync(guestId, guestAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a guest by guest id. [/guest/{id}]
    * @param {string} guestId The guest account id
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @returns {Promise}
    */
    deleteGuestAsync(guestId, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!guestId) {
                reject(new Error('You must specify a Guest ID.'));
                return;
            }

            this._baseDeleteAsync(`/guest/${encodeURIComponent(guestId)}`, { change_of_authorization: doChangeOfAuth })
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a guest by guest id. [/guest/{id}]
    * @param {string} guestId The guest account id
    * @param {boolean=} doChangeOfAuth - Do a Change of Authorization
    * @param {doNext} next - The callback function
    */
    deleteGuest(guestId, doChangeOfAuth, next) {
        this.deleteGuestAsync(guestId, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get guest account by user name. [/guest/username/{user_name}]
    * @param {string} userName The guest user name.
    * @returns {Promise}
    */
    getGuestByUserNameAsync(userName) {
        return new Promise((resolve, reject) => {

            if (!userName) {
                reject(new Error('You must specify a User Name.'));
                return;
            }

            this._baseGetAsync(`/guest/username/${encodeURIComponent(userName)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get guest account by user name. [/guest/username/{user_name}]
    * @param {string} userName The guest user name.
    * @param {doNext} next The callback function
    */
    getGuestByUserName(userName, next) {
        this.getGuestByUserNameAsync(userName)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a guest by user name. [/guest/username/{user_name}]
    * @param {string} userName The guest user name.
    * @param {guestAccountAttributes} guestAttributes The attributes of the guest to update
    * @param {boolean=} doChangeOfAuth Do a Change of Authorization
    * @returns {Promise}
    */
    updateGuestByUserNameAsync(userName, guestAttributes, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!userName) {
                reject(new Error('You must specify a User Name.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePatchAsync(`/guest/username/${encodeURIComponent(userName)}`, params, guestAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a guest by user name. [/guest/username/{user_name}]
    * @param {string} userName The guest user name.
    * @param {guestAccountAttributes} guestAttributes The attributes of the guest to update
    * @param {boolean=} doChangeOfAuth Do a Change of Authorization
    * @param {doNext} next The callback function
    */
    updateGuestByUserName(userName, guestAttributes, doChangeOfAuth, next) {
        this.updateGuestByUserNameAsync(userName, guestAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a guest by user name. [/guest/username/{user_name}]
    * @param {string} userName The guest user name.
    * @param {guestAccountAttributes} guestAttributes The attributes of the guest to update
    * @param {boolean=} doChangeOfAuth Do a Change of Authorization
    * @returns {Promise}
    */
    replaceGuestByUserNameAsync(userName, guestAttributes, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!userName) {
                reject(new Error('You must specify a User Name.'));
                return;
            }

            var params = { change_of_authorization: doChangeOfAuth };

            this._basePutAsync(`/guest/username/${encodeURIComponent(userName)}`, params, guestAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a guest by user name. [/guest/username/{user_name}]
    * @param {string} userName The guest user name.
    * @param {guestAccountAttributes} guestAttributes The attributes of the guest to update
    * @param {boolean=} doChangeOfAuth Do a Change of Authorization
    * @param {doNext} next The callback function
    */
    replaceGuestByUserName(userName, guestAttributes, doChangeOfAuth, next) {
        this.replaceGuestByUserNameAsync(userName, guestAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a guest by user name. [/guest/username/{user_name}]
    * @param {string} userName The guest user name.
    * @param {boolean=} doChangeOfAuth Do a Change of Authorization
    * @returns {Promise}
    */
    deleteGuestByUsernameAsync(userName, doChangeOfAuth) {
        return new Promise((resolve, reject) => {

            if (!userName) {
                reject(new Error('You must specify a User Name.'));
                return;
            }

            this._baseDeleteAsync(`/guest/username/${encodeURIComponent(userName)}`, { change_of_authorization: doChangeOfAuth })
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a guest by user name. [/guest/username/{user_name}]
    * @param {string} userName The guest user name.
    * @param {boolean=} doChangeOfAuth Do a Change of Authorization
    * @param {doNext} next The callback function
    */
    deleteGuestByUsername(userName, doChangeOfAuth, next) {
        this.deleteGuestByUsernameAsync(userName, guestAttributes, doChangeOfAuth)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Guest Manager: Guest Sponsor
    ****************************************************************************************/

    /**
    * Accept or reject a guest account that is waiting for a sponsor's approval. [/guest/{id}/sponsor]
    * @param {number} guestId The guest account id.
    * @param {randomPasswordOptions} [options] The options to be used for the random password generation.
    * @returns {Promise}
    */
    confirmGuestSponsorAsync(guestId, options) {
        return new Promise((resolve, reject) => {

            if (!guestId) {
                reject(new Error('You must specify a Guest ID.'));
                return;
            }

            this._basePostAsync(`/guest/${encodeURIComponent(guestId)}/sponsor`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Accept or reject a guest account that is waiting for a sponsor's approval. [/guest/{id}/sponsor]
    * @param {number} guestId The guest account id.
    * @param {randomPasswordOptions} [options] The options to be used for the random password generation.
    * @param {doNext} next The callback function
    */
    confirmGuestSponsor(guestId, options, next) {
        this.confirmGuestSponsorAsync(guestId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Guest Manager: Random Password
    ****************************************************************************************/

    /**
    * Generate a random password. [/random-password]
    * @param {randomPasswordOptions} [options] The options to be used for the random password generation.
    * @returns {Promise}
    */
    getRandomPasswordAsync(options) {
        return this._basePostAsync(`/random-password`, null, options);
    }

    /**
    * Generate a random password. [/random-password]
    * @param {randomPasswordOptions} [options] The options to be used for the random password generation.
    * @param {doNext} next The callback function
    */
    getRandomPassword(options, next) {
        this.getRandomPasswordAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Identity: Endpoints
    ****************************************************************************************/

    /**
    * Get a list of endpoints. [/endpoint]
    * @param {searchOptions} options - The options for the guest account search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getEndpointsAsync(options) {
        return this._baseGetLookupAsync('/endpoint', options);
    }

    /**
    * Get a list of endpoints. [/endpoint]
    * @param {searchOptions} options - The options for the guest account search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getEndpoints(options, next) {
        this.getEndpointsAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Create a new endpoint. [/endpoint]
    * @param {endpointObject} options - The attributes of the endpoint to update
    * @returns {Promise}
    */
    createEndpointAsync(options) {
        return this._basePostAsync(`/endpoint`, null, options);
    }

    /**
    * Create a new endpoint. [/endpoint]
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint to update
    * @param {doNext} next - The callback function
    */
    createEndpoint(endpointAttributes, next) {
        this.createEndpointAsync(endpointAttributes)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get an endpoint by id. [/endpoint/{id}]
    * @param {number} endpointId The endpoint id.
    * @returns {Promise}
    */
    getEndpointsAsync(endpointId) {
        return new Promise((resolve, reject) => {

            if (!endpointId) {
                reject(new Error('You must specify an Endpoint ID.'));
                return;
            }

            this._baseGetAsync(`/endpoint/${encodeURIComponent(endpointId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get an endpoint by id. [/endpoint/{id}]
    * @param {number} endpointId The endpoint id.
    * @param {doNext} next The callback function
    */
    getEndpoint(endpointId, next) {
        this.getEndpoint(endpointId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update an endpoint by id. [/endpoint/{id}]
    * @param {number} endpointId The endpoint id.
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint.
    * @returns {Promise}
    */
    updateEndpointAsync(endpointId, endpointAttributes) {
        return new Promise((resolve, reject) => {

            if (!endpointId) {
                reject(new Error('You must specify an Endpoint ID.'));
                return;
            }

            this._basePatchAsync(`/endpoint/${encodeURIComponent(endpointId)}`, null, endpointAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update an endpoint by id. [/endpoint/{id}]
    * @param {number} endpointId The endpoint id.
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint.
    * @param {doNext} next The callback function
    */
    updateEndpoint(endpointId, endpointAttributes, next) {
        this.updateEndpointAsync(endpointId, endpointAttributes)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace an endpoint by id. [/endpoint/{id}]
    * @param {number} endpointId The endpoint id.
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint.
    * @returns {Promise}
    */
    replaceEndpointAsync(endpointId, endpointAttributes) {
        return new Promise((resolve, reject) => {

            if (!endpointId) {
                reject(new Error('You must specify an Endpoint ID.'));
                return;
            }

            this._basePutAsync(`/endpoint/${encodeURIComponent(endpointId)}`, null, endpointAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace an endpoint by id. [/endpoint/{id}]
    * @param {number} endpointId The endpoint id.
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint.
    * @param {doNext} next - The callback function
    */
    replaceEndpoint(endpointId, endpointAttributes, next) {
        this.replaceEndpointAsync(endpointId, endpointAttributes)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete an endpoint by id. [/endpoint/{id}]
    * @param {string} endpointId The endpoint id.
    * @returns {Promise}
    */
    deleteEndpointAsync(endpointId) {
        return new Promise((resolve, reject) => {

            if (!endpointId) {
                reject(new Error('You must specify an Endpoint ID.'));
                return;
            }

            this._baseDeleteAsync(`/endpoint/${encodeURIComponent(endpointId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete an endpoint by id. [/endpoint/{id}]
    * @param {string} endpointId The endpoint id.
    * @param {doNext} next - The callback function
    */
    deleteEndpoint(endpointId, next) {
        this.deleteEndpointAsync(endpointId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get an endpoint by mac address. [/endpoint/mac-address/{mac_address}]
    * @param {string} macAddress The endpoint MAC Address.
    * @returns {Promise}
    */
    getEndpointByMacAsync(macAddress) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            this._baseGetAsync(`/endpoint/mac-address/${encodeURIComponent(macAddress)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }


    /**
    * Get an endpoint by mac address. [/endpoint/mac-address/{mac_address}]
    * @param {string} macAddress The endpoint MAC Address.
    * @param {doNext} next The callback function
    */
    getEndpointByMac(macAddress, next) {
        this.getEndpointByMacAsync(macAddress)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update and endpoint by mac address. [/endpoint/mac-address/{mac_address}]
    * @param {string} macAddress The endpoint MAC Address.
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint.
    * @returns {Promise}
    */
    updateEndpointByMacAsync(macAddress, endpointAttributes) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            this._basePatchAsync(`/endpoint/mac-address/${encodeURIComponent(macAddress)}`, null, endpointAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update and endpoint by mac address. [/endpoint/mac-address/{mac_address}]
    * @param {string} macAddress The endpoint MAC Address.
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint.
    * @param {doNext} next The callback function
    */
    updateEndpointByMac(macAddress, endpointAttributes, next) {
        this.updateEndpointByMacAsync(macAddress, endpointAttributes)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace an endpoint by mac address. [/endpoint/mac-address/{mac_address}]
    * @param {string} macAddress The endpoint MAC Address.
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint.
    * @returns {Promise}
    */
    replaceEndpointByMacAsync(macAddress, endpointAttributes) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            this._basePutAsync(`/endpoint/mac-address/${encodeURIComponent(macAddress)}`, null, endpointAttributes)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace an endpoint by mac address. [/endpoint/mac-address/{mac_address}]
    * @param {string} macAddress The endpoint MAC Address.
    * @param {endpointObject} endpointAttributes - The attributes of the endpoint.
    * @param {doNext} next - The callback function
    */
    replaceEndpointByMac(macAddress, endpointAttributes, next) {
        this.replaceEndpointByMacAsync(macAddress, endpointAttributes)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete an endpoint by mac address. [/endpoint/mac-address/{mac_address}]
    * @param {string} macAddress The endpoint MAC Address.
    * @returns {Promise}
    */
    deleteEndpointByMacAsync(macAddress) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            this._baseDeleteAsync(`/endpoint/mac-address/${encodeURIComponent(macAddress)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete an endpoint by mac address. [/endpoint/mac-address/{mac_address}]
    * @param {string} macAddress The endpoint MAC Address.
    * @param {doNext} next The callback function
    */
    deleteEndpointByMac(macAddress, next) {
        this.deleteEndpointByMacAsync(macAddress)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Identity: Local-Users
    ****************************************************************************************/

    /**
    * Get a list of local users. [/local-user]
    * @param {searchOptions} options - The options for the guest account search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getLocalUsersAsync(options) {
        return this._baseGetLookupAsync('/local-user', options);
    }

    /**
    * Get a list of local users. [/local-user]
    * @param {searchOptions} options - The options for the guest account search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getLocalUsers(options, next) {
        this.getEndpointsAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Create a new local user. [/local-user]
    * @param {LocalUser} options - The local user data.
    * @returns {Promise}
    */
    createLocalUserAsync(options) {
        return this._basePostAsync(`/local-user`, null, options);
    }

    /**
    * Create a new local user. [/local-user]
    * @param {LocalUser} options - The local user data.
    * @param {doNext} next - The callback function
    */
    createLocalUser(options, next) {
        this.createLocalUserAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a local user by id. [/local-user/{id}]
    * @param {number} userId The local user id.
    * @returns {Promise}
    */
    getLocalUserAsync(userId) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must specify a Local User ID.'));
                return;
            }

            this._baseGetAsync(`/local-user/${encodeURIComponent(userId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a local user by id. [/local-user/{id}]
    * @param {number} userId The local user id.
    * @param {doNext} next The callback function
    */
    getLocalUser(userId, next) {
        this.getLocalUserAsync(userId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a local user by id. [/local-user/{id}]
    * @param {number} userId The local user id.
    * @param {LocalUser} options - The local user data.
    * @returns {Promise}
    */
    updateLocalUserAsync(userId, options) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must specify an Local User ID.'));
                return;
            }

            this._basePatchAsync(`/local-user/${encodeURIComponent(userId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a local user by id. [/local-user/{id}]
    * @param {number} userId The local user id.
    * @param {LocalUser} options - The local user data.
    * @param {doNext} next The callback function
    */
    updateLocalUser(userId, options, next) {
        this.updateLocalUserAsync(userId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a local user by id. [/local-user/{id}]
    * @param {number} userId The local user id.
    * @param {LocalUser} options - The local user data.
    * @returns {Promise}
    */
    replaceLocalUserAsync(userId, options) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must specify a Local User ID.'));
                return;
            }

            this._basePutAsync(`/local-user/${encodeURIComponent(userId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a local user by id. [/local-user/{id}]
    * @param {number} userId The local user id.
    * @param {LocalUser} options - The local user data.
    * @param {doNext} next - The callback function
    */
    replaceLocalUser(userId, options, next) {
        this.replaceLocalUserAsync(userId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a local user by id. [/local-user/{id}]
    * @param {number} userId The local user id.
    * @returns {Promise}
    */
    deleteLocalUserAsync(userId) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must specify a Local User ID.'));
                return;
            }

            this._baseDeleteAsync(`/local-user/${encodeURIComponent(userId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a local user by id. [/local-user/{id}]
    * @param {number} userId The local user id.
    * @param {doNext} next - The callback function
    */
    deleteLocalUser(userId, next) {
        this.deleteLocalUserAsync(userId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a local user by id. [/local-user/user-id/{id}]
    * @param {string} userId The user id.
    * @returns {Promise}
    */
    getLocalUserByIdAsync(userId) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must specify a User ID.'));
                return;
            }

            this._baseGetAsync(`/local-user/user-id/${encodeURIComponent(userId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a local user by id. [/local-user/user-id/{id}]
    * @param {string} userId The user id.
    * @param {doNext} next The callback function
    */
    getLocalUserById(userId, next) {
        this.getLocalUserByIdAsync(userId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a local user by id. [/local-user/user-id/{id}]
    * @param {string} userId The user id.
    * @param {LocalUser} options - The local user data.
    * @returns {Promise}
    */
    updateLocalUserByIdAsync(userId, options) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must specify a User ID.'));
                return;
            }

            this._basePatchAsync(`/local-user/user-id/${encodeURIComponent(userId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a local user by id. [/local-user/user-id/{id}]
    * @param {string} userId The user id.
    * @param {LocalUser} options - The local user data.
    * @param {doNext} next The callback function
    */
    updateLocalUserById(userId, options, next) {
        this.updateLocalUserByIdAsync(userId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a local user by id. [/local-user/user-id/{id}]
    * @param {string} userId The user id.
    * @param {LocalUser} options - The local user data.
    * @returns {Promise}
    */
    replaceLocalUserByIdAsync(userId, options) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must specify a User ID.'));
                return;
            }

            this._basePutAsync(`/local-user/user-id/${encodeURIComponent(userId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a local user by id. [/local-user/user-id/{id}]
    * @param {string} userId The user id.
    * @param {LocalUser} options - The local user data.
    * @param {doNext} next - The callback function
    */
    replaceLocalUserById(userId, options, next) {
        this.replaceLocalUserByIdAsync(userId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a local user by id. [/local-user/user-id/{id}]
    * @param {string} userId The user id.
    * @returns {Promise}
    */
    deleteLocalUserByIdAsync(userId) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must specify a User ID.'));
                return;
            }

            this._baseDeleteAsync(`/local-user/user-id/${encodeURIComponent(userId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a local user by id. [/local-user/user-id/{id}]
    * @param {string} userId The user id.
    * @param {doNext} next - The callback function
    */
    deleteLocalUserById(userId, next) {
        this.deleteLocalUserByIdAsync(userId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /****************************************************************************************
    Extensions
    ****************************************************************************************/

    /**
    * Get a list of installed extensions. [/extension/instance]
    * @param {searchOptions} options - The options for the extensions search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getExtensionsAsync(options) {
        return this._baseGetLookupAsync('/extension/instance', options);
    }

    /**
    * Get a list of installed extensions. [/extension/instance]
    * @param {searchOptions} options - The options for the extensions search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getExtensions(options, next) {
        this.getExtensionsAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Install a new extension from the extension store. [/extension/instance]
    * @param {instanceCreate} options The options for the extension create.
    * @returns {Promise}
    */
    installExtensionAsync(options) {
        return this._basePostAsync(`/extension/instance`, null, options);
    }

    /**
    * Install a new extension from the extension store. [/extension/instance]
    * @param {ExtensionInstance} options The options for the extension create.
    * @param {doNext} next The callback function
    */
    installExtension(options, next) {
        this.installExtensionAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get an installed extensions. [/extension/instance/{id}]
    * @param {string} extensionId The id of the extension
    * @returns {Promise}
    */
    getExtensionAsync(extensionId) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._baseGetAsync(`/extension/instance/${encodeURIComponent(extensionId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get an installed extensions. [/extension/instance/{id}]
    * @param {string} extensionId The id of the extension
    * @param {doNext} next The callback function
    */
    getExtension(extensionId, next) {
        this.getExtensionAsync(extensionId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update an installed extensions state. [/extension/instance/{id}]
    * @param {string} extensionId The id of the extension
    * @param {string} extensionState The state of the extension ('stopped', 'running')
    * @returns {Promise}
    */
    updateExtensionStateAsync(extensionId, extensionState) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._basePatchAsync(`/extension/instance/${encodeURIComponent(extensionId)}`, null, { state: extensionState })
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update an installed extensions state. [/extension/instance/{id}]
    * @param {string} extensionId The id of the extension
    * @param {string} extensionState The state of the extension ('stopped', 'running')
    * @param {doNext} next The callback function
    */
    updateExtensionState(extensionId, extensionState, next) {
        this.updateExtensionStateAsync(extensionId, extensionState)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete an installed extension. [/extension/instance/{id}]
    * @param {string} extensionId The id of the extension
    * @param {boolean} force Force extension delete
    * @returns {Promise}
    */
    deleteExtensionAsync(extensionId, force) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._baseDeleteAsync(`/extension/instance/${encodeURIComponent(extensionId)}`, { force: force })
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete an installed extension. [/extension/instance/{id}]
    * @param {string} extensionId The id of the extension
    * @param {boolean} force Force extension delete
    * @param {doNext} next The callback function
    */
    deleteExtension(extensionId, force, next) {
        this.deleteExtensionAsync(extensionId, force)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /**
    * Get an extensions config. [/extension/instance/{id}/config]
    * @param {string} extensionId The id of the extension
    * @returns {Promise}
    */
    getExtensionConfigAsync(extensionId) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._baseGetAsync(`/extension/instance/${encodeURIComponent(extensionId)}/config`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get an extensions config. [/extension/instance/{id}/config]
    * @param {string} extensionId The id of the extension
    * @param {doNext} next The callback function
    */
    getExtensionConfig(extensionId, next) {
        this.getExtensionConfigAsync(extensionId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update an extensions config. [/extension/instance/{id}/config]
    * @param {string} extensionId The id of the extension
    * @param {object} config The extensions configuration
    * @returns {Promise}
    */
    updateExtensionConfigAsync(extensionId, config) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._basePutAsync(`/extension/instance/${encodeURIComponent(extensionId)}/config`, null, config)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update an extensions config. [/extension/instance/{id}/config]
    * @param {string} extensionId The id of the extension
    * @param {object} config The extensions configuration
    * @param {doNext} next The callback function
    */
    updateExtensionConfig(extensionId, config, next) {
        this.updateExtensionConfigAsync(extensionId, config)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Reinstall an extension. [/extension/instance/{id}/reinstall]
    * @param {string} extensionId The id of the extension
    * @param {ExtensionInstance} options The reinstall options
    * @returns {Promise}
    */
    reinstallExtensionAsync(extensionId, options) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._basePostAsync(`/extension/instance/${encodeURIComponent(extensionId)}/reinstall`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Reinstall an extension. [/extension/instance/{id}/reinstall]
    * @param {string} extensionId The id of the extension
    * @param {ExtensionInstance} options The reinstall options
    * @param {doNext} next The callback function
    */
    reinstallExtension(extensionId, options, next) {
        this.reinstallExtensionAsync(extensionId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Restart an extension. [/extension/instance/{id}/restart]
    * @param {string} extensionId The id of the extension
    * @returns {Promise}
    */
    restartExtensionAsync(extensionId) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._basePostAsync(`/extension/instance/${encodeURIComponent(extensionId)}/restart`, null, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Restart an extension. [/extension/instance/{id}/restart]
    * @param {string} extensionId The id of the extension
    * @param {doNext} next The callback function
    */
    restartExtension(extensionId, next) {
        this.restartExtensionAsync(extensionId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Start an extension. [/extension/instance/{id}/start]
    * @param {string} extensionId The id of the extension
    * @returns {Promise}
    */
    startExtensionAsync(extensionId) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._basePostAsync(`/extension/instance/${encodeURIComponent(extensionId)}/start`, null, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Start an extension. [/extension/instance/{id}/start]
    * @param {string} extensionId The id of the extension
    * @param {doNext} next The callback function
    */
    startExtension(extensionId, next) {
        this.startExtensionAsync(extensionId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /**
    * Stop an extension. [/extension/instance/{id}/stop]
    * @param {string} extensionId The id of the extension
    * @returns {Promise}
    */
    stopExtensionAsync(extensionId) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            this._basePostAsync(`/extension/instance/${encodeURIComponent(extensionId)}/stop`, null, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Start an extension. [/extension/instance/{id}/stop]
    * @param {string} extensionId The id of the extension
    * @param {doNext} next The callback function
    */
    stopExtension(extensionId, next) {
        this.stopExtensionAsync(extensionId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get extension logs. [/extension/instance/{id}/log]
    * @param {string} extensionId The id of the extension
    * @param {extensionLogOptions} logOptions Log view options
    * @returns {Promise}
    */
    getExtensionLogsAsync(extensionId, logOptions) {
        return new Promise((resolve, reject) => {

            if (!extensionId) {
                reject(new Error('You must specify an Extension ID.'));
                return;
            }

            var params = {
                stdout: logOptions.stdout === false ? false : true,
                stderr: logOptions.stderr === false ? false : true,
                since: logOptions.since,
                timestamps: logOptions.timestamps === true ? true : false,
                tail: logOptions.tail || "all"
            };

            this._baseGetAsync(`/extension/instance/${encodeURIComponent(extensionId)}/log`, params)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get extension logs. [/extension/instance/{id}/log]
    * @param {string} extensionId The id of the extension
    * @param {extensionLogOptions} logOptions Log view options
    * @param {doNext} next The callback function
    */
    getExtensionLogs(extensionId, logOptions, next) {
        this.getExtensionLogsAsync(extensionId, logOptions)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /****************************************************************************************
    Dictionaries
    ****************************************************************************************/

    /****************************************************************************************
    Attributes
    ****************************************************************************************/

    /**
    * Get a list of attributes. [/attribute]
    * @param {searchOptions} options - The options for the attribute search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getAttributesAsync(options) {
        return this._baseGetLookupAsync('/attribute', options);
    }

    /**
    * Get a list of attributes. [/attribute]
    * @param {searchOptions} options - The options for the attribute search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getAttributes(options, next) {
        this.getAttributesAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Create a new attribute. [/attribute]
    * @param {attributeOptions} options The options for the attribute.
    * @returns {Promise}
    */
    createAttributeAsync(options) {
        return this._basePostAsync(`/attribute`, null, options);
    }

    /**
    * Create a new attribute. [/attribute]
    * @param {attributeOptions} options The options for the attribute.
    * @param {doNext} next - The callback function
    */
    createAttribute(options, next) {
        this.createAttributeAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get an attribute by id. [/attribute/{id}]
    * @param {number} attributeId The attribute id.
    * @returns {Promise}
    */
    getAttributeAsync(attributeId) {
        return new Promise((resolve, reject) => {

            if (!attributeId) {
                reject(new Error('You must specify an Attribute ID'));
                return;
            }

            this._baseGetAsync(`/attribute/${encodeURIComponent(attributeId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get an attribute by id. [/attribute/{id}]
    * @param {number} attributeId The attribute id.
    * @param {doNext} next The callback function
    */
    getAttribute(attributeId, next) {
        this.getAttributeAsync(attributeId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update an attribute by id. [/attribute/{id}]
    * @param {number} attributeId The attribute id.
    * @param {attributeOptions} attribute The options for the attribute.
    * @returns {Promise}
    */
    updateAttributeAsync(attributeId, options) {
        return new Promise((resolve, reject) => {

            if (!attributeId) {
                reject(new Error('You must specify an Attribute ID'));
                return;
            }

            this._basePatchAsync(`/attribute/${encodeURIComponent(attributeId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update an attribute by id. [/attribute/{id}]
    * @param {number} attributeId The attribute id.
    * @param {attributeOptions} options The options for the attribute.
    * @param {doNext} next - The callback function
    */
    updateAttribute(attributeId, options, next) {
        this.updateAttributeAsync(attributeId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace an attribute by id. [/attribute/{id}]
    * @param {number} attributeId The attribute id.
    * @param {attributeOptions} options The options for the attribute.
    * @returns {Promise}
    */
    replaceAttributeAsync(attributeId, options) {
        return new Promise((resolve, reject) => {

            if (!attributeId) {
                reject(new Error('You must specify an Attribute ID'));
                return;
            }

            this._basePutAsync(`/attribute/${encodeURIComponent(attributeId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace an attribute by id. [/attribute/{id}]
    * @param {number} attributeId The attribute id.
    * @param {attributeOptions} options The options for the attribute.
    * @param {doNext} next The callback function
    */
    replaceAttribute(attributeId, options, next) {
        this.replaceAttributeAsync(attributeId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete an attribute by id. [/attribute/{id}]
    * @param {number} attributeId The attribute id.
    * @returns {Promise}
    */
    deleteAttributeAsync(attributeId) {
        return new Promise((resolve, reject) => {

            if (!attributeId) {
                reject(new Error('You must specify an Attribute ID'));
                return;
            }

            this._baseDeleteAsync(`/attribute/${encodeURIComponent(attributeId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete an attribute by id. [/attribute/{id}]
    * @param {number} attributeId The attribute id.
    * @param {doNext} next - The callback function
    */
    deleteAttribute(attributeId, next) {
        this.replaceAttributeAsync(attributeId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get an attribute by name. [/attribute/{entity_name}/name/{attribute_name}]
    * @param {string} entityName The entity name.
    * @param {string} attributeName The attribute name.
    * @returns {Promise}
    */
    getAttributeByNameAsync(entityName, attributeName) {
        return new Promise((resolve, reject) => {

            if (!entityName) {
                reject(new Error('You must specify an Entity Name'));
                return;
            }

            if (!attributeName) {
                reject(new Error('You must specify an Attribute Name'));
                return;
            }

            this._baseGetAsync(`/attribute/${encodeURIComponent(entityName)}/name/${encodeURIComponent(attributeName)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get an attribute by name. [/attribute/{entity_name}/name/{attribute_name}]
    * @param {string} entityName The entity name.
    * @param {string} attributeName The attribute name.
    * @param {doNext} next The callback function
    */
    getAttributeByName(entityName, attributeName, next) {
        this.getAttributeByNameAsync(entityName, attributeName)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update an attribute by name. [/attribute/{entity_name}/name/{attribute_name}]
    * @param {string} entityName The entity name.
    * @param {string} attributeName The attribute name.
    * @param {attributeOptions} options The options for the attribute.
    * @returns {Promise}
    */
    updateAttributeByNameAsync(entityName, attributeName, options) {
        return new Promise((resolve, reject) => {

            if (!entityName) {
                reject(new Error('You must specify an Entity Name'));
                return;
            }

            if (!attributeName) {
                reject(new Error('You must specify an Attribute Name'));
                return;
            }

            this._basePatchAsync(`/attribute/${encodeURIComponent(entityName)}/name/${encodeURIComponent(attributeName)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update an attribute by name. [/attribute/{entity_name}/name/{attribute_name}]
    * @param {string} entityName The entity name.
    * @param {string} attributeName The attribute name.
    * @param {attributeOptions} options The options for the attribute.
    * @param {doNext} next The callback function
    */
    updateAttributeByName(entityName, attributeName, options, next) {
        this.updateAttributeByNameAsync(entityName, attributeName, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace an attribute by name. [/attribute/{entity_name}/name/{attribute_name}]
    * @param {string} entityName The entity name.
    * @param {string} attributeName The attribute name.
    * @param {attributeOptions} options The options for the attribute.
    * @returns {Promise}
    */
    replaceAttributeByNameAsync(entityName, attributeName, options) {
        return new Promise((resolve, reject) => {

            if (!entityName) {
                reject(new Error('You must specify an Entity Name'));
                return;
            }

            if (!attributeName) {
                reject(new Error('You must specify an Attribute Name'));
                return;
            }

            this._basePutAsync(`/attribute/${encodeURIComponent(entityName)}/name/${encodeURIComponent(attributeName)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * replace an attribute by name. [/attribute/{entity_name}/name/{attribute_name}]
    * @param {string} entityName The entity name.
    * @param {string} attributeName The attribute name.
    * @param {attributeOptions} options The options for the attribute.
    * @param {doNext} next The callback function
    */
    replaceAttributeByName(entityName, attributeName, options, next) {
        this.replaceAttributeByNameAsync(entityName, attributeName, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete an attribute by name. [/attribute/{entity_name}/name/{attribute_name}]
    * @param {string} entityName The entity name.
    * @param {string} attributeName The attribute name.
    * @returns {Promise}
    */
    deleteAttributeByNameAsync(entityName, attributeName) {
        return new Promise((resolve, reject) => {

            if (!entityName) {
                reject(new Error('You must specify an Entity Name'));
                return;
            }

            if (!attributeName) {
                reject(new Error('You must specify an Attribute Name'));
                return;
            }

            this._baseDeleteAsync(`/attribute/${encodeURIComponent(entityName)}/name/${encodeURIComponent(attributeName)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete an attribute by name. [/attribute/{entity_name}/name/{attribute_name}]
    * @param {string} entityName The entity name.
    * @param {string} attributeName The attribute name.
    * @param {doNext} next - The callback function
    */
    deleteAttributeByName(entityName, attributeName, next) {
        this.deleteAttributeByNameAsync(entityName, attributeName)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Context Server Actions
    ****************************************************************************************/

    /**
    * Get a list of context server actions. [/context-server-action]
    * @param {searchOptions} options - The options for the context action search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getContextServerActionsAsync(options) {
        return this._baseGetLookupAsync('/context-server-action', options);
    }

    /**
    * Get a list of context server actions. [/context-server-action]
    * @param {searchOptions} options - The options for the context action search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getContextServerActions(options, next) {
        this.getContextServerActionsAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /**
    * Create a new context server action. [/context-server-action]
    * @param {contextServerAction} options The options for the action.
    * @returns {Promise}
    */
    createContextServerActionAsync(options) {
        return this._basePostAsync(`/context-server-action`, null, options);
    }

    /**
    * Create a new context server action. [/context-server-action]
    * @param {contextServerAction} options The options for the action.
    * @param {doNext} next The callback function
    */
    createContextServerAction(options, next) {
        this.createContextServerActionAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a context server action by id. [/context-server-action/{id}]
    * @param {number} csaId The Context Server Action id.
    * @returns {Promise}
    */
    getContextServerActionAsync(csaId) {
        return new Promise((resolve, reject) => {

            if (!csaId) {
                reject(new Error('You must specify a Context Server Action ID.'));
                return;
            }

            this._baseGetAsync(`/context-server-action/${encodeURIComponent(csaId)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a context server action by id. [/context-server-action/{id}]
    * @param {number} csaId The Context Server Action id.
    * @param {doNext} next The callback function
    */
    getContextServerAction(csaId, next) {
        this.getContextServerActionAsync(csaId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a context server action by id. [/context-server-action/{id}]
    * @param {number} csaId The Context Server Action id.
    * @param {contextServerAction} options The options for the action.
    * @returns {Promise}
    */
    updateContextServerActionAsync(csaId, options) {
        return new Promise((resolve, reject) => {

            if (!csaId) {
                reject(new Error('You must specify a Context Server Action ID.'));
                return;
            }

            this._basePatchAsync(`/context-server-action/${encodeURIComponent(csaId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a context server action by id. [/context-server-action/{id}]
    * @param {number} csaId The Context Server Action id.
    * @param {contextServerAction} options The options for the action.
    * @param {doNext} next - The callback function
    */
    updateContextServerAction(csaId, options, next) {
        this.updateContextServerActionAsync(csaId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a context server action by id. [/context-server-action/{id}]
    * @param {number} csaId The Context Server Action id.
    * @param {contextServerAction} options The options for the action.
    * @returns {Promise}
    */
    replaceContextServerActionAsync(csaId, options) {
        return new Promise((resolve, reject) => {

            if (!csaId) {
                reject(new Error('You must specify a Context Server Action ID.'));
                return;
            }

            this._basePutAsync(`/context-server-action/${encodeURIComponent(csaId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a context server action by id. [/context-server-action/{id}]
    * @param {number} csaId The Context Server Action id.
    * @param {contextServerAction} options The options for the action.
    * @param {doNext} next - The callback function
    */
    replaceContextServerAction(csaId, options, next) {
        this.replaceContextServerActionAsync(csaId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a context server action by id. [/context-server-action/{id}]
    * @param {number} csaId The Context Server Action id.
    * @returns {Promise}
    */
    deleteContextServerActionAsync(csaId) {
        return new Promise((resolve, reject) => {

            if (!csaId) {
                reject(new Error('You must specify a Context Server Action ID.'));
                return;
            }

            this._baseDeleteAsync(`/context-server-action/${encodeURIComponent(csaId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a context server action by id. [/context-server-action/{id}]
    * @param {number} csaId The Context Server Action id.
    * @param {doNext} next - The callback function
    */
    deleteContextServerAction(csaId, next) {
        this.deleteContextServerActionAsync(csaId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a context server action by name. [/context-server-action/{type}/action-name/{name}]
    * @param {string} serverType The server type.
    * @param {string} actionName The action name.
    * @returns {Promise}
    */
    getContextServerActionByNameAsync(serverType, actionName) {
        return new Promise((resolve, reject) => {

            if (!serverType) {
                reject(new Error('You must specify a Context Server Action Type.'));
                return;
            }

            if (!actionName) {
                reject(new Error('You must specify a Context Server Action Name.'));
                return;
            }

            this._baseGetAsync(`/context-server-action/${encodeURIComponent(serverType)}/action-name/${encodeURIComponent(actionName)}`)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a context server action by name. [/context-server-action/{type}/action-name/{name}]
    * @param {string} serverType The server type.
    * @param {string} actionName The action name.
    * @param {doNext} next The callback function
    */
    getContextServerActionByName(serverType, actionName, next) {
        this.getContextServerActionByNameAsync(serverType, actionName)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a context server action by name. [/context-server-action/{type}/action-name/{name}]
    * @param {string} serverType The server type.
    * @param {string} actionName The action name.
    * @param {contextServerAction} options The options for the action.
    * @returns {Promise}
    */
    updateContextServerActionByNameAsync(serverType, actionName, options) {
        return new Promise((resolve, reject) => {

            if (!serverType) {
                reject(new Error('You must specify a Context Server Action Type.'));
                return;
            }

            if (!actionName) {
                reject(new Error('You must specify a Context Server Action Name.'));
                return;
            }

            this._basePatchAsync(`/context-server-action/${encodeURIComponent(serverType)}/action-name/${encodeURIComponent(actionName)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a context server action by name. [/context-server-action/{type}/action-name/{name}]
    * @param {string} serverType The server type.
    * @param {string} actionName The action name.
    * @param {contextServerAction} options The options for the action.
    * @param {doNext} next The callback function
    */
    updateContextServerActionByName(serverType, actionName, options, next) {
        this.updateContextServerActionByNameAsync(serverType, actionName, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a context server action by name. [/context-server-action/{type}/action-name/{name}]
    * @param {string} serverType The server type.
    * @param {string} actionName The action name.
    * @param {contextServerAction} options The options for the action.
    * @returns {Promise}
    */
    replaceContextServerActionByNameAsync(serverType, actionName, options) {
        return new Promise((resolve, reject) => {

            if (!serverType) {
                reject(new Error('You must specify a Context Server Action Type.'));
                return;
            }

            if (!actionName) {
                reject(new Error('You must specify a Context Server Action Name.'));
                return;
            }

            this._basePutAsync(`/context-server-action/${encodeURIComponent(serverType)}/action-name/${encodeURIComponent(actionName)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a context server action by name. [/context-server-action/{type}/action-name/{name}]
    * @param {string} serverType The server type.
    * @param {string} actionName The action name.
    * @param {contextServerAction} options The options for the action.
    * @param {doNext} next The callback function
    */
    replaceContextServerActionByName(serverType, actionName, options, next) {
        this.replaceContextServerActionByNameAsync(serverType, actionName, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a context server action by name. [/context-server-action/{type}/action-name/{name}]
    * @param {string} serverType The server type.
    * @param {string} actionName The action name.
    * @returns {Promise}
    */
    deleteContextServerActionByNameAsync(serverType, actionName) {
        return new Promise((resolve, reject) => {

            if (!serverType) {
                reject(new Error('You must specify a Context Server Action Type.'));
                return;
            }

            if (!actionName) {
                reject(new Error('You must specify a Context Server Action Name.'));
                return;
            }

            this._baseDeleteAsync(`/context-server-action/${encodeURIComponent(serverType)}/action-name/${encodeURIComponent(actionName)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a context server action by name. [/context-server-action/{type}/action-name/{name}]
    * @param {string} serverType The server type.
    * @param {string} actionName The action name.
    * @param {doNext} next - The callback function
    */
    deleteContextServerActionByName(serverType, actionName, next) {
        this.deleteContextServerActionByNameAsync(serverType, actionName)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Fingerprints
    ****************************************************************************************/

    /**
    * Get a list of fingerprints. [/fingerprint]
    * @param {searchOptions} options - The options for the fingerprint search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getFingerprintsAsync(options) {
        return this._baseGetLookupAsync('/fingerprint', options);
    }

    /**
    * Get a list of fingerprints. [/fingerprint]
    * @param {searchOptions} options - The options for the fingerprint search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getFingerprints(options, next) {
        this.getFingerprintsAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /**
    * Create a new fingerprint. [/fingerprint]
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @returns {Promise}
    */
    createFingerprintAsync(fingerprint) {
        return this._basePostAsync(`/fingerprint`, null, fingerprint);
    }

    /**
    * Create a new fingerprint. [/fingerprint]
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @param {doNext} next The callback function
    */
    createFingerprint(fingerprint, next) {
        this.createFingerprintAsync(fingerprint)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a fingerprint by id. [/fingerprint/{id}]
    * @param {number} fId The fingerprint id.
    * @returns {Promise}
    */
    getFingerprintAsync(fId) {
        return new Promise((resolve, reject) => {

            if (!fId) {
                reject(new Error('You must specify a Fingerprint ID.'));
                return;
            }

            this._baseGetAsync(`/fingerprint/${encodeURIComponent(fId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a fingerprint by id. [/fingerprint/{id}]
    * @param {number} fId The fingerprint id.
    * @param {doNext} next The callback function
    */
    getFingerprint(fId, next) {
        this.getFingerprintAsync(fId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a fingerprint by id. [/fingerprint/{id}]
    * @param {number} fId The fingerprint id.
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @returns {Promise}
    */
    updateFingerprintAsync(fId, fingerprint, next) {
        return new Promise((resolve, reject) => {

            if (!fId) {
                reject(new Error('You must specify a Fingerprint ID.'));
                return;
            }

            this._basePatchAsync(`/fingerprint/${encodeURIComponent(fId)}`, null, fingerprint)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a fingerprint by id. [/fingerprint/{id}]
    * @param {number} fId The fingerprint id.
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @param {doNext} next - The callback function
    */
    updateFingerprint(fId, fingerprint, next) {
        this.updateFingerprintAsync(fId, fingerprint)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a fingerprint by id. [/fingerprint/{id}]
    * @param {number} fId The fingerprint id.
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @returns {Promise}
    */
    replaceFingerprintAsync(fId, fingerprint) {
        return new Promise((resolve, reject) => {

            if (!fId) {
                reject(new Error('You must specify a Fingerprint ID.'));
                return;
            }

            this._basePutAsync(`/fingerprint/${encodeURIComponent(fId)}`, null, fingerprint)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a fingerprint by id. [/fingerprint/{id}]
    * @param {number} fId The fingerprint id.
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @param {doNext} next - The callback function
    */
    replaceFingerprint(fId, fingerprint, next) {
        this.replaceFingerprintAsync(fId, fingerprint)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a fingerprint by id. [/fingerprint/{id}]
    * @param {number} fId The fingerprint id.
    * @returns {Promise}
    */
    deleteFingerprintAsync(fId) {
        return new Promise((resolve, reject) => {

            if (!fId) {
                reject(new Error('You must specify a Fingerprint ID.'));
                return;
            }

            this._baseDeleteAsync(`/fingerprint/${encodeURIComponent(fId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a fingerprint by id. [/fingerprint/{id}]
    * @param {number} fId The fingerprint id.
    * @param {doNext} next - The callback function
    */
    replaceFingerprint(fId, next) {
        this.deleteFingerprintAsync(fId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a fingerprint by name. [/fingerprint/{category}/{family}/{name}]
    * @param {string} category The fingerprint category.
    * @param {string} family The fingerprint family.
    * @param {string} name The fingerprint name.
    * @returns {Promise}
    */
    getFingerprintByNameAsync(category, family, name) {
        return new Promise((resolve, reject) => {

            if (!category) {
                reject(new Error('You must specify a category.'));
                return;
            }

            if (!family) {
                reject(new Error('You must specify a family.'));
                return;
            }

            if (!name) {
                reject(new Error('You must specify a name.'));
                return;
            }

            this._baseGetAsync(`/fingerprint/${encodeURIComponent(category)}/${encodeURIComponent(family)}/${encodeURIComponent(name)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a fingerprint by name. [/fingerprint/{category}/{family}/{name}]
    * @param {string} category The fingerprint category.
    * @param {string} family The fingerprint family.
    * @param {string} name The fingerprint name.
    * @param {doNext} next The callback function
    */
    getFingerprintByName(category, family, name, next) {
        this.getFingerprintByNameAsync(category, family, name)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a fingerprint by name. [/fingerprint/{category}/{family}/{name}]
    * @param {string} category The fingerprint category.
    * @param {string} family The fingerprint family.
    * @param {string} name The fingerprint name.
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @returns {Promise}
    */
    updateFingerprintByNameAsync(category, family, name, fingerprint) {
        return new Promise((resolve, reject) => {

            if (!category) {
                reject(new Error('You must specify a category.'));
                return;
            }

            if (!family) {
                reject(new Error('You must specify a family.'));
                return;
            }

            if (!name) {
                reject(new Error('You must specify a name.'));
                return;
            }

            this._basePatchAsync(`/fingerprint/${encodeURIComponent(category)}/${encodeURIComponent(family)}/${encodeURIComponent(name)}`, null, fingerprint)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a fingerprint by name. [/fingerprint/{category}/{family}/{name}]
    * @param {string} category The fingerprint category.
    * @param {string} family The fingerprint family.
    * @param {string} name The fingerprint name.
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @param {doNext} next The callback function
    */
    updateFingerprintByName(category, family, name, fingerprint) {
        this.updateFingerprintByNameAsync(category, family, name, fingerprint)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a fingerprint by name. [/fingerprint/{category}/{family}/{name}]
    * @param {string} category The fingerprint category.
    * @param {string} family The fingerprint family.
    * @param {string} name The fingerprint name.
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @returns {Promise}
    */
    replaceFingerprintByNameAsync(category, family, name, fingerprint) {
        return new Promise((resolve, reject) => {

            if (!category) {
                reject(new Error('You must specify a category.'));
                return;
            }

            if (!family) {
                reject(new Error('You must specify a family.'));
                return;
            }

            if (!name) {
                reject(new Error('You must specify a name.'));
                return;
            }

            this._basePutAsync(`/fingerprint/${encodeURIComponent(category)}/${encodeURIComponent(family)}/${encodeURIComponent(name)}`, null, fingerprint)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a fingerprint by name. [/fingerprint/{category}/{family}/{name}]
    * @param {string} category The fingerprint category.
    * @param {string} family The fingerprint family.
    * @param {string} name The fingerprint name.
    * @param {fingerprint} fingerprint The options for the fingerprint.
    * @param {doNext} next The callback function
    */
    replaceFingerprintByName(category, family, name, fingerprint) {
        this.replaceFingerprintByNameAsync(category, family, name, fingerprint)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a fingerprint by name. [/fingerprint/{category}/{family}/{name}]
    * @param {string} category The fingerprint category.
    * @param {string} family The fingerprint family.
    * @param {string} name The fingerprint name.
    * @returns {Promise}
    */
    deleteFingerprintByNameAsync(category, family, name) {
        return new Promise((resolve, reject) => {

            if (!category) {
                reject(new Error('You must specify a category.'));
                return;
            }

            if (!family) {
                reject(new Error('You must specify a family.'));
                return;
            }

            if (!name) {
                reject(new Error('You must specify a name.'));
                return;
            }

            this._baseDeleteAsync(`/fingerprint/${encodeURIComponent(category)}/${encodeURIComponent(family)}/${encodeURIComponent(name)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a fingerprint by name. [/fingerprint/{category}/{family}/{name}]
    * @param {string} category The fingerprint category.
    * @param {string} family The fingerprint family.
    * @param {string} name The fingerprint name.
    * @param {doNext} next The callback function
    */
    deleteFingerprintByName(category, family, name, next) {
        this.deleteFingerprintByNameAsync(category, family, name)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Insights
    ****************************************************************************************/

    /****************************************************************************************
    Insights: Endpoint
    ****************************************************************************************/

    /**
    * Lookup an Insights endpoint by MAC Address. [/insight/endpoint/mac/{mac_Address}]
    * @param {string} macAddress The MAC Address to lookup.
    * @returns {Promise}
    */
    getInsightsByMacAsync(macAddress) {
        return new Promise((resolve, reject) => {

            if (!macAddress) {
                reject(new Error('You must specify a MAC Address.'));
                return;
            }

            this._baseGetAsync(`/insight/endpoint/mac/${encodeURIComponent(macAddress)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Lookup an Insights endpoint by MAC Address. [/insight/endpoint/mac/{mac_Address}]
    * @param {string} macAddress The MAC Address to lookup.
    * @param {doNext} next The callback function
    */
    getInsightsByMac(macAddress, next) {
        this.getInsightsByMacAsync(macAddress)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Lookup an Insights endpoint by IP Address. [/insight/endpoint/ip/{ip_address}]
    * @param {string} ipAddr The ip address to lookup.
    * @returns {Promise}
    */
    getInsightsByIpAsync(ipAddr) {
        return new Promise((resolve, reject) => {

            if (!ipAddr) {
                reject(new Error('You must specify a IP Address.'));
                return;
            }

            this._baseGetAsync(`/insight/endpoint/ip/${encodeURIComponent(ipAddr)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Lookup an Insights endpoint by IP Address. [/insight/endpoint/ip/{ip_address}]
    * @param {string} ipAddr The IP Address to lookup.
    * @param {doNext} next The callback function
    */
    getInsightsByIp(ipAddr, next) {
        this.getInsightsByIpAsync(ipAddr)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Lookup Insights endpoints by IP Address range. [/insight/endpoint/ip-range/{ip_range}]
    * @param {string} ipAddrRange The IP Address range to lookup (e.g. 192.168.1.1-255).
    * @returns {Promise}
    */
    getInsightsByIpRangeAsync(ipAddrRange) {
        return new Promise((resolve, reject) => {

            if (!ipAddrRange) {
                reject(new Error('You must specify an IP Address range.'));
                return;
            }

            this._baseGetAsync(`/insight/endpoint/ip-range/${encodeURIComponent(ipAddrRange)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Lookup Insights endpoints by IP Address range. [/insight/endpoint/ip-range/{ip_range}]
    * @param {string} ipAddrRange The IP Address range to lookup (e.g. 192.168.1.1-255).
    * @param {doNext} next The callback function
    */
    getInsightsByIpRange(ipAddrRange, next) {
        this.getInsightsByIpRangeAsync(ipAddrRange)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Convert a javascript date to a UNIX timestamp.
    * @param {date} date The date to convert to a UNIX timestamp.
    */
    dateToUnixTimestamp(date) {
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

    /**
    * Lookup Insights endpoints by time range. [/insight/endpoint/time-range/{start_time}/{end_time}]
    * @param {string} startTime The start time as a UNIX timestamp.
    * @param {string} endTime The end time as a UNIX timestamp.
    * @returns {Promise}
    */
    getInsightsByTimeRangeAsync(startTime, endTime) {
        return new Promise((resolve, reject) => {

            if (!startTime) {
                reject(new Error('You must specify a start time.'));
                return;
            }

            if (!endTime) {
                reject(new Error('You must specify a end time.'));
                return;
            }

            if (startTime instanceof Date) {
                startTime = self.dateToUnixTimestamp(startTime);
            }

            if (endTime instanceof Date) {
                endTime = self.dateToUnixTimestamp(endTime);
            }

            this._baseGetAsync(`/insight/endpoint/time-range/${encodeURIComponent(startTime)}/${encodeURIComponent(endTime)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Lookup Insights endpoints by time range. [/insight/endpoint/time-range/{start_time}/{end_time}]
    * @param {string} startTime The start time as a UNIX timestamp.
    * @param {string} endTime The end time as a UNIX timestamp.
    * @param {doNext} next The callback function
    */
    getInsightsByTimeRange(startTime, endTime, next) {
        this.getInsightsByTimeRangeAsync(startTime, endTime)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Network
    ****************************************************************************************/

    /****************************************************************************************
    Network: Network Device
    ****************************************************************************************/
    /**
    * Get a list of network devices. [/network-device]
    * @param {searchOptions} options - The options for the netork device search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getNetworkDevicesAsync(options) {
        return this._baseGetLookupAsync(`/network-device`, options);
    }

    /**
    * Get a list of network devices. [/network-device]
    * @param {searchOptions} options - The options for the netork device search (filter, sort, offset, limit)
    * @param {doNext} next - The callback function
    */
    getNetworkDevices(options, next) {
        this.getNetworkDevicesAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Create a new network device. [/network-device]
    * @param {NetworkDevice} device The network device details.
    * @returns {Promise}
    */
    createNetworkDeviceAsync(device) {
        return this._basePostAsync(`/network-device`, null, device);
    }

    /**
    * Create a new network device. [/network-device]
    * @param {NetworkDevice} device The network device details.
    * @param {doNext} next The callback function.
    */
    createNetworkDevice(device, next) {
        this.createNetworkDeviceAsync(device)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get the details of a network device. [/network-device/{id}]
    * @param {number} deviceId The network device id.
    * @returns {Promise}
    */
    getNetworkDeviceAsync(deviceId) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must specify a Device ID.'));
                return;
            }

            this._baseGetAsync(`/network-device/${encodeURIComponent(deviceId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get the details of a network device. [/network-device/{id}]
    * @param {number} deviceId The network device id.
    * @param {doNext} next The callback function.
    */
    getNetworkDevice(deviceId, next) {
        this.getNetworkDeviceAsync(deviceId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a network device. [/network-device/{id}]
    * @param {number} deviceId The network device id.
    * @param {NetworkDevice} device The device options.
    * @returns {Promise}
    */
    updateNetworkDeviceAsync(deviceId, device) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must specify a Device ID.'));
                return;
            }

            this._basePatchAsync(`/network-device/${encodeURIComponent(deviceId)}`, null, device)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a network device. [/network-device/{id}]
    * @param {number} deviceId The network device id.
    * @param {NetworkDevice} device The device options.
    * @param {doNext} next The callback function.
    */
    updateNetworkDevice(deviceId, device, next) {
        this.updateNetworkDeviceAsync(deviceId, device)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a network device. [/network-device/{id}]
    * @param {number} deviceId The network device id.
    * @param {NetworkDevice} device The device options.
    * @returns {Promise}
    */
    replaceNetworkDeviceAsync(deviceId, device) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must specify a Device ID.'));
                return;
            }

            this._basePutAsync(`/network-device/${encodeURIComponent(deviceId)}`, null, device)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a network device. [/network-device/{id}]
    * @param {number} deviceId The network device id.
    * @param {NetworkDevice} device The device options.
    * @param {doNext} next The callback function.
    */
    replaceNetworkDevice(deviceId, device, next) {
        this.replaceNetworkDeviceAsync(deviceId, device)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a network device. [/network-device/{id}]
    * @param {number} deviceId The network device id.
    * @returns {Promise}
    */
    deleteNetworkDeviceAsync(deviceId) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must specify a Device ID.'));
                return;
            }

            this._baseDeleteAsync(`/network-device/${encodeURIComponent(deviceId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a network device. [/network-device/{id}]
    * @param {number} deviceId The network device id.
    * @param {doNext} next The callback function.
    */
    deleteNetworkDevice(deviceId, next) {
        this.deleteNetworkDeviceAsync(deviceId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get the details of a network device. [/network-device/name/{name}]
    * @param {string} deviceName The network device name.
    * @returns {Promise}
    */
    getNetworkDeviceByNameAsync(deviceName) {
        return new Promise((resolve, reject) => {

            if (!deviceName) {
                reject(new Error('You must specify a Device Name.'));
                return;
            }

            this._baseGetAsync(`/network-device/name/${encodeURIComponent(deviceName)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get the details of a network device. [/network-device/name/{name}]
    * @param {string} deviceName The network device name.
    * @param {doNext} next The callback function.
    */
    getNetworkDeviceByName(deviceName, next) {
        this.getNetworkDeviceByNameAsync(deviceName)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a network device. [/network-device/name/{name}]
    * @param {string} deviceName The network device name.
    * @param {NetworkDevice} device The device options.
    * @returns {Promise}
    */
    updateNetworkDeviceByNameAsync(deviceName, device) {
        return new Promise((resolve, reject) => {

            if (!deviceName) {
                reject(new Error('You must specify a Device Name.'));
                return;
            }

            this._basePatchAsync(`/network-device/name/${encodeURIComponent(deviceName)}`, null, device)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a network device. [/network-device/name/{name}]
    * @param {string} deviceName The network device name.
    * @param {NetworkDevice} device The device options.
    * @param {doNext} next The callback function.
    */
    updateNetworkDeviceByName(deviceName, device, next) {
        this.updateNetworkDeviceByNameAsync(deviceName, device)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Replace a network device. [/network-device/name/{name}]
    * @param {string} deviceName The network device name.
    * @param {NetworkDevice} device The device options.
    * @returns {Promise}
    */
    replaceNetworkDeviceByNameAsync(deviceName, device) {
        return new Promise((resolve, reject) => {

            if (!deviceName) {
                reject(new Error('You must specify a Device Name.'));
                return;
            }

            this._basePutAsync(`/network-device/name/${encodeURIComponent(deviceName)}`, null, device)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Replace a network device. [/network-device/name/{name}]
    * @param {string} deviceName The network device name.
    * @param {NetworkDevice} device The device options.
    * @param {doNext} next The callback function.
    */
    replaceNetworkDeviceByName(deviceName, device, next) {
        this.replaceNetworkDeviceByNameAsync(deviceName, device)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a network device. [/network-device/name/{name}]
    * @param {string} deviceName The network device name.
    * @returns {Promise}
    */
    deleteNetworkDeviceByNameAsync(deviceName) {
        return new Promise((resolve, reject) => {

            if (!deviceName) {
                reject(new Error('You must specify a Device Name.'));
                return;
            }

            this._baseDeleteAsync(`/network-device/name/${encodeURIComponent(deviceName)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a network device. [/network-device/name/{name}]
    * @param {string} deviceName The network device name.
    * @param {doNext} next The callback function.
    */
    deleteNetworkDeviceByName(deviceName, next) {
        this.deleteNetworkDeviceByNameAsync(deviceName)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Onboard
    ****************************************************************************************/

    /****************************************************************************************
    Onboard: Certificate
    ****************************************************************************************/

    /**
    * Search for certificates. [/certificate]
    * @param {searchOptions} options The options for the certificate search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getCertificates(options) {
        return this._baseGetLookupAsync(`/certificate`, options);
    }

    /**
    * Search for certificates. [/certificate]
    * @param {searchOptions} options The options for the certificate search (filter, sort, offset, limit)
    * @param {doNext} next The callback function
    */
    getCertificates(options, next) {
        this.getCertificatesAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a certificate. [/certificate/{id}]
    * @param {number} certId The certificate id.
    * @returns {Promise}
    */
    getCertificateAsync(certId) {
        return new Promise((resolve, reject) => {

            if (!certId) {
                reject(new Error('You must specify Certificate ID.'));
                return;
            }

            this._baseGetAsync(`/certificate/${encodeURIComponent(certId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a certificate. [/certificate/{id}]
    * @param {number} certId The certificate id.
    * @param {doNext} next The callback function
    */
    getCertificate(certId, next) {
        this.getCertificateAsync(certId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a certificate. [/certificate/{id}]
    * @param {number} certId The certificate id.
    * @returns {Promise}
    */
    deleteCertificateAsync(certId) {
        return new Promise((resolve, reject) => {

            if (!certId) {
                reject(new Error('You must enter a Certificate ID.'));
                return;
            }

            this._baseDeleteAsync(`/certificate/${encodeURIComponent(certId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a certificate. [/certificate/{id}]
    * @param {number} certId The certificate id.
    * @param {doNext} next The callback function
    */
    deleteCertificate(certId, next) {
        this.deleteCertificateAsync(certId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }


    /**
    * Get a certificate and its trust chain. [/certificate/{id}/chain]
    * @param {number} certId The certificate id.
    * @returns {Promise}
    */
    getCertificateTrustChainAsync(certId) {
        return new Promise((resolve, reject) => {

            if (!certId) {
                reject(new Error('You must enter a Certificate ID.'));
                return;
            }

            this._baseGetAsync(`/certificate/${encodeURIComponent(certId)}/chain`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a certificate and its trust chain. [/certificate/{id}/chain]
    * @param {number} certId The certificate id.
    * @param {doNext} next The callback function
    */
    getCertificateTrustChain(certId, next) {
        this.getCertificateTrustChainAsync(certId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Onboard: Device
    ****************************************************************************************/

    /**
    * Search for devices. [/onboard/device]
    * @param {searchOptions} options The options for the device search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getOnboardDevicesAsync(options) {
        return this._baseGetLookupAsync(`/onboard/device`, options);
    }

    /**
    * Search for devices. [/onboard/device]
    * @param {searchOptions} options The options for the device search (filter, sort, offset, limit)
    * @param {doNext} next The callback function
    */
    getOnboardDevices(options, next) {
        this.getOnboardDevicesAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a device. [/onboard/device/{id}]
    * @param {number} deviceId The device id.
    * @returns {Promise}
    */
    getOnboardDeviceAsync(deviceId) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must enter a Device ID.'));
                return;
            }

            this._baseGetAsync(`/onboard/device/${encodeURIComponent(deviceId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a device. [/onboard/device/{id}]
    * @param {number} deviceId The device id.
    * @param {doNext} next The callback function
    */
    getOnboardDevice(deviceId, next) {
        this.getOnboardDeviceAsync(deviceId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a device. [/onboard/device/{id}]
    * @param {number} deviceId The device id.
    * @param {OnboardDevice} options The device options.
    * @returns {Promise}
    */
    updateOnboardDeviceAsync(deviceId, options) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must enter a Device ID.'));
                return;
            }

            this._basePatchAsync(`/onboard/device/${encodeURIComponent(deviceId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a device. [/onboard/device/{id}]
    * @param {number} deviceId The device id.
    * @param {OnboardDevice} options The device options.
    * @param {doNext} next The callback function
    */
    updateOnboardDevice(deviceId, options, next) {
        this.updateOnboardDeviceAsync(deviceId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a device. [/onboard/device/{id}]
    * @param {number} deviceId The device id.
    * @returns {Promise}
    */
    deleteOnboardDeviceAsync(deviceId) {
        return new Promise((resolve, reject) => {

            if (!deviceId) {
                reject(new Error('You must enter a Device ID.'));
                return;
            }

            this._baseDeleteAsync(`/onboard/device/${encodeURIComponent(deviceId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a device. [/onboard/device/{id}]
    * @param {number} deviceId The device id.
    * @param {doNext} next The callback function
    */
    deleteOnboardDevice(deviceId, next) {
        this.deleteOnboardDeviceAsync(deviceId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Onboard: User
    ****************************************************************************************/

    /**
    * Search for users. [/user]
    * @param {searchOptions} options The options for the user search (filter, sort, offset, limit)
    * @returns {Promise}
    */
    getOnboardUserAsync(options) {
        return this._baseGetLookupAsync(`/user`, options);
    }

    /**
    * Search for users. [/user]
    * @param {searchOptions} options The options for the user search (filter, sort, offset, limit)
    * @param {doNext} next The callback function
    */
    getOnboardUser(options, next) {
        this.getOnboardUserAsync(options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Get a user. [/user/{id}]
    * @param {number} userId The user id.
    * @returns {Promise}
    */
    getOnboardUserAsync(userId) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must enter a User ID.'));
                return;
            }

            this._baseGetAsync(`/user/${encodeURIComponent(userId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Get a user. [/user/{id}]
    * @param {number} userId The user id.
    * @param {doNext} next The callback function
    */
    getOnboardUser(userId, next) {
        this.getOnboardUserAsync(userId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Update a user. [/user/{id}]
    * @param {number} userId The user id.
    * @param {OnboardUser} options The user options.
    * @returns {Promise}
    */
    updateOnboardUserAsync(userId, options) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must enter a User ID.'));
                return;
            }

            this._basePatchAsync(`/user/${encodeURIComponent(userId)}`, null, options)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Update a user. [/user/{id}]
    * @param {number} userId The user id.
    * @param {OnboardUser} options The user options.
    * @param {doNext} next The callback function
    */
    updateOnboardUser(userId, options, next) {
        this.updateOnboardUserAsync(userId, options)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /**
    * Delete a user. [/user/{id}]
    * @param {number} userId The user id.
    * @returns {Promise}
    */
    deleteOnboardUserAsync(userId) {
        return new Promise((resolve, reject) => {

            if (!userId) {
                reject(new Error('You must enter a User ID.'));
                return;
            }

            this._baseDeleteAsync(`/user/${encodeURIComponent(userId)}`, null)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Delete a user. [/user/{id}]
    * @param {number} userId The user id.
    * @param {doNext} next The callback function
    */
    deleteOnboardUser(userId, next) {
        this.deleteOnboardUserAsync(userId)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }

    /****************************************************************************************
    Legacy: Profiler API
    ****************************************************************************************/

    /**
    * Submit an Endpoint to the profiling system. (Uses Legacy APIs) [/async_netd/deviceprofiler/endpoints]
    * @param {DeviceProfile} endpointInfo The user id.
    * @returns {Promise}
    */
    profileEndpointAsync(endpointInfo) {
        return new Promise((resolve, reject) => {

            if (!endpointInfo) {
                reject(new Error('You must enter endpoint information.'));
                return;
            }

            this._baseLegacyActionAsync(`/async_netd/deviceprofiler/endpoints`, 'POST', null, endpointInfo)
                .then((resp) => resolve(resp))
                .catch((e) => reject(e));
        });
    }

    /**
    * Submit an Endpoint to the profiling system. (Uses Legacy APIs)
    * @param {DeviceProfile} endpointInfo The user id.
    * @param {doNext} next The callback function
    */
    profileEndpoint(endpointInfo, next) {
        this.profileEndpointAsync(endpointInfo)
            .then((resp) => {
                next(null, resp.data, resp.status);
            })
            .catch((e) => {
                next(e, e.response ? e.response.data : null, e.response ? e.response.status : null);
            });
    }
}

module.exports = ClearPassApi;