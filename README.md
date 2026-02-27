# HelloID-Conn-SA-Full-Exchange-Online-SharedMailboxDelete

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as organization name, application ID, certificate, etc. You might need to coordinate with the client's application manager before implementing this connector. |

## Description

HelloID-Conn-SA-Full-Exchange-Online-SharedMailboxDelete is a delegated form designed for use with HelloID Service Automation (SA). It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can delete a shared mailbox in Exchange Online. The following options are available:

1. Search and select a shared mailbox (wildcard search by name and email addresses)
2. Delete the selected shared mailbox

## Getting started
### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID App Registration. During the setup process, you'll create a new App Registration in the Entra portal, assign the necessary API permissions, and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:

* [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

* **API Permissions** (Application permissions):
  * `Exchange.ManageAsApp` - To delete and manage shared mailboxes
* **Entra ID Role assignment:**
  * Assign the **Exchange Administrator** role to the App Registration
* **Certificate:**
  * Upload the public key file (.cer) in Entra ID
  * Provide the certificate as a Base64 string in HelloID. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following global variables must be configured in HelloID when importing and configuring the delegated form.

| Variable | Description | Mandatory |
| -------- | ----------- | --------- |
| EntraIdOrganization | The Entra organization name (domain) | Yes |
| EntraIdAppId | The unique identifier (ID) of the App Registration in Microsoft Entra ID | Yes |
| EntraIdCertificateBase64String | The Base64-encoded string representation of the app certificate | Yes |
| EntraIdCertificatePassword | The password associated with the app certificate | Yes |

## Remarks

### Mailbox Search and Deletion

#### Shared Mailbox Search Process

The form includes a search field that retrieves matching shared mailboxes using Exchange Online cmdlets:

1. Search Mailboxes (`Get-EXORecipient` or `Get-Recipient` cmdlet)
   * Mailbox type: Filters by `RecipientTypeDetails = SharedMailbox`
   * Search criteria: Matches against `Name`, `Alias`, `PrimarySmtpAddress`, and `EmailAddresses`
   * Wildcard support: Uses wildcard matching to find partial matches
   * Returns a list of shared mailboxes for selection

#### Shared Mailbox Deletion Process

When the form is submitted, the following process occurs in Exchange Online:

1. Delete Mailbox (`Remove-Mailbox` cmdlet)
   * The script removes the selected shared mailbox using `Remove-Mailbox` with the `Confirm:$false` parameter
   * The mailbox and all associated data are permanently deleted from Exchange Online
   * No data recovery is possible after deletion

## Development resources

### PowerShell Cmdlets

The following PowerShell cmdlets are used by the connector:

| Cmdlet | Description |
| ------ | ----------- |
| Connect-ExchangeOnline | Establish session to Exchange Online using certificate-based app-only authentication |
| Get-Recipient | Search and retrieve recipients to find shared mailboxes |
| Get-EXORecipient | Retrieve recipients from Exchange Online for faster performance |
| Remove-Mailbox | Delete a shared mailbox |
| Disconnect-ExchangeOnline | Close the Exchange Online session |

### Documentation

For more information on the PowerShell cmdlets used in this connector, please refer to:

Exchange Online PowerShell:

* [Exchange Online PowerShell overview](https://learn.microsoft.com/powershell/exchange/exchange-online-powershell)
* [Connect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchange/connect-exchangeonline)
* [Get-Recipient](https://learn.microsoft.com/powershell/module/exchange/get-recipient)
* [Get-EXORecipient](https://learn.microsoft.com/powershell/module/exchange/get-exorecipient)
* [Remove-Mailbox](https://learn.microsoft.com/powershell/module/exchange/remove-mailbox)
* [Disconnect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchange/disconnect-exchangeonline)

## Getting help

💡 **Tip:** For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages.

## HelloID docs

The official HelloID documentation can be found at: [https://docs.helloid.com/](https://docs.helloid.com/)