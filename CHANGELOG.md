# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0.0] - 2025-02-26

### Added

* Certificate-based authentication support for Microsoft Entra ID and Exchange Online
* Search functionality to find shared mailboxes by alias, name, email address with wildcard support
* Real-time search data sources for shared mailbox retrieval using Exchange Online cmdlets
* Comprehensive README with detailed setup instructions, form workflow, and API documentation

### Changed

* **BREAKING:** Migrated authentication from secret-based to certificate-based authentication
  * Old variables: `EntraSecret`, `EntraTenantId`, `EntraAppID`, `EntraOrganization`
  * New variables: `EntraIdCertificateBase64String`, `EntraIdCertificatePassword`,`EntraIdAppID`, `EntraIdOrganization`, `EntraIdAppId`
* Data sources refactored:
  * `EXO-Get-Shared-Mailboxes-Wildcard-Name-EmailAddresses` - Improved search using Get-EXORecipient for better performance
* Mailbox deletion logic improved:
  * Search now supports wildcard matching against Name, Alias, PrimarySmtpAddress, and EmailAddresses
  * Delete operation uses Remove-Mailbox with proper confirmation handling
  * Proper error handling and validation during deletion process
* Error handling and logging enhanced with better exception handling and context
* Required API permissions updated to use Exchange.ManageAsApp for mailbox management
* Role assignment changed from "Exchange Recipient Administrator" to "Exchange Administrator"

### Removed

* Legacy authentication method using client secret
* Old global variable structure

### Fixed

* Improved mailbox search performance by using Get-EXORecipient cmdlet
* Enhanced error messages with better context for troubleshooting

## [1.0.0.0] - 2024-02-12

### Added

* Initial release of HelloID-Conn-SA-Full-Exchange-Online-SharedMailboxDelete
* Shared mailbox deletion functionality in Exchange Online
* Form-based mailbox deletion workflow
* Search functionality to locate shared mailboxes by name/alias
