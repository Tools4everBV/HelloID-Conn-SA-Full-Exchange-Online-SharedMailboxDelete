# Connect to Office 365
try{
    Hid-Write-Status -Event Information -Message "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($ExchangeOnlineAdminUsername, $securePassword)

    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

    Hid-Write-Status -Event Success -Message "Successfully connected to Office 365"
}catch{
    throw "Could not connect to Exchange Online, error: $_"
}

try{
    # Get mailbox permissions
    $permissions = Get-MailboxPermission -Identity $Name | Select-Object User
    
    # Remove AD group which has permissions to mailbox
    foreach($permission in $permissions){
        if($permission.User -like "MBX_*"){
            $adGroupRemove = Remove-ADGroup -Identity $permission.User -Confirm:$false -ErrorAction Stop
            Hid-Write-Status -Message "Removed AD group [$($permission.User)] successfully" -Event Success
            HID-Write-Summary -Message "Removed AD group [$($permission.User)] successfully" -Event Success
        }
    }
    
    # Remove mailbox
    $mailboxRemove = Remove-Mailbox -Identity $Name -Confirm:$false -ErrorAction Stop

    Hid-Write-Status -Message "Removed mailbox [$($Name)] successfully" -Event Success
    HID-Write-Summary -Message "Removed mailbox [$($Name)] successfully" -Event Success
} catch {
    HID-Write-Status -Message "Error removing mailbox [$($Name)]. Error: $($_)" -Event Error
    HID-Write-Summary -Message "Error removing mailbox [$($Name)]" -Event Failed
} finally {
    Hid-Write-Status -Event Information -Message "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Hid-Write-Status -Event Success -Message "Successfully disconnected from Office 365"
}
