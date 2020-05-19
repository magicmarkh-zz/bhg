<##Requires -RunAsAdministrator
[CmdletBinding(DefaultParametersetName="Create")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
	[Alias("url")]
	[String]$PVWAURL,

    [Parameter(Mandatory=$true,HelpMessage="PSCredential file for logging into the CyberArk Vault via API")]
	[Alias("logonCredential")]
    [System.Management.Automation.PSCredential]$logonCred,
    
    [Parameter(Mandatory=$true,HelpMessage="Name of target dependency to be managed.")]
    [String]$tgtDependencyName,

    [Parameter(Mandatory=$true,HelpMessage="Type of dependency to be managed(IIS Application Pool, Windows Service).")]
    [String]$dependencyType,

    [Parameter(Mandatory=$true,HelpMessage="Address of system where service account is configured")]
	[Alias("svcAddress")]
    [String]$serviceAddress,

    [Parameter(Mandatory=$true,HelpMessage="Type of platform being managed(Windows Server Local, Windows Desktop Local, Windows Domain, Unix, Unix SSH Key, AWS, AWS Access Keys) ")]
	[String]$platformType,

    [Parameter(Mandatory=$true,HelpMessage="Username to be vaulted")]
	[Alias("usrName")]
	[String]$username,
    
    [Parameter(Mandatory=$true,HelpMessage="Address of account to be vaulted")]
	[Alias("acctAddress")]
    [String]$address,
    
    [Parameter(Mandatory=$false,HelpMessage="Location of log file, default is c:\tmp\logs\AddDependency.log")]
    [String]$logfile = "c:\tmp\logs\AddDependency\AddDependency.log"
)#>


$PVWAURL = $octopus_pvwa_uri #base url of priv cloud
$password = ConvertTo-SecureString $octopus_cybr_api_password -AsPlainText -Force #password of api account
$logonCred = New-Object System.Management.Automation.PSCredential ($octopus_cybr_api_username, $password)  #username of api account 
$tgtDependencyName = $octopus_dependency_name  #name of iis app pool
$serviceAddress = $octopus_target_server #fqdn of machine where app is deployed
$platformType = "Windows Domain" #leave this alone
$username = $octopus_svc_username #username of account (not fqdn)
$address = $octopus_domain_address #domain address of acct 
$logfile = $octopus_log_location #"c:\tmp\logs\AddDependency\AddDependency.log"
$dependencyType = $octopus_dependency_type #"Windows Service, IIS Application Pool"

#region Functions
Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG")]
        [String]
        $Level = "INFO",

        [Parameter(Mandatory = $True)]
        [string]
        $Message,

        [Parameter(Mandatory = $False)]
        [string]
        $logfile
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If ($logfile) {
        Add-Content $logfile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}

function Exit-WithLogEntry ($level, $closeSession, $msg) {
    Write-Log -Level $level -logfile $logfile -Message $msg
    Write-Log -Level INFO -logfile $logfile -Message "Exiting early due to error."
    Write-Host "Error. Please check logs at $logfile for more details." 
    if ($closeSession) { Close-PASSession }
    exit
}

#endregion Functions

#region pre-reqs

#create the logfile if it doesn't exist
if (!(Test-Path $logfile)) {
    New-Item -Path $logfile -ItemType File -Force | Out-Null
}

#log entry to start script
Write-Log -Level INFO -logfile $logfile -Message "Beginning dependency assignment task."



#check to see if psPAS is installed
if (Get-Module -ListAvailable -Name psPAS) {
    Write-Log -Level INFO -logfile $logfile -Message "psPAS Module exists, continuing installation."
}
else {
    try {
        Install-Module -Name psPAS -Force -Scope CurrentUser
    }
    catch {
        Exit-WithLogEntry -level ERROR -closeSession $false -msg "Could not install psPAS module: $($_.Exception.Message)"
    }
}

#if setting Windows Service Account, PowerShell version 6 required
if ($dependencyType -eq "Windows Service") {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        Exit-WithLogEntry -level ERROR -closeSession $false -msg "PowerShell major version must be at least 6 to set Windows Service. Please update PowerShell to at least version 6."
    }  
}
elseif ($PSVersionTable.PSVersion.Major -lt 5){
    Exit-WithLogEntry -level ERROR -closeSession $false -msg "PowerShell major version must be at least 5. Please update PowerSehll to at least version 5"
}

#if setting IIS App Pool credential, check for Web Administration module
if ($dependencyType -eq "IIS Application Pool") {
    if (Get-Module -ListAvailable -Name WebAdministration) {
        Write-Log -Level INFO -logfile $logfile -Message "Web Administrations Module exists, continuing installation."
    }
    else {
        try {
            Import-Module -Name WebAdministration -UseWindowsPowerShell
        }
        catch {
            Exit-WithLogEntry -level ERROR -closeSession $false -msg "Could not install Web Administration Module: $($_.Exception.Message)"
        }
    }
}

#endregion pre-reqs

#establish session to the vault
try {
    New-PASSession -Credential $logonCred -BaseURI $PVWAURL
    Write-Log -Level INFO -logfile $logfile -Message "Session to vault established with user $($logonCred.username)"
}
catch {
    Exit-WithLogEntry -level ERROR -closeSession $false -msg "Could not establish session to vault with user $($logonCred.username): $($_.Exception.Message)"
}


#Retrieve vaulted account information
try {
    $vaultedAcct = Get-PasAccount -keyword "$username $address"
    if ($null -eq $vaultedAcct) {
        Exit-WithLogEntry -level WARN -closeSession $true -msg "Account $($username)@$($address) not found. Will not continue."
    }
    else {
        Write-Log -Level INFO -logfile $logfile -Message "Successfully retrieved account $($username)@$($address) from vault."
    }

}
catch {
    Exit-WithLogEntry -level ERROR -closeSession $true -msg "Error retrieving account $($username)@$($address): $($_.Exception.Message)"
}

#add dependencies for account
try {
    $dependancy = @()
    $dependancy += @{
        "name"    = $tgtDependencyName
        "address" = $serviceAddress
        "type"    = $platformType
    }
    Add-PASDiscoveredAccount -userName $username -address $address -Dependencies $dependancy -discoveryDate (Get-Date) -AccountEnabled $true -platformType $platformType 
    Write-Log -Level INFO -logfile $logfile -Message "$($platformType) dependency added for $($username)@$($address)."
}
catch {
    Exit-WithLogEntry -level ERROR -closeSession $true -msg "Error adding $($platformType) dependency for account $($username)@$($address): $($_.Exception.Message)"
}

#set account to allow automatic management
try {
    Set-PASAccount -AccountID $vaultedAcct.AccountID -op replace -path /secretManagement/automaticManagementEnabled -value $true | Out-Null
    Write-Log -Level INFO -logfile $logfile -Message "Account $($username)@$($address) set for automatic management."
}
catch {
    Exit-WithLogEntry -level ERROR -closeSession $true -msg "Error setting account $($username)@$($address) for automatic management: $($_.Exception.Message)"
}

try {
    #set account to reconcile
    Invoke-PASCPMOperation -AccountID $vaultedAcct.AccountID -ReconcileTask | Out-Null
    Write-Log -Level INFO -logfile $logfile -Message "Account $($vaultedAcct.Name) set for immediate reconciliation."
}
catch {
    Exit-WithLogEntry -level ERROR -closeSession $true -msg "Error setting account $($vaultedAcct.AccountID) for automatic management: $($_.Exception.Message)"
}

#loop that checks for successful credential change before executing service account credential change
try {
    $reconciled = $false
    do {
        #wait 30 seconds to give CPM time to change password
        Write-Log -Level INFO -logfile $logfile -Message "Waiting 30 seconds to query the vault"
        Start-Sleep -Seconds 30

        #get the current time
        $currentDateTime = Get-Date
    
        #get the latest log entry for the account
        $logResults = Get-PASAccountActivity -AccountID $vaultedAcct.AccountID | Select-Object -first 1

        #set a variable for time difference. Vault only writes in GMT, so convert current time to GMT
        $timeDifference = New-TimeSpan -Start $currentDateTime.ToUniversalTime() -End $logResults.Time
    
        #look for a successful reconcile less than 90 seconds old
        if ($timeDifference.Days -eq 0 -and $timeDifference.Hours -eq 0 -and $timeDifference.Seconds -le 90 -and $logResults.Activity -eq "CPM Reconcile Password") {
            #get service account password and convert to PS credential
            $svcPassword = (Get-PASAccountPassword -id $vaultedAcct.AccountID).ToSecureString()
            $svcLogonCred = New-Object System.Management.Automation.PSCredential ("$($vaultedAcct.username)@$($vaultedAcct.address)", $svcPassword)

            if ($dependencyType -eq "Windows Service") {
                #apply new credentials to the service
                Set-Service -Name $tgtDependencyName -Credential $svcLogonCred -ErrorAction Stop
                Write-Log -Level INFO -logfile $logfile -Message "$tgtDependencyName credentials successfully updated."

                #restart the service with new credentials
                Restart-Service $tgtDependencyName -ErrorAction Stop
                Write-Log -Level INFO -logfile $logfile -Message "$tgtDependencyName successfully restarted."
            }
            elseif ($dependencyType -eq "IIS Application Pool") {
                #set the credential
                Set-ItemProperty IIS:\AppPools\$tgtDependencyName -name processModel -Value @{username = "$($vaultedAcct.username)@$($vaultedAcct.address)"; password = "$($svcPassword)"; identitytype = 3 }
                Restart-WebAppPool $tgtDependencyName
            }
            else {
                Exit-WithLogEntry -level ERROR -closeSession $true -msg "Service Type '$($platformType)' not supported at this time. Please submit ER on github repo or check the spelling of the entry."
            }
            #set the switch to true to end the loop
            $reconciled = $true
        }
        else {
            Write-Log -Level INFO -logfile $logfile -Message "Account not yet reconciled, trying again."
        }
    } while ($false -eq $reconciled)

}
catch {
    Exit-WithLogEntry -level ERROR -closeSession $true -msg "Error updating service account credentials: $($_.Exception.Message)"
}

#logoff from vault
Close-PASSession
Write-Log -Level INFO -logfile $logfile -Message "Dependency assignment completed successfully."
Write-Host "Success."