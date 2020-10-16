<#
.SYNOPSIS
	Script to Invoke immediate Windows Update Check and Install

.DESCRIPTION
	The script will force Windows Update client to check for and install Windows Updates according to the computers Windows Update Settings
	If a computer is set to use a specific update server such as WSUS, an online check can be forced using the -ForceOnlineUpdate switch
    You can view the log file in the Temp directory. Default is  C:\Windows\Temp\InvokeWindowsUpdate.log
    You can change the log location using the LogFileLocation parameter.

.PARAMETER RestartOption
    Specify if you want to restart the Machine upon Windows Update installation completion
	"Example: AutoReboot or IgnoreReboot"

.PARAMETER LogFileLocation
    Specify the file path for the log file.
    "Example: C:\Temp\Logs"
	
.PARAMETER ForceOnlineUpdate
	This is a switch that will force the computer to check online for Windows Updates

.EXAMPLE
    .\Invoke-WindowsUpdate.ps1 -RestartOption 'AutoReboot'
#>
[CmdletBinding()]
param
(
    [parameter(Mandatory=$false,HelpMessage="Example: AutoReboot or IgnoreReboot")]
    [ValidateSet('AutoReboot', 'IgnoreReboot')]
    [String]$RestartOption,

    [parameter(Mandatory=$false,HelpMessage="Example: C:\Logs")]
    [System.IO.FileInfo]$LogFileLocation,

    [Switch]$ForceOnlineUpdate
)

# Get Script Start Time and Date
$DateTime = (Get-Date)

# Set Verbose and ErrorAction Preference
$VerbosePreference = 'Continue'
$ErrorActionPreference = 'Stop'

# Create Script Log File
if (!$LogFileLocation)
{
    
    $ScriptLogFilePath = New-Item -Path "$env:TEMP\InvokeWindowsUpdate.log" -ItemType File -Force
    
}
else
{
    $TestPath = Test-Path $LogFileLocation
    {
        if (!$TestPath)
        {
            New-Item -Path $LogFileLocation -ItemType Directory -Force
        }
    }

    $ScriptLogFilePath = New-Item -Path "$LogFileLocation\InvokeWindowsUpdate.log" -ItemType File -Force
}

Add-Content -Path $ScriptLogFilePath -Value "Script Processing Started at $DateTime"

Function Invoke-WindowsUpdate
{
	[CmdletBinding()]	
	Param
	(	
		# Mode options
		[Switch]$AcceptAll,
		[Switch]$AutoReboot,
		[Switch]$IgnoreReboot,
        [Switch]$ForceOnlineUpdate
	)

	# Check for administrative rights, break if not Administrator
	$User = [Security.Principal.WindowsIdentity]::GetCurrent()
	$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

	if(!$Role)
	{
		Write-Warning "To perform some operations you must run Windows PowerShell with Administrator permissions."
        Break
	}	
		
    # Get updates list
	Write-Verbose "Getting updates list"
    Add-Content -Path $ScriptLogFilePath -Value "Getting updates list"
	$objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager" 
		
	Write-Verbose "Create Microsoft.Update.Session object"
    Add-Content -Path $ScriptLogFilePath -Value "Create Microsoft.Update.Session object"
	$SessionObject = New-Object -ComObject "Microsoft.Update.Session" 
		
	Write-Verbose "Create Microsoft.Update.Session.Searcher object"
    Add-Content -Path $ScriptLogFilePath -Value "Create Microsoft.Update.Session.Searcher object"
	$objSearcher = $SessionObject.CreateUpdateSearcher()
    
    # Check the registry for Windows Update settings and set searcher service
    $WindowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $WindowsUpdateAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    if (!($ForceOnlineUpdate))
    {
        $WSUSRegistryValue = (Get-ItemProperty -Path $WindowsUpdatePath -Name WUServer -ErrorAction SilentlyContinue).WUServer
        if ($WSUSRegistryValue)
        {
            Write-Verbose "Computer is set to use WSUS Server $WSUSRegistryValue"
            Add-Content -Path $ScriptLogFilePath -Value "Computer is set to use WSUS Server $WSUSRegistryValue"
            $objSearcher.ServerSelection = 1
        }

        if ([String]::IsNullOrEmpty($WSUSRegistryValue))
        {
            $FeaturedSoftwareRegistryValue = (Get-ItemProperty -Path $WindowsUpdateAUPath -Name EnableFeaturedSoftware -ErrorAction SilentlyContinue).EnableFeaturedSoftware
            if ($FeaturedSoftwareRegistryValue)
            {
                Write-Verbose "Set source of updates to Microsoft Update"
                Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Microsoft Update"
                $serviceName = $null
                foreach ($objService in $objServiceManager.Services) 
                {
	                If($objService.Name -eq "Microsoft Update")
	                {
		                $objSearcher.ServerSelection = 3
		                $objSearcher.ServiceID = $objService.ServiceID
		                $serviceName = $objService.Name
		                Break
	                }
                }
            }
            else
            {
                Write-Verbose "Set source of updates to Windows Update"
                Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Windows Update"
		        $objSearcher.ServerSelection = 2
		        $serviceName = "Windows Update"
            }
        }
    }

    if ($ForceOnlineUpdate)
    {
        $FeaturedSoftwareRegistryValue = (Get-ItemProperty -Path $WindowsUpdateAUPath -Name EnableFeaturedSoftware -ErrorAction SilentlyContinue).EnableFeaturedSoftware
        if ($FeaturedSoftwareRegistryValue)
        {
            Write-Verbose "Set source of updates to Microsoft Update"
            Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Microsoft Update"
            $serviceName = $null
            foreach ($objService in $objServiceManager.Services) 
            {
	            If($objService.Name -eq "Microsoft Update")
	            {
		            $objSearcher.ServerSelection = 3
		            $objSearcher.ServiceID = $objService.ServiceID
		            $serviceName = $objService.Name
		            Break
	            }
            }
        }
        else
        {
            Write-Verbose "Set source of updates to Windows Update"
            Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Windows Update"
		    $objSearcher.ServerSelection = 2
		    $serviceName = "Windows Update"
        }
    }
		
	Write-Verbose "Connecting to $serviceName server. Please wait..."
    Add-Content -Path $ScriptLogFilePath -Value "Connecting to $serviceName server. Please wait..."

	Try
	{
		# Search for updates
        $Search = 'IsInstalled = 0'
        $objResults = $objSearcher.Search($Search)
	}
	Catch
	{
		If($_ -match "HRESULT: 0x80072EE2")
		{
			Write-Warning "Cannot connect to Windows Update server"
            Add-Content -Path $ScriptLogFilePath -Value "Cannot connect to Windows Update server"
		}
		Return
	}

	$objCollectionUpdate = New-Object -ComObject "Microsoft.Update.UpdateColl" 
		
	$NumberOfUpdate = 1
	$UpdatesExtraDataCollection = @{}
	$PreSearchCriteriaUpdatesToDownload = $objResults.Updates.count

	Write-Verbose "Found $($PreSearchCriteriaUpdatesToDownload) Updates in pre search criteria"	
    Add-Content -Path $ScriptLogFilePath -Value "Found $($PreSearchCriteriaUpdatesToDownload) Updates in pre search criteria"	
        
    # Set updates to install variable
    $UpdatesToInstall = $objResults.Updates

	Foreach($Update in $UpdatesToInstall)
	{
		$UpdateAccess = $true
		Write-Verbose "Found Update: $($Update.Title)"
        Add-Content -Path $ScriptLogFilePath -Value "Found Update: $($Update.Title)"
			
		If($UpdateAccess -eq $true)
		{
			# Convert update size so it is readable
			Switch($Update.MaxDownloadSize)
			{
				{[System.Math]::Round($_/1KB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1KB,0))+" KB"; break }
				{[System.Math]::Round($_/1MB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1MB,0))+" MB"; break }  
				{[System.Math]::Round($_/1GB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1GB,0))+" GB"; break }    
				{[System.Math]::Round($_/1TB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1TB,0))+" TB"; break }
				default { $Size = $_+"B" }
			}
		
			# Convert KB Article IDs so it is readable
			If($Update.KBArticleIDs -ne "")    
			{
				$KB = "KB"+$Update.KBArticleIDs
			}
			Else 
			{
				$KB = ""
			}
				
            # Add updates
			$objCollectionUpdate.Add($Update) | Out-Null
			$UpdatesExtraDataCollection.Add($Update.Identity.UpdateID,@{KB = $KB; Size = $Size})

		}
			
		$NumberOfUpdate++
	}
		
	Write-Verbose "Update Search Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Update Search Completed"
		
    $UpdatesToDownload = $objCollectionUpdate.count

	If($UpdatesToDownload -eq 0)
	{
        Write-Verbose 'No updates were found to download'
        Add-Content -Path $ScriptLogFilePath -Value 'No updates were found to download'		
        Return
	}

	Write-Verbose "Found $($UpdatesToDownload) Updates"
    Add-Content -Path $ScriptLogFilePath -Value "Found $($UpdatesToDownload) Updates"
		
	$NumberOfUpdate = 1
			
	$UpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"

	Foreach($Update in $objCollectionUpdate)
	{	
		$Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
		Write-Verbose "Selected Update $($Update.Title)"

		$Status = "Accepted"

		If($Update.EulaAccepted -eq 0)
		{ 
			$Update.AcceptEula() 
		}
			
		Write-Verbose "Adding update to collection"
		$UpdateCollectionObject.Add($Update) | Out-Null

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 2
		}
				
		Add-Content -Path $ScriptLogFilePath -Value $log
				
		$NumberOfUpdate++
	}

	Write-Verbose "Update Selection Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Update Selection Completed"
			
	$AcceptUpdatesToDownload = $UpdateCollectionObject.count
	Write-Verbose "$($AcceptUpdatesToDownload) Updates to Download"
    Add-Content -Path $ScriptLogFilePath -Value "$($AcceptUpdatesToDownload) Updates to Download"
			
	If($AcceptUpdatesToDownload -eq 0)
	{
		Return
	}
			
	Write-Verbose "Downloading updates"
    Add-Content -Path $ScriptLogFilePath -Value "Downloading updates"

	$NumberOfUpdate = 1
	$UpdateDownloadCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl" 

	Foreach($Update in $UpdateCollectionObject)
	{
		Write-Verbose "$($Update.Title) will be downloaded"
        Add-Content -Path $ScriptLogFilePath -Value "$($Update.Title) will be downloaded"

		$TempUpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"
		$TempUpdateCollectionObject.Add($Update) | Out-Null
					
		$Downloader = $SessionObject.CreateUpdateDownloader() 
		$Downloader.Updates = $TempUpdateCollectionObject

		Try
		{
			Write-Verbose "Attempting to download update $($Update.Title)"
            Add-Content -Path $ScriptLogFilePath -Value "Attempting to download update $($Update.Title)"
			$DownloadResult = $Downloader.Download()
		}
		Catch
		{
			If ($_ -match "HRESULT: 0x80240044")
			{
				Write-Warning "Your security policy does not allow a non-administator to perform this task"
			}
					
			Return
		}
				
		Write-Verbose "Check ResultCode"
		Switch -exact ($DownloadResult.ResultCode)
		{
			0   { $Status = "NotStarted" }
			1   { $Status = "InProgress" }
			2   { $Status = "Downloaded" }
			3   { $Status = "DownloadedWithErrors" }
			4   { $Status = "Failed" }
			5   { $Status = "Aborted" }
		}

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 3
		}
				
		Add-Content -Path $ScriptLogFilePath -Value "Update $($log.Title) KB $($log.KB) Size $($log.Size) Download Status $($log.Status)"
				
		If($DownloadResult.ResultCode -eq 2)
		{
			Write-Verbose "$($Update.Title) Downloaded"
            Add-Content -Path $ScriptLogFilePath -Value "$($Update.Title) Downloaded"
			$UpdateDownloadCollectionObject.Add($Update) | Out-Null
		}
				
		$NumberOfUpdate++
				
	}

	Write-Verbose "Downloading Updates Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Downloading Updates Completed"

	$ReadyUpdatesToInstall = $UpdateDownloadCollectionObject.count
	Write-Verbose "Downloaded $($ReadyUpdatesToInstall) Updates to Install"
    Add-Content -Path $ScriptLogFilePath -Value "Downloaded $($ReadyUpdatesToInstall) Updates to Install"
		
	If($ReadyUpdatesToInstall -eq 0)
	{
        Write-Verbose "No Updates are ready to Install"
        Add-Content -Path $ScriptLogFilePath -Value "No Updates are ready to Install"		
        Return
	}

			
	Write-Verbose "Installing updates"
    Add-Content -Path $ScriptLogFilePath -Value "Installing updates"

	$NumberOfUpdate = 1			
	#install updates	
	Foreach($Update in $UpdateDownloadCollectionObject)
	{
		Write-Verbose "Update to install: $($Update.Title)"
        Add-Content -Path $ScriptLogFilePath -Value "Update to install: $($Update.Title)"

		$TempUpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"
		$TempUpdateCollectionObject.Add($Update) | Out-Null
					
		$InstallerObject = $SessionObject.CreateUpdateInstaller()
		$InstallerObject.Updates = $TempUpdateCollectionObject
						
		Try
		{
			Write-Verbose "Attempting to install update"
            Add-Content -Path $ScriptLogFilePath -Value "Attempting to install update"
			$InstallResult = $InstallerObject.Install()
		}
		Catch
		{
			If($_ -match "HRESULT: 0x80240044")
			{
				Write-Warning "Your security policy does not allow a non-administator to perform this task"
                Add-Content -Path $ScriptLogFilePath -Value "Your security policy does not allow a non-administator to perform this task"
			}
			Return
		}
					
		Switch -exact ($InstallResult.ResultCode)
		{
			0   { $Status = "NotStarted"}
			1   { $Status = "InProgress"}
			2   { $Status = "Installed"}
			3   { $Status = "InstalledWithErrors"}
			4   { $Status = "Failed"}
			5   { $Status = "Aborted"}
		}

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 4
		}
		
        Add-Content -Path $ScriptLogFilePath -Value "Update $($log.Title) KB $($log.KB) Size $($log.Size) Install Status $($log.Status)"
		$NumberOfUpdate++
	}

	Write-Verbose "Installing updates Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Installing updates Completed"
}

Try
{
	$SystemInfoObject = New-Object -ComObject "Microsoft.Update.SystemInfo"	
	If($SystemInfoObject.RebootRequired)
	{
		Write-Warning "Reboot is required to continue"
		If($RestartOption -eq 'AutoReboot')
		{
			Restart-Computer -Force
		}
				
	}
}
Catch
{
	Write-Warning $_
}

if ($ForceOnlineUpdate)
{
    Invoke-WindowsUpdate -AcceptAll -ForceOnlineUpdate
}
else
{
    Invoke-WindowsUpdate -AcceptAll
}

$DateTime = (Get-Date)
Add-Content -Path $ScriptLogFilePath -Value "Script Processing Completed at $DateTime"

Try
{
	$SystemInfoObject = New-Object -ComObject "Microsoft.Update.SystemInfo"	
	If($SystemInfoObject.RebootRequired)
	{
		Write-Warning "Reboot is required to continue"
		If($RestartOption -eq 'AutoReboot')
		{
			Restart-Computer -Force
		}
				
	}
}
Catch
{
	Write-Warning $_
}