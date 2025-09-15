<#
.SYNOPSIS
    Standalone Windows 11 Compatibility Assessment Tool for VMware vCenter
    
.DESCRIPTION
    Performs Windows 11 compatibility assessment on VMs without making any changes.
    Can assess single VMs or multiple VMs from CSV file.
    Generates detailed HTML and CSV reports.
    
.EXAMPLE
    .\Assess-Win11Compatibility.ps1 -MachineName "VM001" -vCenterServer "vcenter.domain.com" -vCenterAdminUser "administrator@vsphere.local" -WindowsDomainUser "DOMAIN\admin"
    
.EXAMPLE
    .\Assess-Win11Compatibility.ps1 -CSV "VMs.csv" -vCenterServer "vcenter.domain.com" -vCenterAdminUser "administrator@vsphere.local" -WindowsDomainUser "DOMAIN\admin"
    
.NOTES
    Version: 1.0.0
    This script ONLY performs assessment - no changes are made to VMs
#>

#requires -Version 5.1

param(
    [Parameter(Mandatory=$false)]
    [string]$MachineName,
    
    [Parameter(Mandatory=$false)]
    [string]$CSV,
    
    [Parameter(Mandatory=$true)]
    [string]$vCenterServer,
    
    [Parameter(Mandatory=$true)]
    [string]$vCenterAdminUser,
    
    [Parameter(Mandatory=$true)]
    [string]$WindowsDomainUser,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputCSV = "Win11_Compatibility_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputHTML = "Win11_Compatibility_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipHTMLReport,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowGridView
)

# Import required VMware modules
try {
    $requiredModules = @(
        'VMware.VimAutomation.Core',
        'VMware.VimAutomation.Common',
        'VMware.VimAutomation.Sdk'
    )
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing $module from PowerShell Gallery..."
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -Confirm:$false
        }
        Import-Module $module -ErrorAction Stop
    }
    
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope User | Out-Null
    Set-PowerCLIConfiguration -ParticipateInCEIP $false -Confirm:$false -Scope User | Out-Null
    
    Write-Host "VMware PowerCLI modules loaded successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to load VMware PowerCLI modules: $_"
    throw
}

# Import the compatibility module
. "$PSScriptRoot\VMware-Win11-CompatibilityModule.ps1"

function Show-Banner {
    $banner = @"

========================================================================
    Windows 11 VMware Compatibility Assessment Tool
    Version 1.0.0
    
    Based on Win10-build-checker by Kevin Komlosy (AuthorityGate Inc.)
    
    This tool performs READ-ONLY assessment - No changes will be made
========================================================================

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Connect-vCenter {
    param(
        [string]$Server,
        [PSCredential]$Credential
    )
    
    try {
        Write-Host "Connecting to vCenter Server: $Server..." -ForegroundColor Yellow
        Connect-VIServer -Server $Server -Credential $Credential -Force:$true -ErrorAction Stop | Out-Null
        Write-Host "Successfully connected to vCenter." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to vCenter: $_"
        return $false
    }
}

function Test-VMWindows10OS {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )
    
    $guestOS = $VM.Guest.OSFullName
    
    if ($guestOS -like "*Windows 10*") {
        return $true
    }
    
    return $false
}

function Assess-VM {
    param(
        [string]$VMName,
        [PSCredential]$WindowsCredential
    )
    
    Write-Host ""
    Write-Host "=" * 60
    Write-Host "Assessing VM: $VMName"
    Write-Host "=" * 60
    
    try {
        # Get VM object
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Check if VM is powered on and VMware Tools is running
        if ($vm.PowerState -ne 'PoweredOn') {
            Write-Warning "VM is not powered on. Cannot perform assessment."
            return @{
                ComputerName = $VMName
                Status = "VM Not Powered On"
                Win11Compatible = "Cannot Assess"
                CompatibilityIssues = "VM must be powered on for assessment"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        if ($vm.Guest.State -ne 'Running') {
            Write-Warning "VMware Tools is not running. Cannot perform assessment."
            return @{
                ComputerName = $VMName
                Status = "VMware Tools Not Running"
                Win11Compatible = "Cannot Assess"
                CompatibilityIssues = "VMware Tools must be running for assessment"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        # Check if this is Windows 10
        if (-not (Test-VMWindows10OS -VM $vm)) {
            Write-Host "VM is not running Windows 10. Guest OS: $($vm.Guest.OSFullName)" -ForegroundColor Yellow
            return @{
                ComputerName = $VMName
                Status = "Not Windows 10"
                GuestOS = $vm.Guest.OSFullName
                Win11Compatible = "N/A - Not Windows 10"
                CompatibilityIssues = "System is not Windows 10"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        Write-Host "Windows 10 detected. Running compatibility assessment..." -ForegroundColor Green
        
        # Run the comprehensive compatibility check
        $result = Test-VMWindows11Compatibility -VM $vm -MachineName $VMName -WindowsDomainCredential $WindowsCredential
        
        if ($result) {
            # Display results
            Write-Host ""
            Write-Host "Assessment Results for $VMName:" -ForegroundColor Cyan
            Write-Host "-" * 40
            Write-Host "OS: $($result.ProductName) $($result.DisplayVersion)"
            Write-Host "Build: $($result.BuildNumber).$($result.UpdateBuildRevision)"
            Write-Host "Architecture: $($result.Architecture)"
            Write-Host ""
            
            # Compatibility status
            $compatColor = switch ($result.Win11Compatible) {
                "Yes" { "Green" }
                "No" { "Red" }
                "VM - Needs Configuration" { "Yellow" }
                default { "Gray" }
            }
            Write-Host "Windows 11 Compatibility: $($result.Win11Compatible)" -ForegroundColor $compatColor
            
            # Show detailed checks
            Write-Host ""
            Write-Host "Compatibility Checks:" -ForegroundColor Cyan
            Write-Host "  License: $(if ($result.IsLicensed) { '[PASS]' } else { '[FAIL]' }) $($result.LicenseStatusText)"
            Write-Host "  TPM 2.0: $(if ($result.TPMVersion -match '2\.0') { '[PASS]' } else { '[FAIL]' }) Version $($result.TPMVersion)"
            Write-Host "  UEFI: $(if ($result.UEFIMode -eq 'Yes') { '[PASS]' } else { '[FAIL]' })"
            Write-Host "  Secure Boot: $(if ($result.SecureBootEnabled -eq 'Yes') { '[PASS]' } else { '[WARN]' })"
            Write-Host "  CPU: $(if ($result.CPUCompatible) { '[PASS]' } else { '[FAIL]' }) $($result.CPUName)"
            Write-Host "  RAM: $(if ($result.RAMSufficient -eq 'Yes') { '[PASS]' } else { '[FAIL]' }) $($result.TotalMemoryGB) GB"
            Write-Host "  Storage: $(if ($result.StorageSufficient -eq 'Yes') { '[PASS]' } else { '[FAIL]' }) $($result.SystemDriveTotalGB) GB"
            
            if ($result.IsVirtualMachine) {
                Write-Host ""
                Write-Host "VM Type: $($result.VMType)" -ForegroundColor Cyan
                if ($result.VMConfigurationNeeded -and $result.VMConfigurationNeeded -ne "No additional VM configuration needed") {
                    Write-Host "VM Configuration Needed:" -ForegroundColor Yellow
                    $configs = $result.VMConfigurationNeeded -split ';'
                    foreach ($config in $configs) {
                        Write-Host "  - $($config.Trim())" -ForegroundColor Yellow
                    }
                }
            }
            
            # Check for virtual TPM in VMware
            try {
                $vmView = $vm | Get-View
                $tpmDevice = $vmView.Config.Hardware.Device | Where-Object { $_.GetType().Name -eq 'VirtualTPM' }
                $hasVMwareTPM = ($null -ne $tpmDevice)
                
                if (-not $hasVMwareTPM -and $result.TPMVersion -notmatch '2\.0') {
                    Write-Host ""
                    Write-Host "Note: VM does not have a virtual TPM device in VMware." -ForegroundColor Yellow
                    Write-Host "      A vTPM will need to be added before upgrading to Windows 11." -ForegroundColor Yellow
                }
            }
            catch {
                # Ignore errors checking for vTPM
            }
            
            if ($result.CompatibilityIssues -and $result.CompatibilityIssues -ne "None - Ready for Windows 11" -and $result.CompatibilityIssues -ne "None - VM is ready for Windows 11") {
                Write-Host ""
                Write-Host "Issues Found:" -ForegroundColor Yellow
                $issues = $result.CompatibilityIssues -split ';'
                foreach ($issue in $issues) {
                    Write-Host "  - $($issue.Trim())" -ForegroundColor Yellow
                }
            }
            
            if ($result.UpgradeActionRequired -and $result.UpgradeActionRequired -ne "No action required - System is Windows 11 ready" -and $result.UpgradeActionRequired -ne "No action required - VM is Windows 11 ready") {
                Write-Host ""
                Write-Host "Required Actions:" -ForegroundColor Cyan
                $actions = $result.UpgradeActionRequired -split ';'
                foreach ($action in $actions) {
                    Write-Host "  - $($action.Trim())" -ForegroundColor Cyan
                }
            }
            
            return $result
        }
        else {
            Write-Error "Assessment failed for $VMName"
            return @{
                ComputerName = $VMName
                Status = "Assessment Failed"
                Win11Compatible = "Error"
                CompatibilityIssues = "Failed to complete assessment"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    catch {
        Write-Error "Error assessing VM $VMName : $_"
        return @{
            ComputerName = $VMName
            Status = "Error"
            Win11Compatible = "Error"
            CompatibilityIssues = $_.Exception.Message
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}

# Main execution
try {
    Show-Banner
    
    # Validate parameters
    if (-not $MachineName -and -not $CSV) {
        throw "You must specify either -MachineName or -CSV parameter"
    }
    
    if ($MachineName -and $CSV) {
        throw "Please specify either -MachineName or -CSV, not both"
    }
    
    # Get list of machines to assess
    $machinesToAssess = @()
    if ($MachineName) {
        $machinesToAssess += $MachineName
    }
    else {
        if (-not (Test-Path $CSV)) {
            throw "CSV file not found: $CSV"
        }
        
        $csvData = Import-Csv -Path $CSV
        if ($csvData[0].PSObject.Properties.Name -contains 'MachineName') {
            $machinesToAssess = $csvData.MachineName
        }
        elseif ($csvData[0].PSObject.Properties.Name -contains 'ComputerName') {
            $machinesToAssess = $csvData.ComputerName
        }
        else {
            throw "CSV must contain either 'MachineName' or 'ComputerName' column"
        }
    }
    
    Write-Host "Machines to assess: $($machinesToAssess.Count)" -ForegroundColor Cyan
    
    # Connect to vCenter
    $maxAttempts = 3
    $connected = $false
    
    for ($i = 1; $i -le $maxAttempts; $i++) {
        Write-Host ""
        $vCenterCred = Get-Credential -UserName $vCenterAdminUser -Message "Enter vCenter password (Attempt $i of $maxAttempts)"
        
        if (Connect-vCenter -Server $vCenterServer -Credential $vCenterCred) {
            $connected = $true
            break
        }
        
        if ($i -lt $maxAttempts) {
            Write-Warning "Connection failed. Please try again."
            Start-Sleep -Seconds 2
        }
    }
    
    if (-not $connected) {
        throw "Failed to connect to vCenter after $maxAttempts attempts"
    }
    
    # Get Windows credentials
    Write-Host ""
    $windowsCred = Get-Credential -UserName $WindowsDomainUser -Message "Enter Windows domain password for VM assessment"
    
    # Assess each machine
    $results = @()
    $counter = 0
    $totalMachines = $machinesToAssess.Count
    
    foreach ($machine in $machinesToAssess) {
        $counter++
        
        if ($totalMachines -gt 1) {
            Write-Progress -Activity "Assessing Windows 11 Compatibility" `
                          -Status "Processing $machine ($counter of $totalMachines)" `
                          -PercentComplete (($counter / $totalMachines) * 100)
        }
        
        $result = Assess-VM -VMName $machine -WindowsCredential $windowsCred
        $results += $result
    }
    
    if ($totalMachines -gt 1) {
        Write-Progress -Activity "Assessing Windows 11 Compatibility" -Completed
    }
    
    # Export results to CSV
    Write-Host ""
    Write-Host "Exporting results to CSV: $OutputCSV" -ForegroundColor Yellow
    $results | Export-Csv -Path $OutputCSV -NoTypeInformation -Force
    Write-Host "CSV export complete." -ForegroundColor Green
    
    # Generate HTML report
    if (-not $SkipHTMLReport) {
        Write-Host "Generating HTML report: $OutputHTML" -ForegroundColor Yellow
        Export-CompatibilityReportHTML -Results $results -ReportPath $OutputHTML
    }
    
    # Display summary
    Write-Host ""
    Write-Host "=" * 60
    Write-Host "ASSESSMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 60
    
    $compatible = @($results | Where-Object { $_.Win11Compatible -eq "Yes" }).Count
    $incompatible = @($results | Where-Object { $_.Win11Compatible -in @("No", "No - License/Other Issues") }).Count
    $needsConfig = @($results | Where-Object { $_.Win11Compatible -eq "VM - Needs Configuration" }).Count
    $errors = @($results | Where-Object { $_.Win11Compatible -in @("Error", "Cannot Assess") }).Count
    $notWin10 = @($results | Where-Object { $_.Win11Compatible -eq "N/A - Not Windows 10" }).Count
    
    Write-Host "Total VMs Processed: $($results.Count)"
    Write-Host ""
    Write-Host "Ready for Windows 11: $compatible" -ForegroundColor Green
    Write-Host "Not Compatible: $incompatible" -ForegroundColor Red
    Write-Host "VMs Need Configuration: $needsConfig" -ForegroundColor Yellow
    Write-Host "Assessment Errors: $errors" -ForegroundColor Gray
    Write-Host "Not Windows 10: $notWin10" -ForegroundColor Gray
    
    if ($compatible -gt 0 -and $results.Count -gt 0) {
        $percentage = [math]::Round(($compatible / $results.Count) * 100, 1)
        Write-Host ""
        Write-Host "Compatibility Rate: $percentage%" -ForegroundColor Cyan
    }
    
    # Show in GridView if requested
    if ($ShowGridView) {
        Write-Host ""
        Write-Host "Opening results in GridView..." -ForegroundColor Yellow
        $results | Out-GridView -Title "Windows 11 VMware Compatibility Assessment Results"
    }
    
    Write-Host ""
    Write-Host "Assessment complete!" -ForegroundColor Green
    Write-Host "Results saved to:"
    Write-Host "  CSV: $OutputCSV" -ForegroundColor Cyan
    if (-not $SkipHTMLReport) {
        Write-Host "  HTML: $OutputHTML" -ForegroundColor Cyan
    }
}
catch {
    Write-Error "Script execution failed: $_"
    Write-Host ""
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
}
finally {
    # Disconnect from vCenter
    if ($vCenterServer) {
        try {
            if (Get-VIServer -Server $vCenterServer -ErrorAction SilentlyContinue) {
                Disconnect-VIServer -Server $vCenterServer -Force -Confirm:$false
                Write-Host ""
                Write-Host "Disconnected from vCenter." -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Error disconnecting from vCenter: $_"
        }
    }
}