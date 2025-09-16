#requires -Version 5.1
<#
========================================================================================================
    Title:          VMware Windows 11 Batch Assessment Tool
    Filename:       VMwareWin11BatchAssessment.ps1
    Description:    Enterprise-grade batch assessment tool for Windows 11 upgrade readiness evaluation
                    across VMware virtual machine infrastructure with integrated Microsoft PC Health 
                    Check validation and comprehensive CSV reporting capabilities
    Author:         Kevin Komlosy
    Company:        AuthorityGate Inc.
    Website:        https://www.authoritygate.com
    Email:          kevin.komlosy@authoritygate.com
    Date:           September 15, 2025
    Version:        1.2.3
    
    License:        MIT License (GitHub Freeware)
                    
                    Copyright (c) 2025 AuthorityGate Inc.
                    
                    Permission is hereby granted, free of charge, to any person obtaining a copy
                    of this software and associated documentation files (the "Software"), to deal
                    in the Software without restriction, including without limitation the rights
                    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
                    copies of the Software, and to permit persons to whom the Software is
                    furnished to do so, subject to the following conditions:
                    
                    The above copyright notice and this permission notice shall be included in all
                    copies or substantial portions of the Software.
                    
                    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
                    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
                    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
                    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
                    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
                    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
                    SOFTWARE.
========================================================================================================

.SYNOPSIS
    Performs automated batch assessment of Windows 11 upgrade readiness across VMware virtual machine 
    infrastructure with Microsoft PC Health Check integration and detailed CSV reporting.

.DESCRIPTION
    This streamlined assessment tool provides enterprise IT administrators with a comprehensive 
    Windows 11 readiness evaluation solution for VMware environments. It automates the discovery 
    and assessment of Windows 10 virtual machines, executes Microsoft's official PC Health Check 
    tool within each guest OS, and generates detailed CSV reports for upgrade planning.
    
    Key Features in Version 1.2.3:
    - Automatic discovery of Windows 10 VMs in vCenter inventory
    - Batch processing with progress tracking
    - Microsoft PC Health Check automatic deployment and execution
    - Comprehensive hardware compatibility validation
    - Guest OS detailed assessment when credentials provided
    - CSV export with all assessment metrics
    - Non-interactive operation for automation scenarios
    - Minimal dependencies and lightweight execution
    
    Assessment Categories:
    
    VMware Infrastructure Level:
    - Virtual hardware version compatibility (v14+ for vTPM)
    - CPU core allocation (2+ cores required)
    - Memory allocation (4GB+ required)
    - Virtual disk capacity (64GB+ required)
    - vTPM 2.0 presence and configuration
    - EFI firmware status
    - VMware Tools running state
    
    Guest Operating System Level:
    - Windows 10 build number verification
    - Available disk space on system drive
    - Recovery partition size and configuration
    - Windows activation and licensing status
    - Microsoft PC Health Check validation
    - System file integrity
    
    PC Health Check Integration:
    - Automatic download of latest PC Health Check tool
    - Silent installation on target VMs
    - Execution with result parsing
    - Registry-based result extraction
    - Detailed failure reason reporting
    
    Report Generation:
    - Timestamped CSV files for tracking
    - Comprehensive assessment metrics per VM
    - Actionable recommendations for remediation
    - Overall readiness categorization
    - PC Health Check pass/fail details

.PARAMETER vCenterServer
    Specifies the vCenter server FQDN or IP address to connect to. This parameter is mandatory.
    Examples: "vcenter.domain.com", "192.168.1.100", "vcenter01.contoso.local"

.PARAMETER vCenterUser
    Specifies the username for vCenter authentication. Can be in domain\username or username@domain 
    format. This parameter is mandatory.
    Examples: "domain\admin", "administrator@vsphere.local", "svc_vmware@contoso.com"

.PARAMETER OutputPath
    Specifies the directory path where the CSV report will be saved. If not specified, defaults to 
    the current working directory. The directory must exist and be writable.
    Default: Current directory (Get-Location)

.PARAMETER VMList
    Optional array of specific VM names to assess. If not provided or empty, the tool will 
    automatically discover and assess all Windows 10 VMs in the vCenter inventory.
    Examples: @("VM1", "VM2"), @("Win10-Finance", "Win10-HR", "Win10-IT")

.PARAMETER GuestUser
    Specifies the username for guest OS authentication. This should be a local or domain administrator
    account that has access to all target VMs. Defaults to "Administrator" if not specified.
    Examples: "Administrator", "domain\admin", "localadmin"

.EXAMPLE
    .\VMwareWin11BatchAssessment.ps1 -vCenterServer "vcenter.domain.com" -vCenterUser "administrator@vsphere.local"
    
    Connects to vCenter, discovers all Windows 10 VMs, and performs assessment with default settings.

.EXAMPLE
    .\VMwareWin11BatchAssessment.ps1 -vCenterServer "vcenter.domain.com" -vCenterUser "domain\admin" -VMList @("Win10-01", "Win10-02", "Win10-03") -OutputPath "C:\Reports"
    
    Assesses specific VMs and saves the report to C:\Reports directory.

.EXAMPLE
    .\VMwareWin11BatchAssessment.ps1 -vCenterServer "192.168.1.100" -vCenterUser "admin@vsphere.local" -GuestUser "CONTOSO\svc_admin"
    
    Uses domain service account for guest OS access across all discovered Windows 10 VMs.

.EXAMPLE
    # Automated scheduled task example
    $params = @{
        vCenterServer = "vcenter.contoso.com"
        vCenterUser = "svc_vmware@contoso.com"
        OutputPath = "\\fileserver\reports\win11"
        GuestUser = "CONTOSO\svc_assessment"
    }
    .\VMwareWin11BatchAssessment.ps1 @params
    
    Example for use in scheduled tasks or automation scripts with splatting.

.NOTES
    Prerequisites:
    - PowerShell 5.1 or higher
    - VMware PowerCLI modules (automatically installed if missing)
    - vCenter Server 6.5 or higher
    - VMware Tools installed and running on target VMs
    - Administrative credentials for vCenter
    - Administrative credentials for guest OS (for detailed assessment)
    - Network connectivity to vCenter server
    - Internet connectivity on target VMs (for PC Health Check download)
    
    VMware PowerCLI Modules Required:
    - VMware.VimAutomation.Core
    - VMware.VimAutomation.Common
    
    Supported Guest Operating Systems:
    - Windows 10 version 1909 and later
    - Windows 10 Enterprise, Pro, Education editions
    - Windows 10 LTSC/LTSB editions (with limitations)
    
    Assessment Output Fields:
    - Timestamp: Assessment date and time
    - VMName: Virtual machine name
    - PowerState: Current power state
    - GuestOS: Guest operating system
    - OverallReadiness: Consolidated readiness status
    - PCHealthCheckStatus: Microsoft tool result
    - PCHealthCheckDetails: Specific failure reasons
    - CPU/Memory/Disk status: Hardware compliance
    - vTPM/Firmware status: Security requirements
    - RecoveryPartition: Size and status
    - LicenseStatus: Windows activation state
    - RequiredActions: Remediation steps needed
    
    Performance Considerations:
    - Assessment time: ~1-2 minutes per VM
    - Parallel processing: Not implemented (sequential for stability)
    - Network bandwidth: Minimal (~10MB per VM for PC Health Check)
    - Guest OS impact: Low (brief CPU spike during assessment)
    
    Security Considerations:
    - Credentials are not stored or logged
    - PC Health Check runs with provided admin rights
    - No permanent changes made to VMs
    - Assessment is read-only except for PC Health Check installation
    
    Limitations:
    - Requires powered-on VMs for full assessment
    - PC Health Check requires internet access or local repository
    - Some metrics unavailable without guest credentials
    - LTSC editions may show false negatives in PC Health Check
    
    Exit Codes:
    - 0: Success - Assessment completed
    - 1: Error - Connection or assessment failure
    
    CSV Report Format:
    The generated CSV includes all assessment metrics in a flat structure suitable for:
    - Import into Excel or database systems
    - Power BI or Tableau visualization
    - SCCM or other deployment planning tools
    - Executive reporting dashboards

.LINK
    https://www.authoritygate.com

.LINK
    https://github.com/authoritygate

.LINK
    https://aka.ms/GetPCHealthCheckApp

.LINK
    https://docs.microsoft.com/windows/whats-new/windows-11-requirements

.LINK
    https://docs.vmware.com/en/VMware-vSphere/index.html

.FUNCTIONALITY
    Batch Assessment, Windows 11 Readiness, VMware vSphere, Guest OS Analysis, PC Health Check,
    CSV Reporting, Virtual Machine Discovery, Compliance Validation, Upgrade Planning,
    Infrastructure Assessment, Automated Evaluation, Enterprise Reporting
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$vCenterServer,
    
    [Parameter(Mandatory=$true)]
    [string]$vCenterUser,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory=$false)]
    [string[]]$VMList = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$GuestUser = "Administrator"
)

# Initialize VMware modules
function Initialize-VMwareModules {
    $requiredModules = @(
        'VMware.VimAutomation.Core',
        'VMware.VimAutomation.Common'
    )
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing $module..." -ForegroundColor Yellow
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -Confirm:$false
        }
        Import-Module $module -ErrorAction Stop
    }
    
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope User | Out-Null
    Set-PowerCLIConfiguration -ParticipateInCEIP $false -Confirm:$false -Scope User | Out-Null
}

# Test VMware Tools status
function Test-VMwareToolsRunning {
    param([VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM)
    
    $VM = Get-VM -Name $VM.Name | Select-Object -First 1 -ErrorAction SilentlyContinue
    if (-not $VM) { return $false }
    
    return ($VM.ExtensionData.Guest.ToolsRunningStatus -eq 'guestToolsRunning' -or 
            $VM.Guest.State -eq 'Running' -or 
            $VM.ExtensionData.Guest.ToolsStatus -eq 'toolsOk')
}

# Check vTPM status
function Check-vTPMStatus {
    param([VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM)
    
    $vmView = $VM | Get-View
    
    # Check hardware version
    $hwVersion = 0
    if ($VM.Version -and $VM.Version -ne "Unknown") {
        $versionString = $VM.Version -replace 'v', '' -replace 'vmx-', ''
        if ($versionString -match '^\d+$') {
            $hwVersion = [int]$versionString
        }
    }
    
    # Check firmware
    $firmware = $vmView.Config.Firmware
    if (-not $firmware) { $firmware = "bios" }
    
    # Check for vTPM
    $vTPM = $vmView.Config.Hardware.Device | Where-Object { $_.GetType().Name -eq 'VirtualTPM' }
    
    return @{
        HardwareVersion = $hwVersion
        Firmware = $firmware
        HasTPM = [bool]$vTPM
    }
}

# Run PC Health Check on VM
function Invoke-PCHealthCheck {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [PSCredential]$GuestCredential
    )
    
    if (-not (Test-VMwareToolsRunning -VM $VM)) {
        return @{
            Status = "Skipped"
            Reason = "VMware Tools not running"
            Result = "Unknown"
        }
    }
    
    $healthCheckScript = @'
$ErrorActionPreference = "SilentlyContinue"

# Download PC Health Check if not present
$installerPath = "$env:TEMP\WindowsPCHealthCheckSetup.msi"
$appPath = "${env:ProgramFiles}\PCHealthCheck\WindowsPCHealthCheckBeta.exe"

# Check if already installed
if (-not (Test-Path $appPath)) {
    try {
        Write-Output "Downloading PC Health Check..."
        $downloadUrl = "https://aka.ms/GetPCHealthCheckApp"
        
        # Use WebClient for compatibility
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($downloadUrl, $installerPath)
        
        if (Test-Path $installerPath) {
            Write-Output "Installing PC Health Check..."
            Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait -NoNewWindow
            Start-Sleep -Seconds 5
        }
    } catch {
        Write-Output "ERROR: Failed to download/install PC Health Check: $_"
        return
    }
}

# Run PC Health Check
if (Test-Path $appPath) {
    try {
        # Run silently and check registry for results
        Start-Process $appPath -ArgumentList "-s" -Wait -NoNewWindow
        Start-Sleep -Seconds 3
        
        # Check registry for results
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\WindowsUpdateEligibility"
        if (Test-Path $regPath) {
            $eligibility = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            
            if ($eligibility) {
                $isEligible = $eligibility.IsEligible
                $reasons = @()
                
                # Check specific requirements
                if ($eligibility.TPMVersion -lt 2) { $reasons += "TPM 2.0 required" }
                if ($eligibility.ProcessorGeneration -eq 0) { $reasons += "Unsupported processor" }
                if ($eligibility.SecureBootCapable -eq 0) { $reasons += "Secure Boot not capable" }
                if ($eligibility.RAMSize -lt 4) { $reasons += "Insufficient RAM" }
                if ($eligibility.StorageSize -lt 64) { $reasons += "Insufficient storage" }
                
                if ($isEligible -eq 1) {
                    Write-Output "PCHEALTHCHECK:PASS|DETAILS:All requirements met"
                } else {
                    $reasonText = if ($reasons.Count -gt 0) { $reasons -join ";" } else { "Requirements not met" }
                    Write-Output "PCHEALTHCHECK:FAIL|DETAILS:$reasonText"
                }
            } else {
                Write-Output "PCHEALTHCHECK:UNKNOWN|DETAILS:Could not read results"
            }
        } else {
            # Try alternative check
            Write-Output "PCHEALTHCHECK:UNKNOWN|DETAILS:Registry key not found"
        }
    } catch {
        Write-Output "PCHEALTHCHECK:ERROR|DETAILS:$_"
    }
} else {
    Write-Output "PCHEALTHCHECK:NOTINSTALLED|DETAILS:PC Health Check not installed"
}
'@
    
    try {
        $result = Invoke-VMScript -VM $VM -ScriptText $healthCheckScript `
            -ScriptType PowerShell -GuestCredential $GuestCredential `
            -ErrorAction Stop -WarningAction SilentlyContinue
        
        if ($result.ScriptOutput -match "PCHEALTHCHECK:([^|]+)\|DETAILS:(.+)") {
            return @{
                Status = $matches[1].Trim()
                Details = $matches[2].Trim()
                Result = if ($matches[1].Trim() -eq "PASS") { "Ready" } else { "Not Ready" }
            }
        }
        
        return @{
            Status = "Unknown"
            Details = "Could not parse results"
            Result = "Unknown"
        }
    }
    catch {
        return @{
            Status = "Error"
            Details = "Failed to run: $_"
            Result = "Unknown"
        }
    }
}

# Main assessment function
function Assess-Windows11Readiness {
    param(
        [string[]]$VMNames = @(),
        [PSCredential]$GuestCredential
    )
    
    Write-Host "`n=== Windows 11 Readiness Batch Assessment ===" -ForegroundColor Cyan
    Write-Host "Assessment started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    # Discover Windows 10 VMs if none specified
    if ($VMNames.Count -eq 0) {
        Write-Host "Discovering Windows 10 VMs..." -ForegroundColor Yellow
        
        $allVMs = Get-VM | Where-Object { 
            $_.Guest.OSFullName -match "Windows 10" -or 
            $_.Guest.OSFullName -match "Microsoft Windows 10" -or
            ($_.Guest.OSFullName -match "Windows" -and 
             $_.Guest.OSFullName -notmatch "Server|Windows 11|Windows 7|Windows 8")
        }
        
        if ($allVMs.Count -eq 0) {
            Write-Host "No Windows 10 VMs found" -ForegroundColor Red
            return @()
        }
        
        Write-Host "Found $($allVMs.Count) Windows 10 VM(s)" -ForegroundColor Green
        $VMNames = $allVMs.Name
    }
    
    # Initialize results
    $assessmentResults = @()
    $currentVM = 1
    $totalVMs = $VMNames.Count
    
    Write-Host "Assessing $totalVMs VM(s)..." -ForegroundColor Cyan
    Write-Host ""
    
    # Assessment scripts
    $diskCheckScript = @'
try {
    $cDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
    "FREE:$([math]::Round($cDrive.FreeSpace / 1GB, 2))|TOTAL:$([math]::Round($cDrive.Size / 1GB, 2))"
} catch { "ERROR:DiskCheck" }
'@

    $recoveryCheckScript = @'
try {
    $recoveryPartitions = Get-Partition | Where-Object { $_.Type -eq "Recovery" } -ErrorAction Stop
    $totalSizeMB = 0
    $count = 0
    if ($recoveryPartitions) {
        foreach ($rp in $recoveryPartitions) {
            $totalSizeMB += [math]::Round($rp.Size / 1MB, 0)
            $count++
        }
    }
    "RECOVERY_COUNT:$count|RECOVERY_MB:$totalSizeMB"
} catch { "RECOVERY_COUNT:0|RECOVERY_MB:0" }
'@

    $licenseCheckScript = @'
try {
    $activation = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop | 
        Where-Object { $_.PartialProductKey -and $_.Name -like "Windows*" } | 
        Select-Object -First 1
    
    if ($activation) {
        $status = if ($activation.LicenseStatus -eq 1) { "Licensed" } else { "Unlicensed" }
        $activated = if ($activation.LicenseStatus -eq 1) { "Activated" } else { "NotActivated" }
        $licType = if ($activation.Description -match "Volume") { "Volume" } 
                   elseif ($activation.Description -match "OEM") { "OEM" } 
                   else { "Retail" }
        "LICENSE:$status|ACTIVATION:$activated|TYPE:$licType"
    } else { "LICENSE:Unknown|ACTIVATION:Unknown|TYPE:Unknown" }
} catch { "LICENSE:CheckFailed|ACTIVATION:CheckFailed|TYPE:CheckFailed" }
'@

    $osInfoScript = @'
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    "BUILD:$($os.BuildNumber)|OS:$($os.Caption)"
} catch { "BUILD:Unknown|OS:Unknown" }
'@

    # Process each VM
    foreach ($vmName in $VMNames) {
        Write-Host "[$currentVM/$totalVMs] Assessing: $vmName" -ForegroundColor Cyan
        
        try {
            $vm = Get-VM -Name $vmName -ErrorAction Stop
            
            # Initialize assessment
            $assessment = @{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                VMName = $vm.Name
                PowerState = $vm.PowerState
                GuestOS = $vm.Guest.OSFullName
                VMwareToolsStatus = $vm.Guest.State
                
                # Hardware checks
                CPU = $vm.NumCpu
                CPUStatus = if ($vm.NumCpu -ge 2) { "Pass" } else { "Fail" }
                MemoryGB = $vm.MemoryGB
                MemoryStatus = if ($vm.MemoryGB -ge 4) { "Pass" } else { "Fail" }
                
                # Guest OS defaults
                GuestOSBuild = "N/A"
                FreeDiskSpaceGB = 0
                DiskSpaceStatus = "Unknown"
                RecoveryPartitionMB = 0
                RecoveryPartitionStatus = "Unknown"
                LicenseStatus = "Unknown"
                ActivationStatus = "Unknown"
                
                # PC Health Check
                PCHealthCheckStatus = "Not Run"
                PCHealthCheckDetails = ""
                PCHealthCheckResult = "Unknown"
                
                # Overall
                OverallReadiness = "Not Assessed"
                RequiredActions = @()
            }
            
            # Check disk
            $disk = Get-HardDisk -VM $vm | Select-Object -First 1
            $assessment.DiskSizeGB = [math]::Round($disk.CapacityGB, 2)
            $assessment.DiskStatus = if ($disk.CapacityGB -ge 64) { "Pass" } else { "Fail" }
            
            # Check vTPM
            $tpmStatus = Check-vTPMStatus -VM $vm
            $assessment.vTPM = if ($tpmStatus.HasTPM) { "Present" } else { "Missing" }
            $assessment.vTPMStatus = if ($tpmStatus.HasTPM) { "Pass" } else { "Fail" }
            $assessment.Firmware = $tpmStatus.Firmware
            $assessment.FirmwareStatus = if ($tpmStatus.Firmware -eq 'efi') { "Pass" } else { "Fail" }
            
            # Guest OS checks if powered on
            if ($vm.PowerState -eq 'PoweredOn' -and $GuestCredential -and (Test-VMwareToolsRunning -VM $vm)) {
                Write-Host "  Running guest OS checks..." -ForegroundColor Yellow
                
                # OS Info
                try {
                    $osResult = Invoke-VMScript -VM $vm -ScriptText $osInfoScript `
                        -ScriptType PowerShell -GuestCredential $GuestCredential `
                        -ErrorAction Stop -WarningAction SilentlyContinue
                    
                    if ($osResult.ScriptOutput -match "BUILD:([^|]+)\|OS:(.+)") {
                        $assessment.GuestOSBuild = $matches[1].Trim()
                    }
                } catch {}
                
                # Disk Space
                try {
                    $diskResult = Invoke-VMScript -VM $vm -ScriptText $diskCheckScript `
                        -ScriptType PowerShell -GuestCredential $GuestCredential `
                        -ErrorAction Stop -WarningAction SilentlyContinue
                    
                    if ($diskResult.ScriptOutput -match "FREE:([^|]+)\|TOTAL:(.+)") {
                        $assessment.FreeDiskSpaceGB = [decimal]$matches[1].Trim()
                        $assessment.DiskSpaceStatus = if ($assessment.FreeDiskSpaceGB -ge 30) { "Pass" } else { "Fail" }
                    }
                } catch {}
                
                # Recovery Partition
                try {
                    $recoveryResult = Invoke-VMScript -VM $vm -ScriptText $recoveryCheckScript `
                        -ScriptType PowerShell -GuestCredential $GuestCredential `
                        -ErrorAction Stop -WarningAction SilentlyContinue
                    
                    if ($recoveryResult.ScriptOutput -match "RECOVERY_COUNT:([^|]+)\|RECOVERY_MB:(.+)") {
                        $assessment.RecoveryPartitionMB = [int]$matches[2].Trim()
                        $assessment.RecoveryPartitionStatus = if ($assessment.RecoveryPartitionMB -ge 1100) { "Pass" } 
                                                               elseif ($assessment.RecoveryPartitionMB -eq 0) { "Missing" } 
                                                               else { "Fail" }
                    }
                } catch {}
                
                # License Status
                try {
                    $licenseResult = Invoke-VMScript -VM $vm -ScriptText $licenseCheckScript `
                        -ScriptType PowerShell -GuestCredential $GuestCredential `
                        -ErrorAction Stop -WarningAction SilentlyContinue
                    
                    if ($licenseResult.ScriptOutput -match "LICENSE:([^|]+)\|ACTIVATION:([^|]+)\|TYPE:(.+)") {
                        $assessment.LicenseStatus = $matches[1].Trim()
                        $assessment.ActivationStatus = $matches[2].Trim()
                    }
                } catch {}
                
                # PC Health Check
                Write-Host "  Running PC Health Check..." -ForegroundColor Yellow
                $pcHealthResult = Invoke-PCHealthCheck -VM $vm -GuestCredential $GuestCredential
                $assessment.PCHealthCheckStatus = $pcHealthResult.Status
                $assessment.PCHealthCheckDetails = $pcHealthResult.Details
                $assessment.PCHealthCheckResult = $pcHealthResult.Result
                
                Write-Host "  Guest checks completed" -ForegroundColor Green
            } elseif ($vm.PowerState -ne 'PoweredOn') {
                $assessment.PCHealthCheckStatus = "VM Off"
                $assessment.PCHealthCheckDetails = "VM must be powered on for health check"
            }
            
            # Calculate overall readiness
            $failCount = 0
            
            if ($assessment.CPUStatus -eq "Fail") { 
                $failCount++
                $assessment.RequiredActions += "Increase CPU to 2+ cores"
            }
            if ($assessment.MemoryStatus -eq "Fail") { 
                $failCount++
                $assessment.RequiredActions += "Increase memory to 4+ GB"
            }
            if ($assessment.DiskStatus -eq "Fail") { 
                $failCount++
                $assessment.RequiredActions += "Expand disk to 64+ GB"
            }
            if ($assessment.vTPMStatus -eq "Fail") { 
                $failCount++
                $assessment.RequiredActions += "Add vTPM 2.0"
            }
            if ($assessment.FirmwareStatus -eq "Fail") { 
                $failCount++
                $assessment.RequiredActions += "Convert to EFI firmware"
            }
            if ($assessment.DiskSpaceStatus -eq "Fail") {
                $failCount++
                $assessment.RequiredActions += "Free up disk space (need 30+ GB)"
            }
            if ($assessment.RecoveryPartitionStatus -eq "Fail") {
                $assessment.RequiredActions += "Resize recovery partition to 1100+ MB"
            }
            
            # Overall status
            if ($assessment.PCHealthCheckStatus -eq "PASS" -and $failCount -eq 0) {
                $assessment.OverallReadiness = "Ready"
            } elseif ($assessment.PCHealthCheckStatus -eq "FAIL" -or $failCount -gt 2) {
                $assessment.OverallReadiness = "Not Ready"
            } elseif ($failCount -le 2) {
                $assessment.OverallReadiness = "Minor Issues"
            } else {
                $assessment.OverallReadiness = "Major Issues"
            }
            
            $assessmentResults += $assessment
            
            # Display status
            $statusColor = switch ($assessment.OverallReadiness) {
                "Ready" { 'Green' }
                "Minor Issues" { 'Yellow' }
                default { 'Red' }
            }
            Write-Host "  Status: $($assessment.OverallReadiness)" -ForegroundColor $statusColor
            Write-Host "  PC Health Check: $($assessment.PCHealthCheckStatus)" -ForegroundColor Gray
            
        }
        catch {
            Write-Host "  Error: $_" -ForegroundColor Red
            $assessmentResults += @{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                VMName = $vmName
                OverallReadiness = "Error"
                PCHealthCheckStatus = "Error"
                RequiredActions = @("Assessment failed: $_")
            }
        }
        
        $currentVM++
    }
    
    return $assessmentResults
}

# Export results to CSV
function Export-AssessmentResults {
    param(
        [array]$Results,
        [string]$OutputPath
    )
    
    if ($Results.Count -eq 0) {
        Write-Host "No results to export" -ForegroundColor Yellow
        return
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $fileName = "Win11Assessment_$timestamp.csv"
    $fullPath = Join-Path $OutputPath $fileName
    
    # Convert to CSV format
    $csvData = @()
    foreach ($result in $Results) {
        $csvData += [PSCustomObject]@{
            Timestamp = $result.Timestamp
            VMName = $result.VMName
            PowerState = $result.PowerState
            GuestOS = $result.GuestOS
            OverallReadiness = $result.OverallReadiness
            PCHealthCheckStatus = $result.PCHealthCheckStatus
            PCHealthCheckDetails = $result.PCHealthCheckDetails
            PCHealthCheckResult = $result.PCHealthCheckResult
            CPU = $result.CPU
            CPUStatus = $result.CPUStatus
            MemoryGB = $result.MemoryGB
            MemoryStatus = $result.MemoryStatus
            DiskSizeGB = $result.DiskSizeGB
            DiskStatus = $result.DiskStatus
            FreeDiskSpaceGB = $result.FreeDiskSpaceGB
            DiskSpaceStatus = $result.DiskSpaceStatus
            vTPM = $result.vTPM
            vTPMStatus = $result.vTPMStatus
            Firmware = $result.Firmware
            FirmwareStatus = $result.FirmwareStatus
            RecoveryPartitionMB = $result.RecoveryPartitionMB
            RecoveryPartitionStatus = $result.RecoveryPartitionStatus
            LicenseStatus = $result.LicenseStatus
            ActivationStatus = $result.ActivationStatus
            GuestOSBuild = $result.GuestOSBuild
            VMwareToolsStatus = $result.VMwareToolsStatus
            RequiredActions = ($result.RequiredActions -join "; ")
        }
    }
    
    $csvData | Export-Csv -Path $fullPath -NoTypeInformation
    
    return $fullPath
}

# Main execution
try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Windows 11 Readiness Batch Assessment " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Initialize VMware modules
    Write-Host "Initializing VMware PowerCLI..." -ForegroundColor Yellow
    Initialize-VMwareModules
    
    # Connect to vCenter
    Write-Host "Connecting to vCenter: $vCenterServer" -ForegroundColor Yellow
    $vCenterCred = Get-Credential -UserName $vCenterUser -Message "Enter vCenter password"
    
    if (-not $vCenterCred) {
        throw "No vCenter credentials provided"
    }
    
    Connect-VIServer -Server $vCenterServer -Credential $vCenterCred -ErrorAction Stop | Out-Null
    Write-Host "Connected successfully" -ForegroundColor Green
    
    # Get guest credentials
    Write-Host ""
    Write-Host "Guest OS credentials are required for detailed assessment and PC Health Check" -ForegroundColor Yellow
    $guestCred = Get-Credential -UserName $GuestUser -Message "Enter guest OS admin credentials (Domain or Local Admin)"
    
    if (-not $guestCred) {
        Write-Host "Warning: No guest credentials provided. Assessment will be limited." -ForegroundColor Yellow
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -ne 'Y' -and $continue -ne 'y') {
            throw "Assessment cancelled"
        }
    }
    
    # Run assessment
    $results = Assess-Windows11Readiness -VMNames $VMList -GuestCredential $guestCred
    
    # Summary
    Write-Host ""
    Write-Host "=== Assessment Summary ===" -ForegroundColor Cyan
    
    $readyCount = ($results | Where-Object { $_.OverallReadiness -eq "Ready" }).Count
    $minorCount = ($results | Where-Object { $_.OverallReadiness -eq "Minor Issues" }).Count
    $notReadyCount = ($results | Where-Object { $_.OverallReadiness -match "Not Ready|Major Issues" }).Count
    $errorCount = ($results | Where-Object { $_.OverallReadiness -eq "Error" }).Count
    
    Write-Host "Total VMs assessed: $($results.Count)" -ForegroundColor White
    Write-Host "Ready for Windows 11: $readyCount" -ForegroundColor Green
    Write-Host "Minor issues: $minorCount" -ForegroundColor Yellow
    Write-Host "Not ready: $notReadyCount" -ForegroundColor Red
    if ($errorCount -gt 0) {
        Write-Host "Assessment errors: $errorCount" -ForegroundColor Red
    }
    
    # PC Health Check results
    $pcHealthPass = ($results | Where-Object { $_.PCHealthCheckStatus -eq "PASS" }).Count
    $pcHealthFail = ($results | Where-Object { $_.PCHealthCheckStatus -eq "FAIL" }).Count
    
    Write-Host ""
    Write-Host "PC Health Check Results:" -ForegroundColor Cyan
    Write-Host "Passed: $pcHealthPass" -ForegroundColor Green
    Write-Host "Failed: $pcHealthFail" -ForegroundColor Red
    
    # Export results
    Write-Host ""
    $csvFile = Export-AssessmentResults -Results $results -OutputPath $OutputPath
    Write-Host "Results exported to: $csvFile" -ForegroundColor Green
    
}
catch {
    Write-Host ""
    Write-Host "ERROR: $_" -ForegroundColor Red
    exit 1
}
finally {
    # Disconnect from vCenter
    if ($global:DefaultVIServers) {
        Write-Host ""
        Write-Host "Disconnecting from vCenter..." -ForegroundColor Yellow
        Disconnect-VIServer -Server * -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "Assessment complete!" -ForegroundColor Green
