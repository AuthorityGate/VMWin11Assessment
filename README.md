=======================================================================================================
    Title:          VMware Windows 11 Batch Assessment Tool
    Filename:       VMwareWin11BatchAssessment.ps1
    Description:    Enterprise-grade batch assessment tool for Windows 11 upgrade readiness evaluation
                    across VMware virtual machine infrastructure with integrated Microsoft PC Health 
                    Check validation and comprehensive CSV reporting capabilities
    Author:         Kevin Komlosy
    Company:        AuthorityGate Inc.
    Website:        https://www.authoritygate.com
    Email:          kevin.komlosy@authoritygate.com
    Date:           September 12, 2025
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
