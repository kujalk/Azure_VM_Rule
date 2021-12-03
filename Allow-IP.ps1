<#
        .SYNOPSIS
        To add security rules to security group for Azure VM
        Developer - K.Janarthanan
        .DESCRIPTION
        To add security rules to security group for Azure VM
        Date - 26/11/2021
        .OUTPUTS
        Log file with name Azure_SecurityGroup.log in the same directory of the script
        .EXAMPLE
        PS> .\Allow-IP.ps1 -ConfigFile ./Config.json
#>

Param(
    [Parameter(Mandatory)]
    [string]$ConfigFile
)

$Global:LogFile = "$PSScriptRoot\Azure_SecurityGroup.log" #Log file location
function Write-Log #Function for logging
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Validateset("INFO","ERR","WARN")]
        [string]$Type="INFO"
    )

    $DateTime = Get-Date -Format "MM-dd-yyyy HH:mm:ss"
    $FinalMessage = "[{0}]::[{1}]::[{2}]" -f $DateTime,$Type,$Message

    #Storing the output in the log file
    $FinalMessage | Out-File -FilePath $LogFile -Append

    if($Type -eq "ERR")
    {
        Write-Host "$FinalMessage" -ForegroundColor Red
    }
    else 
    {
        Write-Host "$FinalMessage" -ForegroundColor Green
    }
}

function Create-Rules #Function for logging
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $Rules,
        [Parameter(Mandatory=$true)]
        [string]$IP
    )

    try 
    {
        $All_Rules = @()

        foreach($Rule in $Rules)
        {
            Write-Log "Creating Rule in Security Group- $($Rule.Name)"

            $SG_Rule = New-AzNetworkSecurityRuleConfig -Name $Rule.Name `
            -Description "Allow $($Rule.Name)" `
            -Access Allow `
            -Protocol $Rule.Protocol `
            -Direction $Rule.Direction `
            -Priority $Rule.Priority `
            -SourceAddressPrefix $IP `
            -SourcePortRange * `
            -DestinationAddressPrefix * `
            -DestinationPortRange $Rule.Port

            $All_Rules += $SG_Rule
        }

        return $All_Rules
    }
    catch 
    {
        throw "Error while processing Rules - $_. Pls check everything is fine"    
    }
}

try
{
    Import-Module -Name Az.Accounts -ErrorAction Stop
    Import-Module -Name Az.Resources -ErrorAction Stop
    Import-Module -Name Az.Network -ErrorAction Stop 

    Write-Log "Script Started"

    $Config = Get-Content -Path $ConfigFile -ErrorAction Stop | ConvertFrom-Json

    if(($Config.SubscriptionName -ne $null) -and ($Config.ResourceGroup -ne $null))
    {
        Connect-AzAccount

        # Set subscription 
        Set-AzContext -SubscriptionId $Config.SubscriptionName -ErrorAction Stop | Out-Null
        Write-Log "Switched to the subscription"

        $SecurityGroup = Get-AzNetworkSecurityGroup -ResourceGroupName $Config.ResourceGroup -EA Stop | where-object {$_.Name -eq $Config.Network_SGName}

        if($SecurityGroup)
        {
            Write-Log "Security Group with name $($Config.Network_SGName) is present. Will update the rules"

            #Delete all existing Rules
            foreach($Rule in $SecurityGroup.SecurityRules)
            {
                Write-Log "Removing $($Rule.Name) from Security Group"
                $NSG = Get-AzNetworkSecurityGroup -ResourceGroupName $Config.ResourceGroup -Name $Config.Network_SGName -EA Stop
                Remove-AzNetworkSecurityRuleConfig -Name $Rule.Name -NetworkSecurityGroup $NSG -ErrorAction Stop | Out-Null
                $NSG | Set-AzNetworkSecurityGroup | Out-Null
                Start-Sleep 5
            }

            #Create all Rules
            foreach($Rule in $Config.Rules)
            {
                Write-Log "Creating new rule $($Rule.Name) inside Security Group"

                Get-AzNetworkSecurityGroup -Name $Config.Network_SGName -ResourceGroupName $Config.ResourceGroup  | Add-AzNetworkSecurityRuleConfig `
                -Name $Rule.Name -Description "Allow $($Rule.Name)" -Access Allow `
                -Protocol $Rule.Protocol -Direction $Rule.Direction -Priority $Rule.Priority -SourceAddressPrefix $Config.SourceIP -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $Rule.Port | Set-AzNetworkSecurityGroup | Out-Null
            }
                
            Write-Log "Applying Security Group to Network Interface"

            $NIC = Get-AzNetworkInterface -Name $Config.VMNIC_Name -ResourceGroupName $Config.ResourceGroup -EA Stop
            $NIC.NetworkSecurityGroup = $SecurityGroup
            Set-AzNetworkInterface -NetworkInterface $NIC -ErrorAction Stop | Out-Null

            Write-Log "Applied Security Group to Network Interface"
        }

        else 
        {
            Write-Log "Security Group with name $($Config.Network_SGName) is not there already. Therefore will create it"    

            #Create all Rules
            $PreparedRules = Create-Rules -Rules $Config.Rules -IP $Config.SourceIP -ErrorAction Stop

            Write-Log "Creating new Security Group"
            $Network_SG = New-AzNetworkSecurityGroup -Name $Config.Network_SGName -Location $Config.Region `
                    -ResourceGroupName $Config.ResourceGroup `
                    -SecurityRules $PreparedRules
                     
            Write-Log "Created new Security Group"

            Write-Log "Applying Security Group to Network Interface"

            $NIC = Get-AzNetworkInterface -Name $Config.VMNIC_Name -ResourceGroupName $Config.ResourceGroup -EA Stop
            $NIC.NetworkSecurityGroup = $Network_SG
            Set-AzNetworkInterface -NetworkInterface $NIC -ErrorAction Stop | Out-Null

            Write-Log "Applied Security Group to Network Interface"
        }

    }

    else 
    {
        throw "Azure Subscription and Resource groups are must for this script"    
    }
}
catch
{
    Write-Log "$_" -Type ERR
}