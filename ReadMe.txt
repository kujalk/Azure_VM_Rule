Pre-requisites
---------------
1. Make sure you have installed following PowerShell modules
   Az.Accounts
   Az.Resources
   Az.Network


Method
-------------
1. Fill the attached JSON file

    - SubscriptionName - Your Azure Subscription ID
    - ResourceGroup - Resource Group Name
    - Region - Location of Resource Group
    - VMNIC_Name - NIC Name of VM. For this only Security Group will be applied
    - Network_SGName - Network Security Group Name
    - SourceIP - IP address that needs to be allow-listed
    - Rules (Set of protocol and ports)
            Name -> Name of the rule
            Protocol -> TCP or UDP
            Direction -> Inbound or Outbound
            Port -> Port No
            Priority -> Priority No of the rule

2. Execute the script as -> \Allow-IP.ps1 -ConfigFile ./Config.json

3. Provide your credentials when prompt opens

4. Log file be created at -> Same folder location of script in the name of Azure_SecurityGroup.log

How this script works
----------------------

1. This script applies the Network Security Group to the NIC of the VM
2. If the Security Group is already exists, then this script will remove all the rules inside it and apply only the rules mentioned in JSON file
3. If the Security Group is not existing, then this script will create a new one with the rules mentioned in JSON file
