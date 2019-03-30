#Requires -Version 3.0

Param (

    [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,
    [string] $ResourceGroupName = 'itea-ansible-infra-rg-west',
    [switch] $UploadArtifacts,
    [string] $storageAccountNamePrefix,
    [string] $TemplateFile = 'deployAnsibleInfrastructure.json',
    [string] $TemplateParametersFile = 'AnisbleInfrastructure.parameters.json',
    [string] $ValidateOnly = 'No'
	#[string] [Parameter(Mandatory=$true)] $username

)

<#
try {
    [Microsoft.Azure.Common.Authentication.AzureSession]::ClientFactory.AddUserAgent("VSAzureTools-$UI$($host.name)".replace(' ','_'), '3.0.0')
} catch { }
#>
<#
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
#>


function Format-ValidationOutput {
    param ($ValidationOutput, [int] $Depth = 0)
    Set-StrictMode -Off
    return @($ValidationOutput | Where-Object { $_ -ne $null } | ForEach-Object { @('  ' * $Depth + ': ' + $_.Message) + @(Format-ValidationOutput @($_.Details) ($Depth + 1)) })
}




		$CurrentDirectory =  Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
		$templatePath =  [string]::Concat($CurrentDirectory, '\', $TemplateFile)
		$parametersPath = [string]::Concat($CurrentDirectory, '\', $TemplateParametersFile)
		$sshKeysLocation =  [string]::Concat($CurrentDirectory, '\', 'ansible', '\',  'ssh_keys')
		$ansibleConfigScriptsLocation = [string]::Concat($CurrentDirectory, '\', 'ansible', '\',  'ansible_configure')
		$ansiblePlaybooksLocation = [string]::Concat($CurrentDirectory, '\..\', '\..\',  'asset-configuration')		
		$SSHStorageContainerName = 'ssh'
		$ansibleConfigStorageContainerName = 'configscipts'
		$ansiblePlaybooksStorageFileShareName = 'playbooks'
		$ansibleShareDriveLetter = 'X'
        $ansibleShareDrivePath = $ansibleShareDriveLetter + ':\'
<#
        $userName = Read-Host 'Type your Azure username to login: ' 
		$userPassword = Read-Host 'Type your Azure password to login: ' -AsSecureString 
		$SubscriptionId = Read-Host 'Type subsription ID to login upon: ' -AsSecureString 
		$adminUserName = Read-Host 'Type ansible user name: '
		$adminPassword = Read-Host 'Type ansible admin password to login: ' -AsSecureString 
	    $sshKeyData = Read-Host 'Type ansible public key to be used: ' -AsSecureString
		$sshKeysLocation =  Read-Host 'Specify path to keys: '
#>
		#$userName = 'devopsInterL@outlook.com'
		#$userPassword = 'New_opportunity'
		$SubscriptionId = ' set Subscription ID '
		$adminUserName = 'iteacademy'
		$adminPassword = 'New_opportunity'
	    $sshKeyData = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDdTG/LZjmh7jGQuFkH6tLV4+Bytlz4CzPMDvTNfZT+Ey1E9ExJeaWQcABSjX3u1J178AaAmeurWeZ4MozmIMy7IIPsgOot+R7FyR3Vnm/KRcDPwTNbyl0y9wWGTsxtBbdZZgD8l3TGAX+CwVBtt7CAB+cMLl+AkgsbG81sNjY4c3/FY71c1xeGhKqTV5hvB+NtA0Q4NfK+HmO2KGP0Xzd6dJzYbub5FV+LgGan4zp6e2uFDo8zykqlLZxLK2HC1GCNB967wd6GI3HfT8k7uM6HoU3yABODsTOqvAvGG3csQw9ie/uMPV+GOnd+70NE6O2lOEseWEQYBDwRE8EmuL9p'
		#$sshKeysLocation =  '\\Mac\Home\Downloads\MineQDevOpsInfrastructureasCode\AnsibleInfrastracture\AnsibleInfrastracture\ansible\ssh_keys'
	
		#$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($userPassword)
		#$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        Write-Host "Logging to Azure ... " -foregroundcolor "Yellow"

		#$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $userPassword

		#Login-AzureRmAccount -Credential $cred 

		Login-AzureRmAccount
		
		#$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SubscriptionId)
		#$UnsecureSubscriptionId = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

		Set-AzureRmContext -SubscriptionId $SubscriptionId

        Write-Host Working on preparing  pre-requisites for deploying Ansible Infra -foregroundcolor "Green"


	    $OptionalParameters = New-Object -TypeName Hashtable

		if ($UploadArtifacts) {

				# Parse the parameter file and update the values of artifacts location and artifacts location SAS token if they are present
    			$JsonParameters = Get-Content $parametersPath -Raw | ConvertFrom-Json
    			if (($JsonParameters | Get-Member -Type NoteProperty 'parameters') -ne $null) {
        			$JsonParameters = $JsonParameters.parameters
    			}
    			$scriptsLocationName = '_ansibleConfigScriptsLocation'
    			$scriptsLocationAccountKey = '_ansibleConfigScriptsLocationAccountKey'
    			$OptionalParameters[$scriptsLocationName] = $JsonParameters | Select -Expand $scriptsLocationName -ErrorAction Ignore | Select -Expand 'value' -ErrorAction Ignore
    			$OptionalParameters[$scriptsLocationAccountKey] = $JsonParameters | Select -Expand $scriptsLocationAccountKey -ErrorAction Ignore | Select -Expand 'value' -ErrorAction Ignore

				$OptionalParameters['_adminUsername'] = $JsonParameters | Select -Expand '_adminUsername' -ErrorAction Ignore | Select -Expand 'value' -ErrorAction Ignore
				$OptionalParameters['_adminPassword'] = $JsonParameters | Select -Expand '_adminPassword' -ErrorAction Ignore | Select -Expand 'value' -ErrorAction Ignore
				$OptionalParameters['_sshKeyData'] = $JsonParameters | Select -Expand '_sshKeyData' -ErrorAction Ignore | Select -Expand 'value' -ErrorAction Ignore

			}

    		# Create a storage account name 
		    $StorageAccountName = $storageAccountNamePrefix + ((Get-AzureRmContext).Subscription.SubscriptionId).Replace('-', '').substring(0, 13)
			$StorageAccount = (Get-AzureRmStorageAccount | Where-Object{$_.StorageAccountName -eq $StorageAccountName})

    		# Create the storage account if it doesn't already exist
    		if ($StorageAccount -eq $null) {
        		$StorageResourceGroupName = $ResourceGroupName
        		New-AzureRmResourceGroup -Location $ResourceGroupLocation -Name $StorageResourceGroupName -Force
        		$StorageAccount = New-AzureRmStorageAccount -StorageAccountName $StorageAccountName -Type 'Standard_LRS' -ResourceGroupName $StorageResourceGroupName -Location $ResourceGroupLocation 
    		}

    		# Generate the value for scripts location if it is not provided in the parameter file
    		if ($OptionalParameters[$scriptsLocationName] -eq "") {
			
        		$OptionalParameters[$scriptsLocationName] = $StorageAccount.Context.BlobEndPoint + $ansibleConfigStorageContainerName
    		}
	        
    		if ($OptionalParameters['_adminUsername'] -eq "") {
				
        		$OptionalParameters['_adminUsername'] = $adminUserName
    		}

    		if ($OptionalParameters['_adminPassword'] -eq "") {
				
				#$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPassword)
				#$UnsecureUserPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        		$OptionalParameters['_adminPassword'] = $adminPassword
    		}

			if ($OptionalParameters['_sshKeyData'] -eq "") {

				#$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sshKeyData)
				#$UnsecureSshKeyData = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        		$OptionalParameters['_sshKeyData'] = $sshKeyData
    		}

			$scriptsStorageAccountName = '_ansibleConfigScriptsStorageAccountName'

			# Pass Storage Account name dynamicaly during deployment 
			$OptionalParameters[$scriptsStorageAccountName] = $StorageAccountName

    		# Copy ansible configuration scripts from the local storage staging location to the storage account container
			$StorageContainer =  Get-AzureStorageContainer -Name $ansibleConfigStorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1
			if  ($StorageContainer -eq $null) {
    			New-AzureStorageContainer -Name $ansibleConfigStorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1
			}

    		$ScriptFilesPaths = Get-ChildItem $ansibleConfigScriptsLocation -Recurse -File | ForEach-Object -Process {$_.FullName}
    		foreach ($SourcePath in $ScriptFilesPaths) {				
				$fileName = [System.IO.Path]::GetFileName($SourcePath)
				Write-Host "Uploading ansible configuration scripts: "  $fileName -foregroundcolor "Yellow"
        		Set-AzureStorageBlobContent -File $SourcePath -Blob $fileName `
            	-Container $ansibleConfigStorageContainerName -Context $StorageAccount.Context -Force
			}
			
			<#
    		# Copy ansible playbook scripts from the local storage staging location to the storage account container
			$StorageContainer =  Get-AzureStorageContainer -Name $ansiblePlaybooksStorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1
			if  ($StorageContainer -eq $null) {
    			New-AzureStorageContainer -Name $ansiblePlaybooksStorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1
			}

    		$PlaybookFilesPaths = Get-ChildItem $ansiblePlaybooksLocation -Recurse | ForEach-Object -Process {$_.FullName}
    		foreach ($PlaybookPath in $PlaybookFilesPaths) {				
				$PlaybookName = [System.IO.Path]::GetFileName($PlaybookPath)
				Write-Host "Uploading ansible playbooks: "  $PlaybookName -foregroundcolor "Yellow"
            	Set-AzureStorageBlobContent -File $PlaybookPath -Blob $PlaybookName `
            	-Container $ansiblePlaybooksStorageContainerName -Context $StorageAccount.Context -Force
    		}
			#>

    		# Copy ssh keys from the local storage staging location to the storage account container
			$StorageContainer =  Get-AzureStorageContainer -Name $SSHStorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1
			if  ($StorageContainer -eq $null) {
    			New-AzureStorageContainer -Name $SSHStorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1
			}

    		$SSHKeyFilesPaths = Get-ChildItem $sshKeysLocation -Recurse -File | ForEach-Object -Process {$_.FullName}
    		foreach ($SourcePath in $SSHKeyFilesPaths) {				
				$fileName = [System.IO.Path]::GetFileName($SourcePath)
				Write-Host "Uploading ssh key: "  $fileName -foregroundcolor "Yellow"
        		Set-AzureStorageBlobContent -File $SourcePath -Blob $fileName `
            	-Container $SSHStorageContainerName -Context $StorageAccount.Context -Force
    		}
			<# Since custom scripts extension doesn't work with SAS tokens i need to get Account key '
            # Generate a 4 hour SAS token for the artifacts location if one was not provided in the parameters file
            if ($OptionalParameters[$scriptsLocationAccountKey] -eq "") {
				
            	$OptionalParameters[$scriptsLocationAccountKey] = ConvertTo-SecureString -AsPlainText -Force `
            		( New-AzureStorageContainerSASToken -name $ansibleConfigStorageContainerName -Context $StorageAccount.Context -Permission rwdl -ExpiryTime (Get-Date).AddHours(12))
            
				#$OptionalParameters[$scriptsLocationAccountKey] = New-AzureStorageContainerSASToken -name $ansibleConfigStorageContainerName -Context $StorageAccount.Context -Permission rwdl -ExpiryTime (Get-Date).AddHours(12)
			}
			#>

			if ($OptionalParameters[$scriptsLocationAccountKey] -eq "") {
				
            	$OptionalParameters[$scriptsLocationAccountKey] = (Get-AzureRmStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName ).Value[0]
            
				#$OptionalParameters[$scriptsLocationAccountKey] = New-AzureStorageContainerSASToken -name $ansibleConfigStorageContainerName -Context $StorageAccount.Context -Permission rwdl -ExpiryTime (Get-Date).AddHours(12)
			
			<#

			# Copy ansible playbook scripts from the local storage staging location to the azure file share
            $StorageFileshare = Get-AzureStorageShare $ansiblePlaybooksStorageFileShareName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1
			if  ($StorageFileShare -eq $null) {
                New-AzureStorageShare -Name $ansiblePlaybooksStorageFileShareName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1
			}
			$acctKey = ConvertTo-SecureString -String $OptionalParameters[$scriptsLocationAccountKey] -AsPlainText -Force
			$credential = New-Object System.Management.Automation.PSCredential -ArgumentList "$StorageAccountName", $acctKey
			New-PSDrive -Name $ansibleShareDriveLetter -PSProvider 'FileSystem' -Root "\\$StorageAccountName.file.core.windows.net\$ansiblePlaybooksStorageFileShareName" -Credential $credential
            Copy-Item -Path $ansiblePlaybooksLocation -Destination $ansibleShareDrivePath -recurse -Force
			Remove-PSDrive -Name $ansibleShareDriveLetter
		    
			 #>
			}

		
  <#
            Write-Host  Target Environment: $environment -foregroundcolor  "Yellow"
			Write-Host  Deployment level: $deploymentLevel -foregroundcolor  "Yellow"
			Write-Host  Target Component : $targetComponentType -foregroundcolor  "Yellow"
			Write-Host  Azure Resources location: $PSBoundParameters.location -foregroundcolor  "Yellow"
			Write-Host  Azure Resource Group Name: $PSBoundParameters.resourceGroupName -foregroundcolor  "Yellow"
			Write-Host  "Configuration Type:" $PSBoundParameters.configurationType -foregroundcolor  "Yellow"
			Write-Host  "SSH keys Path for Ansible:" $sshKeysLocation -foregroundcolor  "Yellow"
			Write-Host  "Storage account name prefix for configuration scripts:" $PSBoundParameters.storageAccountNamePrefix -foregroundcolor  "Yellow"			
			Write-Host  "Azure Template Path:" $templatePath -foregroundcolor  "Yellow"
			Write-Host  "Azure Parameters Path:" $parametersPath -foregroundcolor  "Yellow"

			Write-Host  "Parameters values" $parametersPath -foregroundcolor  "Green"

			Write-Host _ansibleConfigScriptsLocation: $OptionalParameters[$scriptsStorageAccountName] -foregroundcolor  "Yellow"
			Write-Host _ansibleConfigScriptsLocationAccountKey: $OptionalParameters[$scriptsLocationAccountKey] -foregroundcolor  "Yellow"
			Write-Host _storageAccountName:$OptionalParameters[$scriptsStorageAccountName] -foregroundcolor  "Yellow"

			$JsonParameters = Get-Content $parametersPath -Raw | ConvertFrom-Json
    			if (($JsonParameters | Get-Member -Type NoteProperty 'parameters') -ne $null) {
            			$parameters =  $JsonParameters.parameters

    			}

    		foreach ($h in $parameters.psobject.Properties) {
    			Write-Host $h.name : $h.value.value -foregroundcolor  "Yellow"
			}

	
			# Create or update the resource group using the specified template file and template parameters file
			New-AzureRmResourceGroup -Name $PSBoundParameters.resourceGroupName -Location $PSBoundParameters.location -Verbose -Force

			$ValidateOnly = "No"

			#>

			if ($ValidateOnly -eq "Yes") {
				$ErrorMessages = Format-ValidationOutput (Test-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName `
																							-TemplateFile $templatePath `
																							-TemplateParameterFile $parametersPath 
																							)
				if ($ErrorMessages) {
					Write-Output '', 'Validation returned the following errors:', @($ErrorMessages), '', 'Template is invalid.'
				}
				else {
					Write-Output '', 'Template is valid.'
				}
			}
			else {

				New-AzureRmResourceGroupDeployment -Name ((Get-ChildItem $templatePath).BaseName + '-' + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')) `
												-ResourceGroupName $ResourceGroupName `
												-TemplateFile $templatePath `
												-TemplateParameterFile $parametersPath `
												@OptionalParameters `
												-Force -Verbose `
												-ErrorVariable ErrorMessages
				if ($ErrorMessages) {
					Write-Output '', 'Template deployment returned the following errors:', @(@($ErrorMessages) | ForEach-Object { $_.Exception.Message.TrimEnd("`r`n") })
				}
			}
