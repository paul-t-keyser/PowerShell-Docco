# Basic Commands and Concepts

Based on https://www.pluralsight.com/courses/powershell-getting-started 

## Implementations of PS
* Visual Studio "Code" runs PS 
* The PowerShell "ISE" also recommended 
* Can also use: 
	* Windows Server Manager 
	* Windows Admin Center -- integrates with Win Azure 

* PS is based on .NET Standard and no further development ("feature complete") 

* PS "Core" based on .NET Core and is the future 
	* get from GitHub 

* *MAY* need v7.2 for Azure DevOps 

	*	get it from https://github.com/PowerShell/Powershell ?
	
	*	using https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2 ?

	*	download RSAT : https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools 


1. First set of basic commands
	* `Get-Host | Select-Object Version`
	* `$PSVersionTable` 

	* Multiline PS commands 
		* Contrast below under Scripts & ISE for how this works in ISE
		`Get-Service | #{hit Shift-enter}`
		`>> where ...`
	
	* Naming convention of all commands
		* `VERB`-`NOUN`
		* https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.2 

1. Pipelining is Crucial 
	* left to right execution, in which PS pipes the output of the lefter command to the input to the righter command 
	* what is passed along is some object (use Get-Member to find methods on the type
	
	* To count number of items:
	`... | Measure-Object`

	* To display as a table:
	`... | FT` (alias for `Format-Table`)

	* To export as text or CSV file:
	`... | Out-File .\results.csv` 
	`... | Export-CSV .\results.csv` 


1. Using Reflection to Explore Available Methods
	* Some Nouns
	* `Get-Service | where Status -Eq "Stopped" | Select-Object DisplayName,Status`
	* `Get-Service | Where-Object -Property Status -Eq "Stopped"` 
	* `Get-Alias -Definition Get-Service` 
		* result is `gsv`

	* `(Get-Command).count` 

	* `Get-Alias -Definition GetCommand` 
		* result is `gcm` 

	* `Get-Command -Name *IP*`
	* `Get-Command -Name *IP* -Module Net*`      // the -Module filters on the 'Source'
	* `Get-Command -Name *IP* -Module NetTCPIP`  // very focussed list
	* `Get-Command -Verb Stop` 
	* `Get-Command -CommandType Function | Measure-Object`
	
	* Some Verbs
		* https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.2 
	* `Get-Verb 
		* Returns list of all known verbs in the PS `Verb-Noun` formalism 
	* `Get-Verb -Verb Set` 
	* `Get-Verb -Verb Set | Format-List` 
	* `Get-Verb -Group Security` # ooops v7.2 only 
	
	* `Get-Alias` # aliases for command-names 
	* `Get-Alias -Definition Get-Alias` 
		* result is `gal` 
	* `Get-Alias -Name <short>` # gets expansion from short-name 
	* `Get-Alias -Definition <some piece of the full name>` 
	
	* `Get-History` # retieves list of *commands* (not outputs) from current session 
	* `Invoke-History -Id <NN>` # reruns the NN'th command in the history 
	* `Start-Transcript -Path <filename> -Append` # saves *everything* in the console including output & errors 
	* `Stop-Transcript` 

1. Using the Help System to Explore Available Methods
	* Must run as Admin!

	* `Update-Help` 
	* `Get-Help <command-name>`
		* can append `-Detailed` 
		* can append `-Examples` // can be useful for seeing what can be done 
		* appending the switch `-Online` opens the relevant MS docco webpage 
		* if the ,`<command-name>` matches multiple cmds, get a summary table 
		* the alias `Help` abbreviates the ouput and pipes it to "more": `| more`
	* `Get-Alias -Definition Get-Help` // NONE

	* `help about_*` // gives list of files
	* `help about_* | Measure-Object` // says there are 141 of them 
	
	* positional parameters : sometimes possible to omit parameter names
	* abbreviated parameters : sometimes possible to shorten parameter names 


	######################################################################################
	# USING Get-Member TO DISCOVER OTHER METHODS ON THE OUTPUT OF A COMMAND 
	# tutor likes to represent objects as rows of a table whose columns are properties 

	> Get-Member # "gets properties & methods" of the PS Objects 
	> Get-Alias -Definition Get-Member # -->> `gm` 
	
	> Get-Service | Where-Object -Property Status -Eq "Stopped" | Get-Member 
	# looking at its help, and that for add-member, led nowhere 

	> Get-Service -Name AppVClient | Get-Member # just pick an example service-name 
	> Get-Service -Name p2p* | Where-Object -Property Status -Eq "Stopped" | Start-Service -WhatIf
	# would start a few services 

	> Get-Service | Select-Object Name,MachineName,Status | Get-Member 
	# the Select-Object filters out all but the specified properties, returning a long list of services;
	# then, the Get-Member sees only those properties, so only those can appear in the output of Get-Member 
	
	> Get-Service | Where-Object -Property Status -Eq "Stopped" | Sort-Object -Property Name
	# add "| Sort-Object -Property Name" -->> 165 of them 


	######################################################################################
	# USING PS to gather info : Hardware, esp. Memory

	# e.g., to find commands about the fire-wall:
	> Get-Command -Name *Fire* # too many!
	> Get-Command -Name Get-*Fire* -Module Net* # returns only ten
	# Out of those ten, he wants to focus on "FirewallRule" (why?) 
	> Get-NetFirewallRule -Name *RemoteDesk* | Select-Object Name,Enabled,Profile,Direction,Action | FT 
	> Get-NetFirewallRule -Name *RemoteDesk* | Set-NetFirewallRule -Enabled 'True' -WhatIf # would enable some rules 


	######################################################################################
	# WMI: Windows Mgmt Instrumentation 
	# CIM: Common Info Model (PS v.3 and later, now preferred) 

	# Performance Counters using Get-Counter -ListSet Memory (unexplained syntax) 
	> Get-Counter -ListSet Memory | Select -expand Counter
	# From the list produced in prior command:
	> Get-Counter -Counter "\Memory\Pages/sec","\Memory\% Committed Bytes In Use" | FT
	
	> Get-WmiObject -List * | Measure-Object# 1446 items!
	> Get-CimClass -ClassName * | Measure-Object # same 1446 items!
	# after some unexplained choices:
	> Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object Tag,Capacity 


	######################################################################################
	# USING PS to gather info : Network 

	> ipconfig # supported by PS 
	> ipconfig | Get-Member # has no properties, because ret-val of ipconfig is not a PS-object 

	> Get-NetIPAddress       # multiple values
	> Get-NetIPConfiguration # ditto 

	# use `gcm get-*dns* -Module *dns*` to discover DNS-related commands
	
	# use `gcm *smb*` to get commands around mapping network drive; SMB = "Simple Message Block"
	> gcm *smb* |Measure-Object  # returns "90"
	> gcm *smbmap* # returns 3 that look promising
	
	> help New-SmbMapping -ex  # shows two params `-LocalPath` and `-RemotePath` 


	######################################################################################
	# Get the reboot-timestamp using event-viewer for event-type #1074 
	
	> Get-Alias -Definition Get-EventLog -->> fails 

	# Get-EventLog -LogName system |Get-Memory # not available in 5.1
	
	PS C:\Users\paul.keyser\PowersHell> Get-EventLog -LogName system -newest 100000 |
	>> where-object {$_.eventid -eq '1074'} |
	>> ft name,machinename,username,timegenerated,message -autosize

name MachineName              UserName            TimeGenerated          Message
---- -----------              --------            -------------          -------
                                                4/18/2022 4:56:08 PM   The process C:\WINDOWS\servicing\TrustedInstaller. ($MACHINE_NAME) has initiated the restart of computer $MACHINE_NAME on...
                                                4/18/2022 4:45:08 PM   The process C:\Windows\System32\RuntimeBroker. ($MACHINE_NAME) has initiated the restart of computer $MACHINE_NAME on beh...
                                                3/23/2022 12:17:15 PM  The process C:\Windows\System32\RuntimeBroker.exe ($MACHINE_NAME) has initiated the restart of computer $MACHINE_NAME on beh...
                                                2/7/2022 9:29:47 AM    The process C:\Windows\explorer.exe ($MACHINE_NAME) has initiated the restart of computer $MACHINE_NAME on behalf of user ..
                                                12/14/2021 10:06:02 AM The process C:\WINDOWS\system32\winlogon.exe ($MACHINE_NAME) has initiated the restart of computer $MACHINE_NAME on behalf o...
                                                12/3/2021 9:36:17 AM   The process C:\WINDOWS\system32\SlideToShutDown.exe ($MACHINE_NAME) has initiated the power off of computer $MACHINE_NAME on...

	...


	######################################################################################
	# Get-ComputerInfo 

	> Get-Alias -Definition Get-ComputerInfo # -->> `gin`

	> Get-ComputerInfo -Property *memory* # one huge object, so need to filter like this


	######################################################################################
	# Get-ChildItem, Copy-Item, etc.: for Files & Folders  

	> Get-Alias -Definition Get-ChildItem # -->> `gci` but also `dir` and `ls` 

	> Get-ChildItem -Path ..\..\paul.keyser\ -Recurse | where Extension -eq ".png" | Measure-Object # -->> 16341 
	> Get-ChildItem -Path ..\..\paul.keyser\ -Recurse | where lastwritetime -gt 1/1/2022 |  where Extension -eq ".xls" | Measure-Object # -->> 486

	> Copy-Item <src> -Destination <dest> 
	> Move-Item <src> -Destination <dest> 
	> Rename-Item <src> -NewName <dest> 


	######################################################################################
	# Remote management 
	
	# Windows Management Infrastructure (WMI) old-school 
	# Windows Remote Management (WinRM) impl of WSMan <<<<<<<<<<<< the focus 
	# SSH in PS 
	# RPC in PS (not PS Core) 

	# First, do this:
	> Enable-PSRemoting -Force # on the target machine 
	# Then do this:
	> Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurtyDescriptorUI 
	# Additionally, if target machine is running PS-Core, run this, as Admin, on target machine:
	> .\Install-PowerShellRemoting.ps1 

	# OK, so at this point the target machine is running the correct stuff, but might have firewall blockages:
	> Get-Service -ComputerName TargetMachineName # will fail unless the following have been done: 

	> Get-NetfirewallRule | where DisplayName -like "*Windows Management Instrumentation*" | Set-NetFirewallRule -Enable True 
	# actually they seem to be named "WMI-*"

	# also:
	> Get-NetfirewallRule | where DisplayGroup -eq "Remote Service Management" | Set-NetFirewallRule -Enable True 
	# the DisplayName (not Group) ~ RemoteSvcAdmin-*
	
	> Enter-PSSession -ComputerName <name> # of target machine will now work, to log onto target machine


	######################################################################################
	# Variables 

	> Get-ChildItem ENV: | more # to see the ~50 env vars 
	# access any of them like this: `$env:SystemRoot` 

	> Get-Variable | measure # the ~51 system vars 
	> Get-Alias -Definition Get-Variable # -->> `gv` 
	# access any one of them like this `Get-Variable Home` 

	> $NewVariable = "value of new var"
	> $NewVariable # accesses the `NewVariable` # or `$nEWvARIABLE` -- all cap is the same
	> Write-Output "message about $newVariable"
	# note that if we use a single-quote string (like 'singles') the name of the var is the value
	> Write-Output 'message about $newVariable'

	# Can also use `${newVariable}` anywhere (?) 


	######################################################################################
	# Creds 

	> Get-Credential # asks for id/pwd, does not validate it, returns object value to stash in variable 
	# in PS-Core, the equivalent of the UI dialog is right in the shell 


	######################################################################################
	# Remoting 

	# Many PS commands that remote use a parameter `-Computername` 
	# Many PS commands that remote use a noun `PSSession` 

	> Enter-PSSession -ComputerName $FOO -Credential $CRED  # allows you to run commands as if on the remote `$FOO` machine 
	# or enter a session created by New-PSSession
	# or enter a session by `-Id` (integer)
	# to exit, use `exit`
	
	# to get rid of a running session, use `Remove-PSSession` (and enter one or more id's)
	
	> Get-Command *PSSession  # ~ 10 of them 

	> Get-Service -ComputerName $REMOTE -Credential $CRED | select Name,Status 

	
	> Invoke-Command -ComputerName $FOO -FilePath $PATH_TO_ps1 
	# allows running a .PS1 script on the target system; PS objects are (de)serialized for transport
	# return-value of Invoke-Command is an object, and has the value of the return from the script block 
	# ... so for a `{ Get-Service ... }` can call Get-Method on return-value of Invoke-Command 
	
	# parameter `-ScriptBlock { ... }` where the ... indicates PS script, e.g., `Get-Service -ComputerName $FOO` 
	# BUT, to pass over the $FOO variable, need to use `$using:` prefix on variable name: `Get-Service -ComputerName $using:$FOO` 
	...
	
	Can pass commands in the `{ ... }` that are installed on the remote system, even if not installed on local system!


	# for legacy machines: 
	> New-CimSession -ComputerName $FOO  # can stash ret-val in variable, e.g. `$SESSION` 
	> Get-CimSession ...

	> Get-DNSClientServerAddress -CimSession $SESSION


	######################################################################################
	# Scripts & ISE

	# Can use ISE or VisualStudio Code to create and run these.
	# all have .PS1 extension 

	# Have to set the execution policy in PS:
	> .\script.ps1  # will fail unless policy correctly set
	> Get-ExecutionPolicy  #  -->> `Restricted` (fails) or `Unrestricted` (runs) 
	> Help Set-ExecutionPolicy -Parameter ExecutionPolicy  # NOTE: specifying which parameter to document is possible 
	# `RemoteSigned` == downloaded from trusted site, or created by you.

	# MULTILINE PS COMMANDS  
		Get-Service | #{hit Enter} <<< contrast to line-continuation in PS window 
		>> where ...

	# To the right in ISE, a window that lists all commands

	# Sample scriptlet I wrote:
	Get-CimInstance -ClassName Win32_OperatingSystem |
		Select-Object -Property CSName,LastBootUpTime 

	# Install Visual Studio code from a download 
	# Get the extension "PowerShell" from within a running VisualStudio Code instance

	# The "param" declaration in a script:
	Param (                                 #<< declaration (
		[Parameter(Mandatory=$true)]        #<< makes it required
	    [string[]]                          #<< the type of the param (string-array)
	    $Computername                       #<< name of the parameter within the script
	 )                                      #<< end declaration )

	> $svcs = Get-Service -Computername $Computername   # retval is list or array
	> Foreach ($svc in $svcs) { ... }
	> {
	>    $svc.Status        # accesses the `Status` field 
	>    $svc.DisplayName   # accesses the `DisplayName` 
	>    if ($var -eq 'Value') { ... }
	> }

	# Script template (any capitalization):
	# <#
	# .Synopsis 
	#    Write it here
	# .Description 
	#    Write it here
	# .Example 
	#    Write it here
	# #>
	
	undocumented Write-Output syntax:
	Write-Output "Plain text or $Variable, Tail";"";""
	# adds one trailing new-line per `;""` unit

	PowerShell.org community

	https://www.pluralsight.com/paths/windows-powershell-essentials 
	https://app.pluralsight.com/paths/skills/windows-powershell-essentials
	
	--> "Hicks, Putting PS to work"
	
	--> "Hicks, Automation with PS"
	
	--> "Bender, Windows Server Admin"


.
