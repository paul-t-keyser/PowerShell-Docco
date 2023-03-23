# Control-Flow

## Some Syntax
* the `switch() {}` allows multiple evaluations in the ()'s and the values of the cases are evaluated at run-time
* the `[DateTime]$var` is equivalent to: `$var -as [DateTime]` 
* the `$list ForEach-Object { ... $PSItem ...}`  (where `$PSItem` is "automatic") is equivalent to: `foreach ($item in $list) { ... $item ...}`  
* to create Hashtable:  `$htempty = @{} ; $ht = @{Key1 = "Value", "Key2" = "Value2"}` ; $ht.keys and $ht.values, etc. 
* to create an ordered Hashtable, `$ht = [ordered]@{Key1 = "Value", "Key2" = "Value2"}`
* the `-is` and `-isnot` operators for types 
* Write-Output syntax:
    * `Write-Output "Plain text or $Variable, Tail";"";""`
    * adds one trailing new-line per `;""` unit

* `$svcs = Get-Service -Computername $Computername`
  * retval is list or array
```
Foreach ($svc in $svcs) { ... }
    {
       $svc.Status        # accesses the "Status" field 
       $svc.DisplayName   # accesses the "DisplayName" 
       if ($var -eq 'Value') { ... }
    }
```


## Exceptions and try/catch
* `try {} catch [$CLASS_NAME] {} finally {}`
  * has blocks as in C# 
  * `$CLASS_NAME` might be e.g. `System.IO.FileNotFoundException` ... and the variable after a catch is `$_` ( like `$\.Exception.Message` ) 
* to throw a typed exception : `throw [$CLASS_NAME] "message you want to send"`
* `Write-Error -Message "something" -ErrorAction (Continue | Ignore | SilentlyContinue | Stop)` 
  * apparently the `-ErrorAction $WHAT` can be appended to any call to a user-written function that throws 
  * the return-value of a throw (warning): `$error = Throw "Something"` loads up a complex pile of data into $error 


# Security Matters
* `New-SelfSignedCertificate -DNSName "..." -CertStoreLocation $path -Type CodeSigningCert -Subject "whatever"` 
  * but this is of limited use 
* `Set-AuthenticodeSignature $script -Certificate $certificate` , where `$certificate = (Get-ChildItem $path -CodeSigningCert)[0]`
  * adds a long base-64 (question) signature as a trailing comment in the file 
  * have to run the "Microsoft Management Console" to copy the cert, to its store of "snap-ins" under "Trusted Root", from the "Personal/Certificates" 


# Scripts and Functions

## Basic Stuff
* edit and run scripts from Visual Studio Code 
* pass "arguments" ( rather than parameters ) to a function, and to access the array of args inside, use syntax like this: 
  * `$($args[0])`
* given a user-composed function `Do-Foo([String]$item)`, call `Do-Foo -item "whatever"` 

* use this syntax to define a parameter called 'name', with a defined set of options (tab-completeable):
```
  [Parameter(Mandatory=$true)] 
  [ValidateSet("a", "b", "c", ...)] 
  [string] $name 
```
* class for auto-completion, pass its name to the ValidateSet() above:
```
class Cities : System.Management.Automation.IValidateSetValuesGenerator { [string[]] GetValidValues() { return @( 'a', 'b', 'c', ... )  }  }
```

### The "param" declaration in a script:
```
    Param (                                 #<< declaration (
        [Parameter(Mandatory=$true)]        #<< makes it required
        [string[]]                          #<< the type of the param (string-array)
        $Computername                       #<< name of the parameter within the script
     )                                      #<< end declaration )
```

* Script template (any capitalization):
```
  <#
  .Synopsis 
     Write it here
  .Description 
     Write it here
  .Example 
     Write it here
  #>
```

## Built-In Tooling
* There is comment-based help ... 
* start/stop the transcript to record a script ...
