function Rotate-Byte {
<#
    .SYNOPSIS
    
        Performs left/right binary rotation on individual bytes.
        Author: @harmj0y

    .DESCRIPTION

        Implements the logic to perform per-byte binary rotates right and left.
        Use a positive offset value to rotate right, negative to rotate left.

    .PARAMETER Value

        The individual byte value, or array of byte values, to bit rotate.
        Passable on the pipeline.

    .PARAMETER Offset

        The number of bits to rotate, [-8..8]. Positive values rotate right, negative
        rotate left.

    .OUTPUTS
        
        [Byte[]]. Returns a stream of bit-rotated bytes.

    .EXAMPLE
        
        PS > 131 | Rotate-Byte
        56

        Rotate 131 right by 4 bits.

    .EXAMPLE
        
        PS > Rotate-Byte 131 -3
        28

        Rotate 131 left by 3 bits.

    .EXAMPLE
        
        PS > [Byte[]]$Bytes = @(131, 130, 129)
        PS > $Bytes | Rotate-Byte
        56
        40
        24

        Rotates all bytes right by 4 bits.

    .EXAMPLE

        PS > @(131, 130, 129) | Rotate-Byte -Offset -2
        14
        10
        6

        Rotates all bytes left by 2 bits.
#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, Mandatory = $True)]
        [Byte[]]
        $Value,

        [Parameter(Position = 1)]
        [Int]
        [ValidateRange(-8,8)]
        $Offset = 4
    )

    PROCESS {
        ForEach($Byte in $Value) {
            if ($Offset -lt 0) {
                1..(-$Offset) | ForEach-Object {
                    if($Byte -band 128) {
                        $Byte = 1 + ([Math]::Floor($Byte * [math]::Pow(2, 1)) -band 254)
                    }
                    else {
                        $Byte = [Math]::Floor($Byte * [math]::Pow(2, 1)) -band 254
                    }
                }
            }
            else {
                1..$Offset | ForEach-Object {
                    if($Byte -band 1) {
                        $Byte = 128 + [Math]::Floor($Byte * [math]::Pow(2, -1))
                    }
                    else {
                        $Byte = [Math]::Floor($Byte * [math]::Pow(2, -1))
                    }
                }
            }
            $Byte
        }
    }
}

function Read-FlashfloodData 
{
    <#
        .SYNOPSIS
    
            Decompresses a file based on APT30 / NaikonAPT compression routine
            Author: @sixdub

        .DESCRIPTION

            Replicates the decompression routine required by the FLASHFLOOD  malware (sha1: cfa438449715b61bffa20130df8af778ef011e15)
            and writes the decompressed data to the pipeline. More info about the threat actor: https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf

        .PARAMETER Path

            The path to the compressed file

        .OUTPUTS
        
            Byte[] of the decompressed file 

        .EXAMPLE
        
            PS > Read-FlashfloodFile -Path c:\windows\temp\test.ldf | Out-File -Encoding Ascii c:\hi.txt

            Decompress c:\windows\temp\test.ldf and output it to hi.txt

    #>

    [cmdletbinding()]
    Param(
    [ValidateNotNullOrEmpty()]
    [String]$Path
    )

    #Read in the file 
    $CompressedData = [System.IO.File]::ReadAllBytes($Path)
    Write-Verbose "$Path read"
    #Apply APT30/NaikonAPT custom deobfuscation
    for($i=0;$i -lt $CompressedData.Count;$i++)
    {
        $CompressedData[$i] = $CompressedData[$i] -bxor 0x23
        $CompressedData[$i] = Rotate-Byte $CompressedData[$i] 4
    }
    Write-Verbose "Applied custom deobfuscation"
    Write-Verbose "Original length: $($CompressedData.Length)"

    #GZip Decompress
    $MemoryStream2 = New-Object System.IO.MemoryStream
    $MemoryStream2.Write($CompressedData, 0, $CompressedData.Length)
    $MemoryStream2.Seek(0,0) | Out-Null
    $CompressionStream2 = New-Object System.IO.Compression.GZipStream($MemoryStream2, [System.IO.Compression.CompressionMode]::Decompress)
    $OutputStream = New-Object System.IO.MemoryStream
    while(($B = $CompressionStream2.ReadByte()) -ne -1)
    {
        $OutputStream.WriteByte($B)

    }
    $DecompressedBytes = $OutputStream.ToArray()
    "DecompressedBytes length: $($DecompressedBytes.Length)"

    #Write decompressed bytes
    Write-Output $DecompressedBytes

}

function Out-FlashfloodFile
{
    <#
        .SYNOPSIS
    
            Outputs compressed form of input using APT30 / NaikonAPT compression routine
            Author: @sixdub

        .DESCRIPTION

            Replicates the compression routine used by the FLASHFLOOD malware (sha1: cfa438449715b61bffa20130df8af778ef011e15)
            and writes the compressed data to a file. More info about the threat actor: https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf

        .PARAMETER Data

            The Byte array containing the original data

        .PARAMETER Path

            The path to output the compressed file

        .OUTPUTS
        
            FileInfo object pointing to the output file. 

        .EXAMPLE
        
            PS > [System.IO.File]::ReadAllBytes("c:\test.txt") | Out-FlashfloodFile -Path c:\windows\temp\test.ldf.

            Takes test.txt and compresses it to the location c:\windows\temp\test.ldf

    #>

    [CmdletBinding()]
    Param(
    [Parameter(ValueFromPipeline=$True)]
    [Byte[]] $Data,
    [ValidateScript({$(Split-Path $_ | Test-Path) -and -Not $(Test-Path $_)})]
    [String]$Path
    )
    Begin {
        $PipelineData = New-Object System.IO.MemoryStream
    }

    Process { 
        Foreach($B in $Data)
        {
            $PipelineData.WriteByte($B)
        }
    }

    End {
        $RawData = $PipelineData.ToArray()
        #Create the required streams including gzip stream
        Write-Verbose "Original length: $($RawData.Length)"
        $MemoryStream = New-Object System.IO.MemoryStream
        $CompressionStream = New-Object System.IO.Compression.GZipStream($MemoryStream, [System.IO.Compression.CompressionMode]::Compress)

        #Write data into the stream to compress
        $CompressionStream.Write([Byte[]]($RawData),0,$RawData.Length)

        #Close the compression stream to finalize writes
        $CompressionStream.Dispose()
        $CompressedData = $MemoryStream.ToArray()
        Write-Verbose "Compressed length: $($CompressedData.Length)"
        $MemoryStream.Dispose()

        #Apply custom NaikonAPT/APT30 obfuscation routine of a rotate 4, xor 0x23 to the compressed stream
        for($i=0;$i -lt $CompressedData.Count;$i++)
        {
            $CompressedData[$i] = Rotate-Byte $CompressedData[$i] 4
            $CompressedData[$i] = $CompressedData[$i] -bxor 0x23
        }
        Write-Verbose "Custom obfuscation applied, writing to file $Path"
        #Write output and return the object
        [System.IO.File]::WriteAllBytes($Path,$CompressedData)
        $OutFile = Get-ChildItem -path $Path 
	    return $OutFile

    }

}