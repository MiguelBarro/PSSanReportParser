<# 
.Synopsis
Simplify ASan reports parsing

.Description
Parsing test output to retrieve a ASan report object collection

.Parameter Path
File or collection of files to be parsed for ASan reports.

.Parameter InputObject
Collection of strings to be parsed for ASan reports.

.Parameter NoHash
Avoid fuzz hashing the reports. Significant speed boost.

.Inputs
Sources of ASan logs.

.Outputs
Collection of report objects extracted from the inputs.

.Example
To parse from several files is advisable to used the -Path argument because it provides
parallelization and progress report.

PS> Show-ASan (gci t.*)

.Example
Is posible to feed files into the pipeline but that disables paralellization.

PS> (gci t.*) | Show-ASan

.Example
To parse reports from pipeline:

PS> ctest -C Debug -V | Show-ASan

any non report related text would be discarded.

.Example
Is possible to speed up report processing if hashing is disabled:

PS> Show-ASan (gci t.*) -NoHash

.Example
Use fuzzy logic to check the most popular reported deadlock issue.

PS> $g = Show-ASan (gci) | ? type -NotMatch race | Group-Object -Property fuzzhash
PS> $g | sort -Property Count -Descending | select name, count -first 3

    Name Count
    ---- -----
    48     317
    73      62
    72      41

.Notes
Thread-Sanitizer has a tendency to duplicate the same report. In this case the MD5hash
would be the same and duplicates can be easily removed by doing:

PS> Show-ASan (gci t.*) | sort md5hash | Get-Unique -AsString | measure

.Link

https://github.com/MiguelBarro/PSSanReportParser

#>
function Show-ASan {
    [Alias('sas')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
            ParameterSetName = 'File',
            HelpMessage = 'Enter one or more filenames',
            ValueFromPipelineByPropertyName=$true,
            Position = 0)]
        [Alias("FullName")]
        [ValidateScript({
            Test-Path -Path $_ -PathType Leaf
            })]
        [String[]] $Path,

        [Parameter(Mandatory=$true,
            ParameterSetName = 'Pipe',
            HelpMessage = 'Pipeline stream',
            ValueFromPipeline=$true)]
        [AllowEmptyString()]
        [AllowNull()]
        [String[]] $InputObject,

        [Parameter(Mandatory=$false,
            HelpMessage = "Don`'t add a Fuzzy hash member")]
        [Switch]
        $NoHash
    )

    Begin
    {
        # sort of perfect forwarding 😅 
        $common_params = @{};
        foreach($arg in $PSBoundParameters.GetEnumerator())
        {
            if( $arg.key -ne $Null -and $arg.key -notmatch "Path|InputObject")
            {
                $common_params[$arg.key] = $arg.value
            }
        }

        # Current ASan report
        $arguments = [bool]$Path -or [bool]$InputObject

        # Current ASan report
        $current = $null

        # Current nesting level
        $nesting = 0
    }

    Process
    { 
        # Path arguments processing at the end
        if($arguments) { return }

        # Using Path property from the pipeline
        if($Path)
        {
            Write-Verbose "Processing file from pipeline: $Path"
            Get-Content $Path | Show-ASan @common_params | % { $_.file = $Path | Split-Path -Leaf; $_ }
            return
        }

        # Using pipeline
        if($InputObject)
        {

            Write-Debug "Processing line: $_"

            # Using pipeline input Check for report boundary, note that ASan reports may be interleaved. This would be notified
            # via warning and the affected reports dismissed. Use ASan flags to avoid this issue:
            #   + SanitizerCommonFlags (https://github.com/google/sanitizers/wiki/SanitizerCommonFlags)
            #       > log_path -> specifies an output file name without extension (the extension is going to be the process pid value)
            #   + AddressSanitizerFlags (https://github.com/google/sanitizers/wiki/AddressSanitizerFlags)
            #       > io_sync -> Controls level of synchronization implied by IO operations.
            if($_ -match "==(?<pid>\d+)==ERROR: AddressSanitizer: (?<sort>[-\w-\(\)/]+)")
            {
                Write-Debug "Above line is a header with type=$($Matches.sort) & pid=$($Matches.pid)"

                if($nesting++)
                {
                    Write-Warning "($nesting) Possible mixed report. Report header without closing the last one: $($Matches.pid)"
                    return
                }

                # create a new report object
                $current = [PSCustomObject]@{PSTypeName="eProsima.TSanReport.v1";type=$Matches.sort;pid=$Matches.pid;report=$_;file=$null} 
                Add-Member -InputObject $current -MemberType ScriptMethod -Name ToString -Value {$this.report} -Force

                Write-Verbose "Detected report prolog as $($Matches.sort) $($Matches.pid)"
            }
            elseif($_ -match "SUMMARY: AddressSanitizer: (?<sort>[-\w-\(\)/]+)")
            {
                Write-Debug "Above line is a footer with type=$($Matches.sort)"

                if(--$nesting -or $current -eq $null)
                {
                    # dismiss former report may be tainted
                    $current = $null 
                    Write-Warning "($nesting) Possible mixed report. Report footer without a clear header matched:`n>>>> $_"
                    return
                }

                if(!$NoHash)
                {
                    # mark as a type extension
                    $current.PSObject.TypeNames.Insert(0,"eProsima.TSanReport.v1#hashes")

                    # quick and dirty fuzzy hash, it depends on the kind of report (deadlocks have a larger variance than the data races)
                    switch -exact ($current.type)
                    {
                        { $_ -in 'access-violation',
                                 'heap-use-after-free',
                                 'new-delete-type-mismatch',
                                 'stack-use-after-scope'
                        } {
                            # admit little differences, about 100 chars
                            $current.report.ToCharArray() | % { $fuzzhash = 0 }{ $fuzzhash += [int]$_ }{ $fuzzhash /= 10000 };
                        }
                        default
                        {
                            # admit little differences, about 100 chars
                            $current.report.ToCharArray() | % { $fuzzhash = 0 }{ $fuzzhash += [int]$_ }{ $fuzzhash /= 10000 };
                        }
                    }
                    # let's quickly weight also the issue reported
                    $fuzzhash += 100 * $current.type.length

                    Add-Member -InputObject $current -NotePropertyName fuzzhash -NotePropertyValue ([int][Math]::floor($fuzzhash))
                    # actual hash of the report contents (required for Group-Object)
                    Add-Member -InputObject $current -NotePropertyName MD5hash -NotePropertyValue (Get-FileHash -Algorith MD5 `
                               -InputStream ([System.IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($current.report)))).Hash
                    # profit from the actual hashing to improve .Net object management
                    Add-Member -InputObject $current -MemberType ScriptMethod -Name GetHashCode -Value {$this.md5hash.GetHashCode()} -Force
                }

                Write-Verbose "Detected report epilog as $($Matches.sort)"

                # Send to the pipeline and prepare the next one
                $res = $current
                $current = $Null
                return $res
            }
            else
            {
                # Capture the report contents
                if($current)
                {
                    $current.report += "`n$_"

                    Write-Debug "keeping report line: $_"
                }
                else
                {
                    Write-Debug "line disposal: $_"
                }
            }
        }
    }

    End
    {
        # Using arguments, delegate into the pipe
        if($arguments)
        {
            if($Path)
            {
                Write-Verbose "Processing files from Path argument: $Path"

                # Report progress information
                $cur = 0 # current element processed  
                $pfunc = {
                    Param([int]$current)

                    $pc = $current/$Path.count*100
                    Write-Progress -Activity "Parsing ASan Reports:" `
                                   -Status ("{0:F2}%" -f $pc) `
                                   -PercentComplete $pc 
                }

                if($NoHash -or $PSVersionTable.PSVersion -lt [System.Version]"7.0")
                {
                    # Serial processing 
                    return $Path | % {
                        Get-Item $_ | Show-ASan @common_params
                        & $pfunc(++$cur) }
                }
                else
                {
                    $recursive = { $_ | Show-ASan @common_params}

                    # Parallel processing 
                    $job = $Path | Get-Item  | % -Parallel {
                        $_ | Show-ASan @using:common_params
                    } -AsJob -ThrottleLimit 10

                    # workaround for core issue https://github.com/PowerShell/PowerShell/issues/17077
                    $fix = { # TODO: remove when fixed
                        foreach ( $name in ($_ | Get-Member -MemberType ScriptMethod).name)
                        {
                             Add-Member -InputObject $_ -MemberType ScriptMethod -Name $name `
                                        -Value ([ScriptBlock]::Create($_.$name.Script)) -Force -PassThru 
                         }}

                    # Show progress
                    while($job.State -ne "Completed")
                    {
                        # Count the number of completed tasks and output the result at once
                        $done = $job.ChildJobs | ? State -eq "Completed"
                        if($done)
                        {
                            $done | Receive-Job | % { & $fix };
                            & $pfunc($done.count)
                        }
                    }
                    # Retrieve all pending data
                    Receive-Job $job -Wait -AutoRemoveJob | % { & $fix };
                }
            }
            else # InputObject
            {
                Write-Debug "Processing input from InputObject argument"
                # progress cannot be evaluated because Show-ASan calls require the input
                # received to contain complete reports
                return $InputObject | Show-ASan @common_params
            }
        }
    }
}
