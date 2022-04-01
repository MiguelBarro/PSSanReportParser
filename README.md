# PSSanReportParser

A [PowerShell](#requirements-and-platform-support) module to parse [google/sanitizers](https://github.com/google/sanitizers/wiki) reports.

## Installation

The latest release can found in the [PowerShell Gallery](https://www.powershellgallery.com/packages/SanReportParser/) or the [GitHub releases page](https://github.com/MiguelBarro/PSSanReportParser/releases). Installing is easiest from the gallery using `Install-Module`.
See [Installing PowerShellGet](https://docs.microsoft.com/en-us/powershell/scripting/gallery/installing-psget) if you run into problems with it.

```powershell
# install for all users (requires elevation)
Install-Module -Name PSSanReportParser -Scope AllUsers

# install for current user
Install-Module -Name PSSanReportParser -Scope CurrentUser
```

## Quick Start

Run your sanitation aware programs (usually build with `g -fsanitize=thread` compiler flags but that's platform
dependant) and parse the log output to generate a collection of report objects. There are two possibilities.

+ having the program output intermingled with the sanitizer reports. It's the most convenient procedure for mature
  code with few reports.

  ```powershell
  > $reports = ./my_sanitize_program | Show-TSan
  ```

+ use the environment variable
  [TSAN_OPTIONS](https://github.com/google/sanitizers/wiki/ThreadSanitizerFlags#runtime-flags) to generate a per-process
  log file (`log_path` option). This is convenient for test suites binaries like
  [ctest](https://cmake.org/cmake/help/latest/manual/ctest.1.html) or [googletest](https://github.com/google/googletest).

  If all test output is directed to `sterr` (which is the default) the reports may get mixed and become effectively
  useless. Besides having different log files can speed up the parsing process using parallelization (only available for
  powershell core).

  ```powershell
  > TSAN_OPTIONS="second_deadlock_stack=1 log_path=/tmp/san_reports/report" ctest -V -j8
  > $reports = Show-TSan (gci /tmp/san_reports)
  ```

  Note: it's advisable to direct the test suite to set the environment `TSAN_OPTIONS` for each test run in order to
  provide a different log name. That's because the OS system reuses process id numbers which is the device google
  sanitizers use to generate different log file names.

Once a collection of reports is generated is very usual to have hundreds of duplicated reports. Those are reports that
report the same issue on different processes. On report generation the `Show-TSan` cmdlet adds a `fuzzhash` property
which is meant to be the same value for the duplicated reports. This allows the trim up the `$reports` collection by
doing:

```powershell
> $groups = $reports | group fuzzhash 
# get issue frequency distribution
> $groups | sort Count -Descending | select Name, Count
# non duplicate actual issues collection
> $issues = $groups | % { $_.group[0] }
```

## Requirements and Platform Support

* Supports Windows PowerShell 5.1 (Desktop edition) **with .NET Framework 4.7.1** or later
* Supports PowerShell 7.2 or later ([Core edition](https://docs.microsoft.com/en-us/powershell/scripting/whats-new/differences-from-windows-powershell)) on all supported OS platforms.
* Requires `FullLanguage` [language mode](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes)
