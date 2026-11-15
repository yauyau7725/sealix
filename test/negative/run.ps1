$ErrorActionPreference = 'Stop'

Push-Location (Join-Path $PSScriptRoot '..\..\app')

try {
    go test ./internal/cli `
        -run '^(TestNegativeU02ToU13|TestVerifyPrecedence)$' `
        -count=1 -v

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}