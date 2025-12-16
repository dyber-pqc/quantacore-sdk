<#
.SYNOPSIS
    Generate QUAC 100 API Documentation

.DESCRIPTION
    Generates API documentation from source code using Doxygen.
    Creates HTML and optionally PDF documentation.

.PARAMETER OutputDir
    Output directory for documentation

.PARAMETER Format
    Output format: HTML, PDF, Both

.PARAMETER Open
    Open documentation in browser after generation

.EXAMPLE
    .\gendocs.ps1
    Generate HTML documentation

.EXAMPLE
    .\gendocs.ps1 -Format Both -Open
    Generate HTML and PDF, then open in browser
#>

param(
    [string]$OutputDir,
    
    [ValidateSet("HTML", "PDF", "Both")]
    [string]$Format = "HTML",
    
    [switch]$Open
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "QUAC 100 Documentation Generator" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

if (-not $OutputDir) {
    $OutputDir = Join-Path $RootDir "docs\api"
}

# Check for Doxygen
$doxygen = Get-Command doxygen -ErrorAction SilentlyContinue

if (-not $doxygen) {
    # Try common install locations
    $doxyPaths = @(
        "C:\Program Files\doxygen\bin\doxygen.exe",
        "C:\Program Files (x86)\doxygen\bin\doxygen.exe",
        "$env:LOCALAPPDATA\Programs\doxygen\bin\doxygen.exe"
    )
    
    foreach ($path in $doxyPaths) {
        if (Test-Path $path) {
            $doxygen = $path
            break
        }
    }
}

if (-not $doxygen) {
    Write-Warning "Doxygen not found. Install from https://www.doxygen.nl/download.html"
    Write-Host "Generating basic documentation without Doxygen..." -ForegroundColor Yellow
    
    # Create basic docs
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    # Generate API reference from headers
    $apiDoc = @"
<!DOCTYPE html>
<html>
<head>
    <title>QUAC 100 API Reference</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 40px; }
        h3 { color: #7f8c8d; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 5px; overflow-x: auto; }
        code { font-family: 'Consolas', 'Monaco', monospace; }
        .function { margin: 20px 0; padding: 15px; background: #f8f9fa; border-left: 4px solid #3498db; }
        .function-name { font-weight: bold; color: #2980b9; }
        .param { color: #27ae60; }
        .return { color: #8e44ad; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #3498db; color: white; }
        tr:hover { background: #f5f5f5; }
    </style>
</head>
<body>
<div class="container">
<h1>QUAC 100 Windows Driver API Reference</h1>
<p>Version: 1.0.0 | Generated: $(Get-Date -Format "yyyy-MM-dd")</p>

<h2>Overview</h2>
<p>The QUAC 100 user-mode API provides access to the post-quantum cryptographic accelerator hardware.</p>

<h2>Quick Start</h2>
<pre><code>#include "quac100lib.h"

// Open device
QUAC_HANDLE handle;
QuacOpen(0, &amp;handle);

// Generate random bytes
BYTE random[32];
QuacRandom(handle, random, 32, QUAC_RNG_QUALITY_HIGH);

// Perform KEM key generation
QUAC_KEM_SIZES sizes;
QuacKemGetSizes(QUAC_KEM_KYBER768, &amp;sizes);

BYTE* pk = malloc(sizes.PublicKeySize);
BYTE* sk = malloc(sizes.SecretKeySize);
QuacKemKeyGen(handle, QUAC_KEM_KYBER768, pk, sk);

// Clean up
QuacClose(handle);
</code></pre>

<h2>Device Management</h2>

<div class="function">
    <span class="function-name">QuacGetVersion</span>
    <p>Get library version information.</p>
    <pre><code>QUAC_ERROR QuacGetVersion(
    UINT32* major,
    UINT32* minor,
    UINT32* patch,
    const char** versionString
);</code></pre>
</div>

<div class="function">
    <span class="function-name">QuacEnumerateDevices</span>
    <p>Count available QUAC 100 devices.</p>
    <pre><code>QUAC_ERROR QuacEnumerateDevices(
    UINT32* deviceCount
);</code></pre>
</div>

<div class="function">
    <span class="function-name">QuacOpen</span>
    <p>Open a device handle for cryptographic operations.</p>
    <pre><code>QUAC_ERROR QuacOpen(
    UINT32 deviceIndex,
    QUAC_HANDLE* handle
);</code></pre>
</div>

<div class="function">
    <span class="function-name">QuacClose</span>
    <p>Close a device handle and release resources.</p>
    <pre><code>QUAC_ERROR QuacClose(
    QUAC_HANDLE handle
);</code></pre>
</div>

<h2>Key Encapsulation (KEM)</h2>

<div class="function">
    <span class="function-name">QuacKemGetSizes</span>
    <p>Get key and ciphertext sizes for a KEM algorithm.</p>
    <pre><code>QUAC_ERROR QuacKemGetSizes(
    QUAC_KEM_ALG algorithm,
    QUAC_KEM_SIZES* sizes
);</code></pre>
</div>

<div class="function">
    <span class="function-name">QuacKemKeyGen</span>
    <p>Generate a KEM key pair.</p>
    <pre><code>QUAC_ERROR QuacKemKeyGen(
    QUAC_HANDLE handle,
    QUAC_KEM_ALG algorithm,
    BYTE* publicKey,
    BYTE* secretKey
);</code></pre>
</div>

<div class="function">
    <span class="function-name">QuacKemEncaps</span>
    <p>Encapsulate a shared secret.</p>
    <pre><code>QUAC_ERROR QuacKemEncaps(
    QUAC_HANDLE handle,
    QUAC_KEM_ALG algorithm,
    const BYTE* publicKey,
    BYTE* ciphertext,
    BYTE* sharedSecret
);</code></pre>
</div>

<div class="function">
    <span class="function-name">QuacKemDecaps</span>
    <p>Decapsulate to recover the shared secret.</p>
    <pre><code>QUAC_ERROR QuacKemDecaps(
    QUAC_HANDLE handle,
    QUAC_KEM_ALG algorithm,
    const BYTE* secretKey,
    const BYTE* ciphertext,
    BYTE* sharedSecret
);</code></pre>
</div>

<h2>Digital Signatures</h2>

<div class="function">
    <span class="function-name">QuacSignKeyGen</span>
    <p>Generate a signing key pair.</p>
    <pre><code>QUAC_ERROR QuacSignKeyGen(
    QUAC_HANDLE handle,
    QUAC_SIGN_ALG algorithm,
    BYTE* publicKey,
    BYTE* secretKey
);</code></pre>
</div>

<div class="function">
    <span class="function-name">QuacSign</span>
    <p>Sign a message.</p>
    <pre><code>QUAC_ERROR QuacSign(
    QUAC_HANDLE handle,
    QUAC_SIGN_ALG algorithm,
    const BYTE* secretKey,
    const BYTE* message,
    SIZE_T messageLen,
    const BYTE* context,
    SIZE_T contextLen,
    BYTE* signature,
    SIZE_T* signatureLen
);</code></pre>
</div>

<div class="function">
    <span class="function-name">QuacVerify</span>
    <p>Verify a signature.</p>
    <pre><code>QUAC_ERROR QuacVerify(
    QUAC_HANDLE handle,
    QUAC_SIGN_ALG algorithm,
    const BYTE* publicKey,
    const BYTE* message,
    SIZE_T messageLen,
    const BYTE* context,
    SIZE_T contextLen,
    const BYTE* signature,
    SIZE_T signatureLen,
    BOOL* valid
);</code></pre>
</div>

<h2>Random Number Generation</h2>

<div class="function">
    <span class="function-name">QuacRandom</span>
    <p>Generate quantum random bytes.</p>
    <pre><code>QUAC_ERROR QuacRandom(
    QUAC_HANDLE handle,
    BYTE* buffer,
    SIZE_T length,
    QUAC_RNG_QUALITY quality
);</code></pre>
</div>

<h2>Error Codes</h2>
<table>
<tr><th>Code</th><th>Name</th><th>Description</th></tr>
<tr><td>0</td><td>QUAC_SUCCESS</td><td>Operation completed successfully</td></tr>
<tr><td>1</td><td>QUAC_ERROR_INVALID_PARAM</td><td>Invalid parameter passed</td></tr>
<tr><td>2</td><td>QUAC_ERROR_DEVICE_NOT_FOUND</td><td>No QUAC 100 device found</td></tr>
<tr><td>3</td><td>QUAC_ERROR_DEVICE_BUSY</td><td>Device is busy</td></tr>
<tr><td>4</td><td>QUAC_ERROR_NOT_SUPPORTED</td><td>Operation not supported</td></tr>
<tr><td>5</td><td>QUAC_ERROR_BUFFER_TOO_SMALL</td><td>Output buffer too small</td></tr>
<tr><td>6</td><td>QUAC_ERROR_TIMEOUT</td><td>Operation timed out</td></tr>
<tr><td>7</td><td>QUAC_ERROR_CRYPTO_FAILED</td><td>Cryptographic operation failed</td></tr>
<tr><td>8</td><td>QUAC_ERROR_ENTROPY_LOW</td><td>Insufficient entropy</td></tr>
<tr><td>9</td><td>QUAC_ERROR_HEALTH_CHECK_FAILED</td><td>Hardware health check failed</td></tr>
</table>

<h2>Algorithms</h2>

<h3>KEM Algorithms</h3>
<table>
<tr><th>Algorithm</th><th>Security Level</th><th>Public Key</th><th>Secret Key</th><th>Ciphertext</th></tr>
<tr><td>QUAC_KEM_KYBER512</td><td>128-bit</td><td>800</td><td>1632</td><td>768</td></tr>
<tr><td>QUAC_KEM_KYBER768</td><td>192-bit</td><td>1184</td><td>2400</td><td>1088</td></tr>
<tr><td>QUAC_KEM_KYBER1024</td><td>256-bit</td><td>1568</td><td>3168</td><td>1568</td></tr>
</table>

<h3>Signature Algorithms</h3>
<table>
<tr><th>Algorithm</th><th>Security</th><th>Public Key</th><th>Secret Key</th><th>Signature</th></tr>
<tr><td>QUAC_SIGN_DILITHIUM2</td><td>Category 2</td><td>1312</td><td>2528</td><td>2420</td></tr>
<tr><td>QUAC_SIGN_DILITHIUM3</td><td>Category 3</td><td>1952</td><td>4000</td><td>3293</td></tr>
<tr><td>QUAC_SIGN_DILITHIUM5</td><td>Category 5</td><td>2592</td><td>4864</td><td>4595</td></tr>
</table>

<hr>
<p>Documentation generated by QUAC 100 SDK<br>
&copy; $(Get-Date -Format "yyyy") Dyber, Inc. - <a href="https://dyber.org">dyber.org</a></p>
</div>
</body>
</html>
"@
    
    $apiDoc | Out-File (Join-Path $OutputDir "index.html") -Encoding UTF8
    Write-Host "Basic documentation generated: $(Join-Path $OutputDir 'index.html')" -ForegroundColor Green
    
    if ($Open) {
        Start-Process (Join-Path $OutputDir "index.html")
    }
    
    exit 0
}

Write-Host "Using Doxygen: $doxygen" -ForegroundColor Gray

# Create Doxyfile
$doxyConfig = @"
PROJECT_NAME           = "QUAC 100 Windows Driver"
PROJECT_NUMBER         = 1.0.0
PROJECT_BRIEF          = "Post-Quantum Cryptographic Accelerator SDK"
OUTPUT_DIRECTORY       = $OutputDir
INPUT                  = $RootDir/include $RootDir/lib/quac100lib
FILE_PATTERNS          = *.h *.c
RECURSIVE              = YES
EXTRACT_ALL            = YES
EXTRACT_PRIVATE        = NO
EXTRACT_STATIC         = YES
GENERATE_HTML          = $(if ($Format -in @("HTML", "Both")) { "YES" } else { "NO" })
GENERATE_LATEX         = $(if ($Format -in @("PDF", "Both")) { "YES" } else { "NO" })
HTML_OUTPUT            = html
LATEX_OUTPUT           = latex
GENERATE_TREEVIEW      = YES
DISABLE_INDEX          = NO
FULL_SIDEBAR           = NO
HTML_COLORSTYLE        = LIGHT
HTML_EXTRA_STYLESHEET  = 
HAVE_DOT               = NO
"@

$doxyFile = Join-Path $env:TEMP "Doxyfile_quac100"
$doxyConfig | Out-File $doxyFile -Encoding ASCII

Write-Host "Generating documentation..." -ForegroundColor Yellow

# Run Doxygen
& $doxygen $doxyFile

if ($LASTEXITCODE -eq 0) {
    Write-Host "Documentation generated successfully!" -ForegroundColor Green
    Write-Host "Output: $OutputDir" -ForegroundColor Gray
    
    if ($Open) {
        $indexPath = Join-Path $OutputDir "html\index.html"
        if (Test-Path $indexPath) {
            Start-Process $indexPath
        }
    }
} else {
    Write-Error "Doxygen failed with exit code $LASTEXITCODE"
}

# Cleanup
Remove-Item $doxyFile -Force -ErrorAction SilentlyContinue
