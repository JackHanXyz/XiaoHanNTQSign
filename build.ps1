# 构建 XiaoHanNTQSign 离线签名服务（x64 控制台程序）
# 用法：powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"

$root    = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir  = Join-Path $root "src"
$outDir  = Join-Path $root "build"
$out     = Join-Path $outDir "xhntqsign.exe"

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# 依次尝试：MSYS2 固定路径 → PATH。
# 显式累加，避免单元素数组被 PowerShell 展开成字符串。
$candidates = @()
foreach ($p in @("D:\msys64\mingw64\bin\g++.exe",
                 "C:\msys64\mingw64\bin\g++.exe")) {
    if (Test-Path $p) { $candidates += $p }
}
$cmd = Get-Command "g++.exe" -ErrorAction SilentlyContinue
if ($cmd) { $candidates += $cmd.Source }
if ($candidates.Count -eq 0) {
    Write-Error "未找到 g++.exe。请先安装 MinGW-w64（本机可用 D:\msys64\mingw64 下的 GCC）"
}
$gpp = $candidates[0]
Write-Host "使用编译器：$gpp"

# g++ 会调用同目录的 cc1plus/as/ld，必须把该目录放进 PATH，
# 否则辅助进程会因找不到 libgmp 等 DLL 而静默失败。
$gppDir = Split-Path -Parent $gpp
$env:PATH = "$gppDir;$env:PATH"

$sources = Get-ChildItem $srcDir -Filter *.cpp | Select-Object -ExpandProperty FullName

& $gpp -std=c++17 -O2 -Wall -Wextra -static `
    -o $out $sources `
    -lws2_32 -lbcrypt

if ($LASTEXITCODE -ne 0) { Write-Error "编译失败（exit=$LASTEXITCODE）" }

$item = Get-Item $out
Write-Host ("构建完成：{0}  ({1:N0} 字节)" -f $item.FullName, $item.Length)