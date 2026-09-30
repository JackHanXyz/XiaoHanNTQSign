# 构建 XiaoHanQQNT 原生注入模块（x64 DLL）
# 用法：powershell -ExecutionPolicy Bypass -File native\build.ps1
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir = Join-Path $root "src"
$outDir = Join-Path $root "build"
$out = Join-Path $outDir "XHQNative_x64.dll"

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# 依次尝试：MSYS2 固定路径 → PATH → WinGet 安装目录
# 注意用显式累加，避免单元素数组被 PowerShell 展开成字符串
$candidates = @()
foreach ($p in @("D:\msys64\mingw64\bin\x86_64-w64-mingw32-gcc.exe",
                 "C:\msys64\mingw64\bin\x86_64-w64-mingw32-gcc.exe")) {
    if (Test-Path $p) { $candidates += $p }
}

$cmd = Get-Command "x86_64-w64-mingw32-gcc.exe" -ErrorAction SilentlyContinue
if ($cmd) { $candidates += $cmd.Source }

if ($candidates.Count -eq 0) {
    $candidates += Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" `
        -Recurse -Filter "x86_64-w64-mingw32-gcc.exe" -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
}

if ($candidates.Count -eq 0) {
    Write-Error "未找到 x86_64-w64-mingw32-gcc.exe。请先安装 MinGW-w64（本机可用 D:\msys64\mingw64 下的 GCC）"
}
$gcc = $candidates[0]
Write-Host "使用编译器：$gcc"

# gcc 会调用同目录下的 cc1.exe / as.exe / ld.exe，必须把它们所在目录放进 PATH，
# 否则这些辅助进程会因为找不到 libgmp 等 DLL 而静默失败（exit 1 且无任何输出）。
$gccDir = Split-Path -Parent $gcc
$env:PATH = "$gccDir;$env:PATH"

& $gcc -O2 -s -shared -static-libgcc -Wall -Wextra `
    -o $out (Get-ChildItem $srcDir -Filter *.c | Select-Object -ExpandProperty FullName) `
    -lkernel32

if ($LASTEXITCODE -ne 0) { Write-Error "编译失败（exit=$LASTEXITCODE）" }

$item = Get-Item $out
Write-Host ("构建完成：{0}  ({1:N0} 字节)" -f $item.FullName, $item.Length)