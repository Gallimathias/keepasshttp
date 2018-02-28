"Start building"
function StartProcess($target, $argument) {
    $result = [System.Diagnostics.Process]::Start($target, $argument)

    $result.WaitForExit()
    if($result.ExitCode -ne 0)
    {
        $result.ExitCode
        exit
    }
}

$plgx = "KeePassHttp.plgx"

if([System.IO.File]::Exists($plgx)){
    "Remove old KeePassHttp.plgs"
    Remove-Item $plgx
}

$mono = "mono\KeePassHttp.dll"
if([System.IO.File]::Exists($mono)){
    "Remove old mono\KeePassHttp.dll"
    Remove-Item $mono
}

$msbuild = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe"
$KeePass = (get-item env:"ProgramFiles(x86)").Value + "\KeePass Password Safe 2\KeePass.exe"
$base = $PSScriptRoot + "\"

"Clean KeePassHttp.sln"
StartProcess  -target $msbuild -argument $("/target:clean `"" + $base + "KeePassHttp.sln`"")
"Clean finished"

"Create plgx"
StartProcess  -target $KeePass -argument $("--plgx-create `"" + $base + "KeePassHttp`"")
"Create finished"

"Build Release KeePassHttp"
StartProcess  -target $msbuild -argument $("/p:Configuration=Release `""+ $base +  "KeePassHttp.sln`"")
"Build finished"

"Copy KeePassHttp.dll to mono"
$path = "" + $base + "KeePassHttp\bin\Release\KeePassHttp.dll"
$destionation = "" + $base + "mono\"
Copy-Item -Path $path -Destination $destionation

"Building Complete"