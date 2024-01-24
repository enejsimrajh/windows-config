# Self-elevate the script
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-NoExit -File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -Wait -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

function Remove-App {
	param ([string] $AppName)
	Get-AppxPackage $AppName -AllUsers | Remove-AppxPackage
	Get-AppXProvisionedPackage -Online | Where-Object DisplayName -like $AppName | Remove-AppxProvisionedPackage -Online
}

$applicationList = @(
    "Clipchamp.Clipchamp"
    "Microsoft.549981C3F5F10" # Cortana
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingWeather"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MicrosoftStickyNotes"
    "Microsoft.OutlookForWindows"
    "Microsoft.Paint"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.Todos"
    "Microsoft.Windows.DevHome"
    "Microsoft.Windows.Photos"
    "Microsoft.WindowsAlarms"
    "Microsoft.WindowsCamera"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsStore"
    "Microsoft.YourPhone"
    "MicrosoftCorporationII.QuickAssist"
);

foreach ($app in $applicationList) {
    Remove-App $app
}
