<#
.SYNOPSIS
    Environmental mitigation patch for CLOSEDQUORUM autonomous AI malware.
    Targets the 'Steal', 'Inject', and 'Persist' modules.
#>

Requires -RunAsAdministrator

Write-Host "Applying CLOSEDQUORUM Mitigations..." -ForegroundColor Cyan

# 1. Neutralize "Steal" Module: Enable LSA Protection (RunAsPPL)
# Prevents the malware from dumping Windows credentials from LSASS memory.
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$name = "RunAsPPL"
$value = 1
If (!(Test-Path $registryPath)) { New-Item -Path $registryPath -Force | Out-Null }
Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWord
Write-Host "[+] LSA Protection Enabled (Requires Reboot to take full effect)" -ForegroundColor Green

# 2. Neutralize "Persist" & "Inject" Modules: Enable specific ASR Rules
# Blocks process hollowing/injection and restricts WMI abuse.
$asrRules = @{
    "Block process creations originating from PSExec and WMI commands" = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
    "Block credential stealing from the Windows local security authority subsystem" = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
    "Block execution of potentially obfuscated scripts" = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
}

foreach ($rule in $asrRules.GetEnumerator()) {
    # 1 = Block mode
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Value -AttackSurfaceReductionRules_Actions 1
    Write-Host "[+] ASR Rule applied: $($rule.Key)" -ForegroundColor Green
}

# 3. Network Triage (Optional): Null-route C2 voting nodes and Discord Webhooks via Hosts file
# Note: As the Talos analyst noted, legitimate apps use these, so apply only to critical servers.
$nullRouteIP = "0.0.0.0"
$c2Domains = @("api.deepseek.com", "openrouter.ai", "api.mistral.ai", "generativelanguage.googleapis.com", "discord.com/api/webhooks")
$hostsFile = "$env:windir\System32\drivers\etc\hosts"

foreach ($domain in $c2Domains) {
    $entry = "$nullRouteIP $domain"
    if (!(Select-String -Path $hostsFile -Pattern $domain -Quiet)) {
        Add-Content -Path $hostsFile -Value $entry
    }
}
Write-Host "[+] Null-routed LLM APIs and Webhooks in Hosts file (Monitor for false positives)" -ForegroundColor Yellow
Write-Host "Patch applied successfully." -ForegroundColor Cyan
