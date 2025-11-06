rule ShadowPad_Modular_Backdoor {
    meta:
        title = "ShadowPad Modular Backdoor - Chinese APT Groups"
        description = "Detects ShadowPad modular backdoor with ScatterBrain obfuscation deployed by APT41 and related Chinese threat actors in global supply chain operations"
        author = "litemars"
        date = "2025-11-06"
        modified = "2025-11-06"
        version = "1.0"
        reference = "https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/"
        mitre_attack = "T1193,T1566.002,T1190,T1195,T1036"
        
    strings:
        $modular_api1 = "GetProcAddress" wide
        $modular_api2 = "LoadLibraryA" wide
        $obfuscation_cfg1 = "ScatterBrain" wide
        $obfuscation_cfg2 = "ScatterBee" wide
        $anti_debug1 = "IsDebuggerPresent" wide
        $anti_debug2 = "CheckRemoteDebuggerPresent" wide
        $control_flow_flatten = {BA ?? ?? ?? ?? 89 C1 FF E0}
        $dll_hijack1 = ".tmp" wide
        $dll_hijack2 = "AppSov.exe" wide
        $c2_domain1 = "dscriy.chtq.net" wide
        $c2_domain2 = "updata.dsqurey.com" wide
        $c2_domain3 = "network.oossafe.com" wide
        $c2_domain4 = "notes.oossafe.com" wide
        $c2_command1 = "cmd.exe" wide
        $c2_command2 = "powershell.exe" wide
        $exfil_zip = "7z.exe" wide
        $exfil_archive = ".tmp" wide
        $persistence_wmi = "WmiPrvSe.exe" wide
        $config_decrypt_verify = {89 D1 BA ?? ?? ?? ??}
        
    condition:
        (uint16(0) == 0x5A4D) and
        (filesize > 80KB and filesize < 2MB) and
        (($modular_api1 and $modular_api2) or ($obfuscation_cfg1 or $obfuscation_cfg2)) and
        ($anti_debug1 or $anti_debug2 or $control_flow_flatten) and
        (($dll_hijack1 or $dll_hijack2) or any of ($c2_domain*)) and
        (($exfil_zip and $exfil_archive) or ($persistence_wmi))
}
