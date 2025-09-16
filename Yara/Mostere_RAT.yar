rule APT_MostereRAT_Banking_Trojan {
    meta:
        description = "Detects MostereRAT banking trojan turned RAT targeting Japanese users"
        author = "litemars"
        date = "2025-09-11"
        reference = "Fortinet MostereRAT Analysis"
        severity = "high"
        mitre_attack = "T1055, T1562.001, T1071.001, T1056.001"
        malware_family = "MostereRAT"
        
    strings:
        // EPL (Easy Programming Language) indicators
        $epl1 = "易语言" ascii wide  // Chinese for "Easy Language"
        $epl2 = ".epk" ascii wide
        $epl3 = "EPL" ascii wide
        
        // Remote access tools
        $rat1 = "AnyDesk" ascii wide nocase
        $rat2 = "TightVNC" ascii wide nocase  
        $rat3 = "TigerVNC" ascii wide nocase
        $rat4 = "RDP Wrapper" ascii wide nocase
        
        // Network blocking/evasion
        $block1 = "Windows Filtering Platform" ascii wide
        $block2 = "WFP" ascii wide
        $block3 = "EDRSilencer" ascii wide
        
        // System manipulation
        $system1 = "TrustedInstaller" ascii wide
        $system2 = "SeDebugPrivilege" ascii wide
        $system3 = "svchost.exe" ascii wide
        $system4 = "Early Bird Injection" ascii wide
        
        // Alibaba tool monitoring
        $alibaba1 = "Qianniu" ascii wide
        $alibaba2 = "千牛" ascii wide  // Chinese characters for Qianniu
        
        // Command and control
        $c2_1 = "CreateSvcRpc" ascii wide
        $c2_2 = "mutual TLS" ascii wide
        $c2_3 = "mTLS" ascii wide
        
        // File paths and names
        $path1 = "ProgramData\\Windows" ascii wide
        $path2 = "\\system32\\" ascii wide
        
        // Hex patterns for mTLS and encryption
        $tls_pattern = { 16 03 ?? ?? 02 00 00 ?? 03 03 }  // TLS handshake
        $enc_pattern = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 }  // Common encryption routine
        
    condition:
        (
            // EPL language indicators
            (1 of ($epl*)) or
            // Remote access tools
            (2 of ($rat*)) or
            // System manipulation techniques
            (2 of ($system*)) or
            // Network evasion
            (1 of ($block*)) or
            // Alibaba monitoring
            (1 of ($alibaba*)) or
            // C2 communication
            (1 of ($c2_*))
        ) and filesize < 5MB
}
