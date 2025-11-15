rule Kalambur_Backdoor_Detection {
    meta:
        author = "litemars"
        date = "2025-11-13"
        description = "Detects Kalambur RDP backdoor malware (Sandworm)"
        malware_type = "backdoor"
        threat_level = "critical"
        mitre_techniques = "T1021.001, T1090, T1573, T1071.001"
        reference = "https://blog.eclecticiq.com/sandworm-apt-kalambur-backdoor"
        
    strings:
        $header = "MZ"
        
        // Kalambur-specific strings
        $name1 = "kalambur" nocase
        $name2 = "kalambur2021" nocase
        $name3 = "WindowsUpdateCheck" nocase
        
        // C# metadata (System.Reflection for .NET)
        $dotnet_marker = ".NET"
        
        // TOR-related strings
        $tor_proxy1 = "socks5h://" nocase
        $tor_proxy2 = "socks5://" nocase
        $tor_proxy3 = "socks4a://" nocase
        $onion_domain = ".onion" nocase
        
        // curl command
        $curl = "curl.exe" nocase
        
        // OpenSSH strings
        $openssh1 = "Win32-OpenSSH" nocase
        $openssh2 = "ssh" nocase
        
        // PowerShell execution
        $powershell = "powershell" nocase
        $scheduled_task = "schtasks" nocase
        
        // RDP setup
        $rdp_port = "3389"
        $rdp_setup = "mstsc" nocase
        
        // Domain reference
        $c2_domain = "kalambur.net" nocase
        
    condition:
        uint16($header) == 0x5a4d and
        (
            (any of ($name*) and $c2_domain) or
            (all of ($tor_proxy*) and $onion_domain) or
            ($curl and $tor_proxy1 and $onion_domain) or
            (all of ($openssh*) and $powershell and $scheduled_task)
        )
}

rule Kalambur_FileHash_Known_Sample {
    meta:
        author = "litemars"
        date = "2025-11-13"
        description = "Detects known Kalambur samples by hash"
        threat_level = "critical"
        
    condition:
        hash.sha256(0, filesize) == "aadd85e88c0ebb0a3af63d241648c0670599c3365ff7e5620eb8d06902fdde83"
}