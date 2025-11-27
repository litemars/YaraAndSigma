rule APT_ShadowPad_Backdoor_Loader {
    meta:
        description = "Detects ShadowPad backdoor DLL loader used by China-linked APT groups"
        author = "litemars"
        date = "2025-11-27"
        severity = "critical"
        tlp = "white"
        mitre_attack = "T1574.002, T1547.001, T1059.003"
        apt_group = "APT41, Bronze Atlas"
        campaign = "ShadowPad WSUS RCE CVE-2025-59287"
        
    strings:
        // DLL sideloading patterns - ETDCtrlHelper.exe loads ETDApix.dll
        $dll_load1 = "ETDCtrlHelper.exe" ascii wide
        $dll_load2 = "ETDApix.dll" ascii wide
        
        // ShadowPad specific persistence patterns
        $persist1 = "Q-X64" ascii wide
        $persist2 = ".tmp" ascii wide
        $sched_task = /SchTasks.*\/create|schtasks.*\/create/i
        
        // C2 communication patterns
        $c2_ua = "Mozilla/5.0" ascii wide
        $c2_firefox = "Firefox" ascii wide
        $http_get = "GET " ascii
        $http_post = "POST " ascii
        
        // Registry persistence paths
        $reg_run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg_runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
        
        // Encoded payload patterns
        $base64_1 = /[A-Za-z0-9+\/]{64,}/
        
        // Process injection indicators
        $inject1 = "CreateRemoteThread" ascii wide
        $inject2 = "VirtualAllocEx" ascii wide
        $inject3 = "WriteProcessMemory" ascii wide
        
        // UAC bypass techniques
        $uac_bypass = "Token Impersonation" ascii wide
        $elevation = "SeDebugPrivilege" ascii wide
        
    condition:
        (uint16(0) == 0x5a4d) and
        (
            (any of ($dll_load*)) or
            (any of ($persist*)) or
            (all of ($inject*)) or
            ($sched_task and any of ($reg_*))
        ) and
        (any of ($c2_*) or any of ($http_*))
}

rule APT_ShadowPad_C2_Communication {
    meta:
        description = "Detects ShadowPad C2 communication patterns via DNS tunneling and HTTPS"
        author = "litemars"
        date = "2025-11-27"
        severity = "critical"
        
    strings:
        // Known C2 domain patterns
        $c2_domain1 = "dscriy.chtq.net" nocase ascii
        $c2_domain2 = "cybaq.chtq.net" nocase ascii
        $c2_domain3 = "chtq.net" nocase ascii
        
        // Known C2 IPs
        $c2_ip1 = "158.247.199.185" ascii
        $c2_ip2 = "163.61.102.245" ascii
        
        // DNS tunneling TXT query pattern
        $dns_txt = /TXT.*chtq\.net/i
        
        // HTTP Tunnel indicator
        $tunnel = "HTTP/1.1" ascii
        
    condition:
        any of ($c2_domain*) or any of ($c2_ip*) or $dns_txt or $tunnel
}