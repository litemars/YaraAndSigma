rule APT_EndClient_RAT_Delivery {
    meta:
        description = "Detects EndClient RAT delivery via signed MSI package"
        author = "litemars"
        date = "2025-11-20"
        severity = "high"
        family = "EndClient RAT"
        apt_group = "Kimsuky"
        mitre_attack = "T1218.009,T1036.005,T1547.001,T1053.005"
        ioc_type = "malware"

    strings:
        // MSI installer related strings
        $msi_1 = "StressClear" nocase
        $msi_2 = ".msi" nocase
        $msi_3 = "msiexec" nocase
        
        // AutoIT script execution indicators
        $autoIt_1 = "AutoIt3.exe" nocase
        $autoIt_2 = "payload.au3" nocase
        $autoIt_3 = {FF 25 ?? ?? ?? ?? [0-32] FF 25} // AutoIT VM patterns
        
        // Persistence mechanisms
        $persist_1 = "\\Startup\\" nocase
        $persist_2 = "schtasks.exe" nocase
        $persist_3 = "hwpviewer.exe" nocase
        $persist_4 = "IoKlTr" nocase // Scheduled task name
        
        // C2 Communication markers
        $c2_1 = "endClient9688"
        $c2_2 = "endServer9688"
        $c2_3 = "116.202.99.218" // Known C2 IP
        
        // File operations
        $file_1 = "C:\\Users\\Public\\Music" nocase
        $file_2 = "C:\\ProgramData\\StressClear" nocase
        
        // Process manipulation
        $process_1 = "cmd.exe" nocase
        $process_2 = "svchost.exe" nocase
        
        // Mutex for single instance
        $mutex_1 = "AB732E15-D8DD-87A1-7464-CE6698819E70"
        
        // Base64 and LZMA compression indicators
        $encoding_1 = {48 8D ?? ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? FF 15} // x64 encode pattern
        $encoding_2 = "LZMA" nocase
        
        // JSON protocol markers in network communication
        $json_marker = {7B 22 [0-20] 7D} // "{...}" JSON structure
        
        // Antivirus evasion checks
        $av_check_1 = "Avast" nocase
        $av_check_2 = "AVG" nocase

    condition:
        (
            // Delivery mechanism: Signed MSI with AutoIT
            ($msi_1 or $msi_2) and ($autoIt_1 or $autoIt_2)
        ) or
        (
            // Persistence indicators combined
            ($persist_1 or $persist_3) and ($persist_4 or "IoKlTr")
        ) or
        (
            // C2 communication pattern
            ($c2_1 and $c2_2) or $c2_3
        ) or
        (
            // File operations + process manipulation
            ($file_1 or $file_2) and ($process_1 and $process_2)
        ) or
        (
            // Mutex + encoding mechanisms
            $mutex_1 and ($encoding_1 or $encoding_2)
        )
}