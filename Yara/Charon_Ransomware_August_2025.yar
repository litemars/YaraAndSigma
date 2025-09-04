rule Charon_Ransomware_August_2025 {
    meta:
        description = "Detection rule for Charon ransomware targeting Middle East"
        author = "litemars"
        date = "2025-08-21"
        version = "1.0"
        reference = "Trend Micro Charon ransomware report"
        malware_family = "Charon"
        target_region = "Middle East"

    strings:
        // Mutex and distinctive strings
        $mutex = "OopsCharonHere" ascii
        $extension = ".charon" ascii
        $ransom_note = "How to Restore Your Files.txt" ascii wide

        // DLL sideloading components
        $dll1 = "msedge.dll" ascii
        $dll2 = "SWORDLDR" ascii
        $edge_exe = "Edge.exe" ascii
        $cookie_exp = "cookie_exporter.exe" ascii

        // Command line arguments
        $arg1 = "--debug=" ascii
        $arg2 = "--shares=" ascii
        $arg3 = "--paths=" ascii
        $arg4 = "--sf" ascii

        // Service names and processes targeted
        $svc1 = "WWC" ascii
        $driver_path = "\System32\Drivers\WWC.sys" ascii
        $svchost = "svchost.exe" ascii

        // Encryption related
        $curve25519 = "Curve25519" ascii
        $chacha20 = "ChaCha20" ascii

        // Anti-recovery actions
        $shadow1 = "vssadmin" ascii
        $shadow2 = "delete shadows" ascii
        $recycle = "Recycle Bin" ascii

        // Process injection patterns
        $injection = "Process Hollowing" ascii
        $ntdll = "ntdll.dll" ascii

    condition:
        uint16(0) == 0x5A4D and (
            (
                $mutex and ($extension or $ransom_note)
            ) or
            (
                ($dll1 or $dll2) and ($edge_exe or $cookie_exp)
            ) or
            (
                2 of ($arg*) and ($svchost or $driver_path)
            ) or
            (
                any of ($shadow*) and ($curve25519 or $chacha20)
            )
        ) and filesize < 20MB
}