rule Charon_DLL_Sideloading {
    meta:
        description = "Detects DLL sideloading technique used by Charon ransomware"
        author = "litemars"
        date = "2025-08-21"
        version = "1.0"
        malware_family = "Charon"

    strings:
        $sideload1 = "msedge.dll" ascii
        $sideload2 = "SWORDLDR" ascii
        $legitimate = "Edge.exe" ascii
        $original = "cookie_exporter.exe" ascii
        $shellcode = "encrypted shellcode" ascii

    condition:
        uint16(0) == 0x5A4D and (
            ($sideload1 or $sideload2) and ($legitimate or $original)
        ) and filesize < 5MB
}