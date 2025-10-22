rule APT_Tickler_Backdoor_Peach_Sandstorm
{
    meta:
        description = "Detects Tickler malware used by Peach Sandstorm (APT33)"
        author = "litemars"
        date = "2025-09-04"
        reference = "https://www.microsoft.com/en-us/security/blog/2024/08/28/peach-sandstorm-deploys-new-custom-tickler-malware-in-long-running-intelligence-gathering-operations/"
        threat_actor = "Peach Sandstorm / APT33"
        malware_family = "Tickler"
        hash1 = "7eb2e9e8cd450fc353323fd2e8b84fbbdfe061a8441fd71750250752c577d198"
        hash2 = "ccb617cc7418a3b22179e00d21db26754666979b4c4f34c7fda8c0082d08cec4"
        hash3 = "5df4269998ed79fbc997766303759768ce89ff1412550b35ff32e85db3c1f57b"

    strings:
        $peb_traversal = { 65 48 8B 04 25 60 00 00 00 }  // PEB traversal technique
        $kernel32_decrypt = "kernell32.dll" wide ascii  // Typo in kernel32 decryption
        $loadlibrary_decrypt = "LoadLibraryA" wide ascii
        $c2_domains1 = "azurewebsites.net" wide ascii
        $c2_domains2 = "satellite" wide ascii
        $c2_domains3 = "support" wide ascii
        $network_info = "systeminfo" wide ascii
        $yahsat_string = "YAHSAT" wide ascii
        $pdf_decoy = ".pdf.exe" wide ascii
        $commands1 = "run" wide ascii
        $commands2 = "delete" wide ascii
        $commands3 = "upload" wide ascii
        $commands4 = "download" wide ascii
        $commands5 = "interval" wide ascii
        $registry_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $sharepoint_exe = "SharePoint.exe" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($peb_traversal and $kernel32_decrypt and $loadlibrary_decrypt) or
            (3 of ($c2_domains*)) or
            ($yahsat_string and $pdf_decoy) or
            (4 of ($commands*) and $registry_key) or
            ($sharepoint_exe and $registry_key)
        ) and
        filesize < 5MB
}
