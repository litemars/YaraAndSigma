rule MiniJunk_UserEnv_DLL_Loader
{
    meta:
        description = "Detects MiniJunk implant loading via userenv.dll backdoor"
        author      = "litemars"
        date        = "2025-09-25"
        reference   = "Check Point Research UNC1549 MiniJunk variant"
        threat      = "UNC1549 (Nimbus Manticore)"
    strings:
        // Suspicious import resolution pattern and backdoor name
        $s1 = "userenv.dll" wide ascii
        $s2 = "DLLMain" wide ascii
        $s3 = { 68 ?? ?? ?? 00 6A 00 6A 04 6A 00 6A 00 } // typical API resolution stub
    condition:
        uint16(0) == 0x5A4D and       // PE header MZ
        all of ($s*) and               // contains importer strings
        filesize < 5MB                 // reasonable implant size
}
