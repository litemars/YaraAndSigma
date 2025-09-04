rule GodRAT_Steganography_Loader {
    meta:
        description = "Detects GodRAT loaders using steganography in images"
        author = "litemars"
        date = "2025-08-21"
        version = "1.0"
        malware_family = "GodRAT"

    strings:
        $stego1 = ".jpg" ascii
        $stego2 = ".jpeg" ascii
        $stego3 = "SDL2.dll" ascii
        $stego4 = "Valve.exe" ascii
        $cert_serial = "084caf4df499141d404b7199aa2c2131" ascii
        $cert_subject = "Valve" ascii
        $extract_func = "PluginMe" ascii

    condition:
        uint16(0) == 0x5A4D and (
            (
                any of ($stego*) and ($cert_serial or $cert_subject)
            ) or
            (
                $extract_func and any of ($stego*)
            )
        ) and filesize < 5MB
}