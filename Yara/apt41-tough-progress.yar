rule APT41_ToughProgress
{
    meta:
        description = "Detects components of APT41 ToughProgress malware"
        author = "litemars"
        date = "2025-09-18"
        reference = "Resecurity APT41 report"

    strings:
        // Malware module names
        $s1 = "ToughProgress"
        $s2 = "PLUSDROP"
        $s3 = "PLUSINJECT"

        // XOR decryption routine reference
        $s4 = { 31 C0 80 34 06 XX 88 04 06 }   // XOR loop pattern

        // Google Calendar C2 indicators
        $url1 = "msapp.workers.dev"
        $url2 = "trycloudflare.com"
        $url3 = "infinityfreeapp.com"

    condition:
        // Must match at least two unique strings
        uint16(0) == 0x5A4D and
        2 of ($s*) and
        1 of ($url*)
}
