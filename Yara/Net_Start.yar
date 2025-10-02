rule NET_STAR_IIServerCore {
    meta:
        description = "Detects Phantom Taurus NET-STAR IIServerCore backdoor"
        author      = "litemars"
        date        = "2025-10-02"
        hash_sha256 = "eeed5530fa1cdeb69398dc058aaa01160eab15d4dcdcd6cb841240987db284dc"
    strings:
        $mz_header    = { 4D 5A }                          // PE header "MZ"
        $s_iiscore    = "IIServerCore" ascii wide
        $s_netstar    = "NET-STAR" ascii
    condition:
        pe and hash.sha256(0, filesize) == hash_sha256 or
        (pe and $mz_header at 0 and any of ($s_iiscore, $s_netstar))
}
