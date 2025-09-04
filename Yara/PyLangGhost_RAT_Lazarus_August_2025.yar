rule PyLangGhost_RAT_Lazarus_August_2025 {
    meta:
        description = "Detection rule for PyLangGhost RAT used by Lazarus Group"
        author = "litemars"
        date = "2025-08-21"
        version = "1.0"
        reference = "Various security reports on PyLangGhost RAT"
        malware_family = "PyLangGhost"
        threat_actor = "Lazarus Group/Famous Chollima"

    strings:
        // Python-specific strings
        $py1 = "nvidia.py" ascii
        $py2 = "csshost.exe" ascii
        $py3 = "api.py" ascii
        $py4 = "command.py" ascii
        $py5 = "util.py" ascii
        $py6 = "auto.py" ascii
        $py7 = "config.py" ascii

        // Registry persistence
        $reg1 = "Software\Microsoft\Windows\CurrentVersion\Run" ascii
        $reg2 = "csshost" ascii

        // Command patterns from ClickFix campaign
        $cmd1 = "curl -k -o" ascii
        $cmd2 = "nvidiaRelease.zip" ascii
        $cmd3 = "Expand-Archive -Force" ascii
        $cmd4 = "update.vbs" ascii
        $cmd5 = "360scanner.store" ascii

        // C2 communication
        $c2_1 = "qpwoe" ascii
        $http_post = "POST" ascii

        // Browser targeting
        $chrome1 = "Chrome" ascii
        $chrome2 = "Login Data" ascii
        $chrome3 = "Local State" ascii
        $meta1 = "MetaMask" ascii
        $coinbase = "Coinbase Wallet" ascii

        // VBScript components
        $vbs1 = "Lib.zip" ascii
        $vbs2 = "wscript" ascii

    condition:
        (
            3 of ($py*) and ($reg1 or $reg2)
        ) or (
            2 of ($cmd*) and any of ($vbs*)
        ) or (
            $c2_1 and $http_post and any of ($chrome*)
        ) and filesize < 50MB
}