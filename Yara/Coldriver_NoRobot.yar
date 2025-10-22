rule COLDRIVER_NOROBOT_Downloader
{
    meta:
        description = "Detects NOROBOT malicious DLL downloader used by COLDRIVER APT"
        author = "litemars"
        date = "2025-10-22"
        reference = "Google GTIG Report - COLDRIVER ROBOT Malware"
        threat_actor = "COLDRIVER (Star Blizzard, UNC4057, Callisto)"
        hash1 = "2e74f6bd9bf73131d3213399ed2f669ec5f75392de69edf8ce8196cd70eb6aee"
        hash2 = "3b49904b68aedb6031318438ad2ff7be4bf9fd865339330495b177d5c4be69d1"
        
    strings:
        // DLL export function names mimicking CAPTCHA verification
        $export1 = "humanCheck" ascii
        $export2 = "verifyme" ascii
        
        // Known DLL filenames
        $dll_name1 = "iamnotarobot.dll" ascii wide
        $dll_name2 = "checkme.dll" ascii wide
        $dll_name3 = "machinerie.dll" ascii wide
        
        // C2 communication paths observed in NOROBOT variants
        $path1 = "/konfiguration12/" wide
        $path2 = "/reglage/avec" wide
        $path3 = "/erreur" wide
        
        // File retrieval strings
        $file1 = "arbeiter" wide
        $file2 = "schlange" wide
        $file3 = "gesundheitA" wide
        $file4 = "gesundheitB" wide
        
        // Registry key persistence indicator
        $reg_key = "HKEY_CURRENT_USER\\SOFTWARE\\Classes\\.pietas" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (
            (pe.is_dll and any of ($export*)) or
            any of ($dll_name*) or
            (2 of ($path*)) or
            (3 of ($file*)) or
            $reg_key
        )
}

rule COLDRIVER_YESROBOT_Python_Backdoor
{
    meta:
        description = "Detects YESROBOT Python-based backdoor (short-lived variant)"
        author = "litemars"
        date = "2025-10-22"
        reference = "Google GTIG Report - COLDRIVER ROBOT Malware"
        threat_actor = "COLDRIVER"
        
    strings:
        // Unique Python code patterns from YESROBOT
        $py1 = "return f'Mozilla/5.0 {base64.b64encode(str(get_machine_name()).encode()).decode()}" ascii
        $py2 = "'User-Agent': obtainUA()," ascii
        $py3 = "url = f\"https://{target}/connect\"" ascii
        $py4 = "print(f'{target} is not availible')" ascii
        $py5 = "tgtIp = check_targets(tgtList)" ascii
        $py6 = "cmd_url = f'https://{tgtIp}/command'" ascii
        $py7 = "print('There is no availible servers...')" ascii
        
        // Associated Python library files
        $lib1 = "libsystemhealthcheck.py" ascii wide
        $lib2 = "libcryptopydatasize.py" ascii wide
        
    condition:
        filesize < 500KB and
        (
            4 of ($py*) or
            any of ($lib*)
        )
}

rule COLDRIVER_MAYBEROBOT_Powershell_Backdoor
{
    meta:
        description = "Detects MAYBEROBOT PowerShell backdoor used by COLDRIVER"
        author = "litemars"
        date = "2025-10-22"
        reference = "Google GTIG Report - COLDRIVER ROBOT Malware"
        threat_actor = "COLDRIVER (Star Blizzard, UNC4057, Callisto)"
        hash = "b60100729de2f468caf686638ad513fe28ce61590d2b0d8db85af9edc5da98f9"
        
    strings:
        // Obfuscation pattern unique to MAYBEROBOT
        $obfuscation = "-replace '\\n', ';' -replace '[^\\x20-\\x7E]', '' -replace '(?i)x[0-9A-Fa-f]{4}', '' -split \"\\n\"" ascii wide
        
        // PowerShell command execution patterns
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "Invoke-Expression" ascii wide nocase
        $cmd3 = "IEX" ascii wide
        $cmd4 = "DownloadString" ascii wide nocase
        
        // Registry-based logon script persistence
        $persist = "UserInitMprLogonScript" ascii wide nocase
        
    condition:
        filesize < 2MB and
        (
            $obfuscation or
            ($persist and 2 of ($cmd*))
        )
}

rule COLDRIVER_COLDCOPY_ClickFix_Lure
{
    meta:
        description = "Detects COLDCOPY ClickFix HTML lure delivering NOROBOT"
        author = "litemars"
        date = "2025-10-22"
        reference = "Google GTIG Report - COLDRIVER ROBOT Malware"
        threat_actor = "COLDRIVER"
        hash = "c4d0fba5aaafa40aef6836ed1414ae3eadc390e1969fdcb3b73c60fe7fb37897"
        
    strings:
        // Fake CAPTCHA verification strings
        $captcha1 = "verify that you are not a robot" ascii wide nocase
        $captcha2 = "I am not a robot" ascii wide nocase
        
        // Rundll32 execution command in HTML
        $rundll = "rundll32" ascii wide nocase
        
        // ClickFix-style PowerShell execution
        $clickfix = "powershell" ascii wide nocase
        
    condition:
        filesize < 100KB and
        any of ($captcha*) and
        ($rundll or $clickfix)
}
