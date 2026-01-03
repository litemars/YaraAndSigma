rule APT36_TransparentTribe_Adaptive_RAT
{
    meta:
        description = "Detects Transparent Tribe (APT36) adaptive RAT campaign with AV-specific persistence"
        author = "litemars"
        date = "2026-01-03"
        reference = "CYFIRMA - APT36 RAT Attacks Against Indian Government January 2026"
        threat_actor = "Transparent Tribe / APT36"
        target_countries = "India"
        mitre_attack = "T1566.001,T1204.002,T1218.005,T1547.001,T1082,T1518.001"
        severity = "high"
        
    strings:
        // LNK file magic and PDF masquerading
        $lnk_magic = {4C 00 00 00 01 14 02 00} // LNK header
        $pdf_embed = ".pdf.lnk" ascii wide
        $ncert_lure = "NCERT-Whatsapp-Advisory" ascii wide nocase
        
        // MSHTA execution patterns
        $mshta_exec1 = "mshta.exe" ascii wide nocase
        $mshta_exec2 = "mshta http" ascii wide nocase
        $mshta_vbscript = "WScript.Shell" ascii wide
        $activex_object = "ActiveXObject" ascii wide
        
        // RAT DLL name
        $rat_dll = "iinneldc.dll" ascii wide nocase
        $wininet_dll = "wininet.dll" ascii wide
        
        // Antivirus detection logic strings
        $av_kaspersky = "Kaspersky" ascii wide nocase
        $av_quickheal = "Quick Heal" ascii wide nocase
        $av_avast = "Avast" ascii wide nocase
        $av_avg = "AVG" ascii wide nocase
        $av_avira = "Avira" ascii wide nocase
        
        // AV-specific persistence paths
        $persist_kaspersky_path = "C:\\Users\\Public\\core\\" ascii wide
        $persist_startup = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ascii wide
        
        // Registry persistence indicators
        $reg_run_key1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg_run_key2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        
        // C2 endpoints with reversed strings
        $c2_register = "/retsiger" ascii wide // "register" reversed
        $c2_heartbeat = "/taebtraeh" ascii wide // "heartbeat" reversed
        $c2_getcommand = "/dnammoc_teg" ascii wide // "get_command" reversed
        $c2_antivmcommand = "/dnammocmvitna" ascii wide // "antivmcommand" reversed
        
        // C2 domain infrastructure
        $c2_domain1 = "wmiprovider.com" ascii wide nocase
        $c2_domain2 = "aeroclubofindia.co.in" ascii wide nocase
        $c2_domain3 = "dns.wmiprovider" ascii wide nocase
        
        // MSI installer name
        $msi_installer = "nikmights.msi" ascii wide nocase
        
        // PcDirvs campaign artifacts
        $pcdirvs_exe = "PcDirvs.exe" ascii wide
        $pcdirvs_hta = "PcDirvs.hta" ascii wide
        $pcdirvs_path = "C:\\ProgramData\\PcDirvs\\" ascii wide
        $pdf_dll = "pdf.dll" ascii wide
        
        // HTA obfuscation and payload deployment
        $vbscript_decode = "Chr(" ascii nocase
        $vbscript_execute = "Execute" ascii wide nocase
        $base64_decode = "Base64" ascii wide nocase
        
        // Command execution patterns
        $cmd_execute = "cmd.exe /c" ascii wide nocase
        $powershell_exec = "powershell.exe" ascii wide nocase
        
        // Decoy PDF display
        $decoy_pdf = "ShellExecute" ascii wide
        $open_pdf = ".pdf" ascii wide
        
        // Batch file persistence markers
        $batch_extension = ".bat" ascii wide
        $batch_timeout = "timeout /t" ascii wide nocase
        
    condition:
        // File type indicators
        (uint16(0) == 0x5A4D or uint32(0) == 0x0000004C or uint16(0) == 0x4B50) and
        
        (
            // LNK-based delivery chain
            (
                ($lnk_magic or $pdf_embed or $ncert_lure) and
                any of ($mshta_*) and
                2 of ($c2_*)
            )
            or
            // RAT DLL detection
            (
                ($rat_dll or $wininet_dll or $pcdirvs_exe) and
                3 of ($c2_*) and
                any of ($av_*)
            )
            or
            // Adaptive persistence mechanism
            (
                2 of ($av_*) and
                ($persist_kaspersky_path or $persist_startup) and
                any of ($reg_run_key*) and
                any of ($mshta_*)
            )
            or
            // C2 communication pattern
            (
                3 of ($c2_register, $c2_heartbeat, $c2_getcommand, $c2_antivmcommand) and
                any of ($c2_domain*)
            )
            or
            // Secondary campaign (NCERT/PcDirvs)
            (
                $ncert_lure and
                2 of ($pcdirvs_*) and
                ($msi_installer or $pdf_dll) and
                any of ($c2_domain*)
            )
        )
}
