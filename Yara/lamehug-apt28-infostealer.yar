rule LameHug_APT28_Infostealer {
    meta:
        author = "litemars"
        description = "Detects LameHug infostealer malware linked to APT28 (Fancy Bear). LameHug integrates AI-generated commands via Hugging Face LLM API for dynamic reconnaissance and data exfiltration."
        date = "2025-10-30"
        version = "1.0"
        mitre_attack = "T1059.006, T1036, T1082, T1057, T1016, T1087.002, T1083, T1005, T1074, T1048, T1041, T1567"
        threat_level = "CRITICAL"
    
    strings:
        // PyInstaller packaged indicators
        $pyi_marker = "PyInstaller"
        $pyi_boot = "pyi-bootloader"
        
        // LameHug-specific API interactions with Hugging Face
        $hf_api_endpoint = "api-inference.huggingface.co" wide
        $hf_api_call = "huggingface" nocase wide
        $qwen_model = "Qwen2.5-Coder-32B-Instruct" wide
        
        // Reconnaissance command patterns
        $systeminfo_cmd = "systeminfo" nocase
        $tasklist_cmd = "tasklist" nocase
        $ipconfig_cmd = "ipconfig" nocase
        $dsquery_cmd = "dsquery" nocase
        $net_start_cmd = "net start" nocase
        
        // Data staging paths
        $staging_path = "C:\\ProgramData\\info" nocase
        $staging_path2 = "%ProgramData%\\info" wide
        
        // Exfiltration endpoints
        $sftp_host = "144.126.202.227"
        $http_exfil = "stayathomeclasses.com/slpw/up.php" wide
        
        // Phishing delivery indicators
        $double_ext_pif = ".pif" wide
        $zip_archive = "Appendix.pdf.zip" wide
        $Ukrainian_zip = "Додаток.pdf.zip" wide
        
        // Base64 encoded command markers
        $b64_encoded = "base64"
        
        // Python function names from LameHug
        $llm_query_func = "LLM_Query_EX"
        $ssh_send_func = "ssh_send"
        $exfil_func = "send"
        
        // File operations patterns
        $fileread_exec = {8B 08 81 F1}  // Inline file read operations
        $copy_operations = "xcopy" nocase

    condition:
        // Must contain PyInstaller packaging
        any of ($pyi*) and
        
        // Must show Hugging Face API communication
        any of ($hf*) and
        
        // Must contain multiple reconnaissance commands or staging paths
        (
            (2 of ($systeminfo_cmd, $tasklist_cmd, $ipconfig_cmd, $dsquery_cmd, $net_start_cmd)) or
            any of ($staging_path*)
        ) and
        
        // Must contain exfiltration indicators
        (
            any of ($sftp_host, $http_exfil) or
            any of ($ssh_send_func, $exfil_func)
        )
}
