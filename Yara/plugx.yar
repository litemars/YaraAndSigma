rule PlugX_UNC6384_Detection {
    meta:
        title = "PlugX RAT (SOGU.SEC) - UNC6384 Campaign"
        description = "Detects PlugX Remote Access Trojan (SOGU.SEC variant) deployed by UNC6384 in recent diplomatic espionage campaigns targeting European diplomatic entities"
        author = "litemars"
        date = "2025-11-06"
        modified = "2025-11-06"
        version = "1.0"
        reference = "https://arcticwolf.com/resources/blog/unc6384-weaponizes-zdi-can-25373-vulnerability-to-deploy-plugx/"
        hash_sha256 = "3fe6443d464f170f13d7f484f37ca4bcae120d1007d13ed491f15427d9a7121f"
        hash_md5 = "dc1dba02ab1020e561166aee3ee8f5fb"
        compilation_timestamp = "2025-09-05T05:15:45Z"
        mitre_attack = "T1547.010,T1059.003,T1571,T1041"
        
    strings:
        $export_msgini = "MSGInitialize" wide
        $export_func1 = "SetWindowLongA" wide
        $export_func2 = "CallWindowProcA" wide
        $registry_path1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $registry_path2 = "Software\\Classes\\CLSID" wide
        $c2_beacon1 = "POST" wide
        $c2_beacon2 = "HTTP/1.1" wide
        $loader_parent1 = "rundll32.exe" wide nocase
        $loader_parent2 = "regsvcs.exe" wide nocase
        $dll_sideload1 = "Canon" wide
        $dll_sideload2 = "Adobe" wide
        $technique_injection = "VirtualAllocEx" wide
        $technique_injection2 = "WriteProcessMemory" wide
        $technique_injection3 = "CreateRemoteThread" wide
        $usb_search = "USB" wide
        $usb_device = "RECYCLER.BIN" wide
        $control_flow_pattern1 = {48 8B 45 F0 48 8B 08 FF 51 20}
        $control_flow_pattern2 = {E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB}
        
    condition:
        (uint16(0) == 0x5A4D) and
        (filesize > 100KB and filesize < 2MB) and
        ($export_msgini) and
        (($technique_injection and $technique_injection2 and $technique_injection3) or
         ($c2_beacon1 and $c2_beacon2) or
         (($dll_sideload1 or $dll_sideload2) and ($loader_parent1 or $loader_parent2)))
}