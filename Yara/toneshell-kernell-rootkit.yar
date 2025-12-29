rule APT_HoneyMyte_ToneShell_KernelRootkit_Dec2025
{
    meta:
        description = "Detects HoneyMyte APT kernel-mode rootkit driver delivering ToneShell backdoor"
        author = "litemars"
        date = "2025-12-29"
        target_geographies = "Southeast Asia, East Asia, Myanmar, Thailand"
        severity = "critical"
        
    strings:
        // Compromised digital certificate indicators
        $cert_serial = {08 01 CC 11 EB 4D 1D 33 1E 3D 54 0C 55 A4 9F 7F}
        $cert_subject = "Guangzhou Kingteller Technology" ascii wide
        
        // Driver service registry key name
        $driver_name1 = "ProjectConfiguration" ascii wide
        $driver_name2 = "ProjectConfiguration\\Instances" wide
        
        // Mini-filter altitude manipulation strings
        $altitude_format = "330024.%l" ascii wide
        $wdfilter_target = "WdFilter" ascii wide nocase
        
        // Protected registry paths
        $reg_protect1 = "ProjectConfiguration Instance" wide
        
        // File protection via mini-filter callbacks
        $filter_register = {FF 15 ?? ?? ?? ?? 85 C0 0F 88} // FltRegisterFilter pattern
        $irp_setinfo = {81 F9 0D 00 00 00} // IRP_MJ_SET_INFORMATION comparison
        
        // Process protection callback registration
        $ob_register = "ObRegisterCallbacks" ascii
        $ps_notify = "PsSetCreateProcessNotifyRoutine" ascii
        $cm_register = "CmRegisterCallbackEx" ascii
        
        // Kernel API dynamic resolution via hash
        $ntoskrnl = "ntoskrnl.exe" ascii
        $fltmgr = "fltmgr.sys" ascii
        $zwquery_sys = "ZwQuerySystemInformation" ascii
        
        // Host ID file path used by ToneShell payload
        $host_id_path = "C:\\ProgramData\\MicrosoftOneDrive.tlb" ascii wide
        
        // ToneShell C2 communication patterns
        $fake_tls_13 = {17 03 04} // TLS 1.3 fake header marker
        $c2_domain1 = "avocadomechanism" ascii wide
        $c2_domain2 = "potherbreference" ascii wide
        
        // XOR rolling key encryption pattern in network traffic
        $xor_rolling = {8A 04 0E 32 04 1F 88 04 0E 41 3B C8}
        
        // ToneShell command structure opcodes
        $cmd_create_temp = {83 F8 01 74} // Command 0x1
        $cmd_download = {83 F8 02 74} // Command 0x2
        $cmd_shell = {83 F8 07 74} // Command 0x7
        $cmd_upload = {83 F8 0A 74} // Command 0xA
        $cmd_close = {83 F8 0D 74} // Command 0xD
        
        // Shellcode injection patterns
        $shellcode_marker = {48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8} // Shellcode address resolution
        $svchost_spawn = "svchost.exe" ascii wide
        
        // SYSTEM_MODULE_INFORMATION query for base address resolution
        $sys_module_query = {B9 0B 00 00 00} // SystemModuleInformation = 0xB
        
    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 500KB and
        
        (
            // Driver-specific indicators
            (
                ($cert_serial or $cert_subject) and
                any of ($driver_name*) and
                2 of ($filter_register, $irp_setinfo, $altitude_format, $wdfilter_target)
            )
            or
            // Rootkit protection mechanisms
            (
                2 of ($ob_register, $ps_notify, $cm_register) and
                any of ($reg_protect1, $wdfilter_target) and
                ($ntoskrnl and $fltmgr)
            )
            or
            // ToneShell payload indicators
            (
                $host_id_path and
                $fake_tls_13 and
                any of ($c2_domain*) and
                2 of ($cmd_*)
            )
            or
            // Comprehensive multi-stage detection
            (
                any of ($driver_name*) and
                $svchost_spawn and
                any of ($c2_domain*) and
                $fake_tls_13
            )
        )
}
