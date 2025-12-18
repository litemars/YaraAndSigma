rule APT28_NotDoor_Outlook_VBA_Backdoor
{
    meta:
        description = "Detects APT28 NotDoor Outlook VBA backdoor (event-driven macro C2 over email)"
        author      = "litemars"
        date        = "2025-12-18"
        reference_1 = "S2 Grupo LAB52 NotDoor analysis"
        reference_2 = "TheHackerNews - APT28 NotDoor Outlook backdoor"
        reference_3 = "Splunk Threat Research - NotDoor Insights"
        malware     = "NotDoor"
        family      = "APT28"
        mitre       = "T1059.005,T1566.002,T1114.003,T1071.004,T1027"

    strings:
        // Outlook VBA event handlers abused by NotDoor
        $s_event1 = "Application_MAPILogonComplete" ascii
        $s_event2 = "Application_NewMailEx" ascii

        // Typical trigger string & marker words in analysis
        $s_trigger_phrase1 = "Daily Report" ascii
        $s_trigger_phrase2 = "Nothing" ascii

        // Commands supported by the backdoor
        $s_cmd_1 = "cmdno" ascii
        $s_cmd_2 = "cmd\"" ascii nocase
        $s_cmd_3 = "dwn\"" ascii nocase
        $s_cmd_4 = "upl\"" ascii nocase

        // Temp staging folder and TXT artifacts
        $s_temp_folder1 = "%TEMP%\\Temp" ascii
        $s_temp_folder2 = "\\Temp\\*.txt" ascii

        // Custom “encoded-as-Base64-with-junk” style comment markers
        $s_enc_hint1 = "Base64" ascii
        $s_enc_hint2 = "Replace$(Replace$(" ascii

        // Exfil & C2 infrastructure references
        $s_exfil_mail1 = "proton.me" ascii
        $s_exfil_mail2 = "@proton.me" ascii
        $s_webhook1    = "webhook.site" ascii

        // Registry/profile modification hints (macro & prompt suppression)
        $s_reg1 = "DisableMACRO" ascii nocase
        $s_reg2 = "EnableUnsafeClientMailRules" ascii
        $s_reg3 = "ShowSecurityDialog" ascii

        // Generic but rare Outlook macro artifacts
        $s_outlook1 = "ThisOutlookSession" ascii
        $s_outlook2 = "MailItem" ascii
        $s_outlook3 = "MAPIFolder" ascii

    condition:
        // Target VBA text / OTM dump / memory region
        filesize < 5MB and

        // Core Outlook VBA event-driven behavior AND command verbs
        ( ( $s_event1 or $s_event2 ) and
          ( 1 of ( $s_cmd_1, $s_cmd_2, $s_cmd_3, $s_cmd_4 ) ) and
          1 of ( $s_outlook1, $s_outlook2, $s_outlook3 ) ) and

        // Any additional NotDoor-typical feature:
        ( 1 of ( $s_trigger_phrase1, $s_trigger_phrase2 ) or
          any of ( $s_temp_folder* ) or
          any of ( $s_exfil_mail* ) or
          $s_webhook1 or
          1 of ( $s_reg1, $s_reg2, $s_reg3 ) or
          ( $s_enc_hint1 and $s_enc_hint2 ) )
}
