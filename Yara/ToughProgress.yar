rule ToughProgress_APT41_2025 {
    meta:
        description = "Detects ToughProgress malware using Google Calendar for C2"
        author = "litemars"
        date = "2025-10-09"
        reference = "APT41 Google Calendar C2 operations"
        severity = "high"
        
    strings:
        $calendar_api1 = "calendar/v3/calendars" ascii wide
        $calendar_api2 = "www.googleapis.com/calendar" ascii wide
        $module1 = "PLUSDROP" ascii wide
        $module2 = "PLUSINJECT" ascii wide  
        $module3 = "TOUGHPROGRESS" ascii wide
        $hollowing1 = "svchost.exe" wide
        $event_desc = "description" ascii wide
        
    condition:
        uint16(0) == 0x5a4d and
        filesize > 50KB and filesize < 5MB and
        (
            (2 of ($calendar_api*) and $event_desc) or
            (any of ($module*) and $hollowing1)
        )
}
