rule APT_MeshAgent_Weaponized_Awaken_Likho
{
    meta:
        description = "Detects weaponized MeshAgent used by Awaken Likho APT group"
        author = "litemars"
        date = "2025-09-04"
        reference = "https://securelist.com/awaken-likho-apt-new-implant-campaign/114101/"
        threat_actor = "Awaken Likho / Core Werewolf"
        malware_family = "MeshAgent"
        hash1 = "603eead3a4dd56a796ea26b1e507a1a3"
        hash2 = "deae4a955e1c38aae41bec5e5098f96f"

    strings:
        $meshcentral1 = "MeshCentral" wide ascii
        $meshcentral2 = "meshcentral" wide ascii
        $meshagent1 = "MeshAgent" wide ascii
        $meshagent2 = "meshagent" wide ascii
        $autoit_script = "AutoIt" wide ascii
        $scheduled_task1 = "MicrosoftEdgeUpdateTaskMachineMS" wide ascii
        $scheduled_task2 = "schtasks" wide ascii
        $c2_domain = "kwazindernuren.com" wide ascii
        $network_drivers = "NetworkDrivers.exe" wide ascii
        $microsoft_stores = "MicrosoftStores.exe" wide ascii
        $websocket = "WebSocket" wide ascii
        $cmd_obfuscated = "nKka9a82kjn8KJHA9.cmd" wide ascii
        $mesh_cert = "MeshCentralRoot" wide ascii
        $seven_zip = "7-Zip" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($meshcentral*) and 2 of ($meshagent*)) or
            ($scheduled_task1 and ($network_drivers or $microsoft_stores)) or
            ($autoit_script and $seven_zip and $websocket) or
            ($mesh_cert and $c2_domain)
        ) and
        filesize > 100KB and filesize < 10MB
}
