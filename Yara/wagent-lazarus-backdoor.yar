rule wAgent_Lazarus_Backdoor {
    meta:
        title = "wAgent Malware - Lazarus Group Updated Variant"
        description = "Detects wAgent backdoor used by Lazarus group with updated capabilities including GMP library for RSA encryption and in-memory plugin loading"
        author = "litemars"
        date = "2025-11-06"
        modified = "2025-11-06"
        version = "1.0"
        reference = "https://securelist.com/operation-synchole-watering-hole-attacks-by-lazarus/"
        mitre_attack = "T1140,T1027.013,T1027.009,T1218.011,T1071.001"
        
    strings:
        $loader_dll = "liblzma.dll" wide
        $rundll32_exec = "rundll32.exe" wide nocase
        $util_path = "c:\\Programdata\\intel\\util.dat" wide
        $aes_algo = "AES-128-CBC" wide
        $rsa_crypto = "RSA" wide
        $gmp_lib = "GMP" wide
        $json_format = "JSON" wide
        $form_data = "form-data" wide
        $auth_token = "__Host-next-auth-token" wide
        $cookie_header = "Cookie" wide
        $stl_map = "std::map" wide
        $memory_load1 = "CreateRemoteThread" wide
        $memory_load2 = "VirtualAllocEx" wide
        $memory_load3 = "WriteProcessMemory" wide
        $plugin_arch = "x64_2.1" wide
        $config_decrypt_key1 = {48 8D 45 E8 48 8B 55 E0}
        $config_decrypt_key2 = {00 10 00 00}
        $c2_rand_append = {FF 15 ?? ?? ?? ?? 89 C2}
        $shared_obj = "SharedObject" wide
        
    condition:
        (uint16(0) == 0x5A4D) and
        (filesize > 150KB and filesize < 3MB) and
        ($loader_dll or $rundll32_exec) and
        (($util_path and $aes_algo) or ($rsa_crypto and $gmp_lib)) and
        (($auth_token and $cookie_header) or ($json_format and $form_data)) and
        ((all of ($memory_load*)) or ($config_decrypt_key1 and $config_decrypt_key2))
}