/*
 * NEXUS Sentinel — Core YARA Rules
 * Place .yar files in this directory; they are auto-loaded by the backend.
 */

rule ransomware_generic {
    meta:
        description = "Detects generic ransomware behavior"
        severity    = "critical"
        author      = "NEXUS Sentinel"
    strings:
        $enc1 = "CryptEncrypt"             ascii
        $enc2 = "AES256"                   ascii
        $note = "YOUR FILES ARE ENCRYPTED" nocase
        $ext1 = ".locked"                  ascii
        $ext2 = ".enc"                     ascii
    condition:
        2 of ($enc*) and 1 of ($note, $ext*)
}

rule webshell_php {
    meta:
        description = "Detects PHP webshell patterns"
        severity    = "high"
        author      = "NEXUS Sentinel"
    strings:
        $php  = "<?php"                ascii
        $cmd1 = "eval(base64_decode"   ascii
        $cmd2 = "system($_GET"         ascii
        $cmd3 = "passthru("            ascii
        $cmd4 = "shell_exec("          ascii
    condition:
        $php and any of ($cmd*)
}

rule sql_injection_payload {
    meta:
        description = "SQL injection patterns"
        severity    = "high"
        author      = "NEXUS Sentinel"
    strings:
        $s1 = "' OR '1'='1" nocase
        $s2 = "UNION SELECT" nocase
        $s3 = "DROP TABLE"   nocase
        $s4 = "xp_cmdshell"  nocase
    condition:
        2 of them
}

rule keylogger_api {
    meta:
        description = "Windows keylogger API usage"
        severity    = "critical"
        author      = "NEXUS Sentinel"
    strings:
        $a1 = "SetWindowsHookEx" ascii wide
        $a2 = "GetAsyncKeyState" ascii wide
        $a3 = "GetKeyboardState" ascii wide
    condition:
        2 of them
}

rule suspicious_powershell {
    meta:
        description = "Obfuscated/malicious PowerShell"
        severity    = "high"
        author      = "NEXUS Sentinel"
    strings:
        $p1 = "powershell"             nocase ascii
        $p2 = "-EncodedCommand"        nocase ascii
        $p3 = "IEX"                    ascii
        $p4 = "Invoke-Expression"      nocase ascii
        $p5 = "DownloadString"         ascii
        $p6 = "-WindowStyle Hidden"    nocase ascii
    condition:
        $p1 and 2 of ($p2, $p3, $p4, $p5, $p6)
}
