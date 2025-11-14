rule Lazarus_CipherVariant_DLL_Payloads
{
    meta:
        author = "Ben Hopkins
        description = "Detects the specific Lazarus malware variant by combining the custom hex-encoded alphabet with multiple known encrypted DLL strings."
        date = "2025-11-13"
        sample = "c39ecc7d9f1e225a37304345731fffe72cdb95b21aeb06aa6022f6d338777012"
        family = "Lazarus", "ScoringMathTea"
        
    strings:
        $key_bytes = { 
            70 42 31 51 35 5A 79 6E    // "pB1Q5Zyn"
            65 43 62 36 73 52 30 33    // "eCb6sR03"
            75 32 4F 78 66 4B 38 76    // "u2OxfK8v"
            56 4D 6B 45 61 6F 77 2D    // "VMkEaow-"
            63 69 53 44 59 49 55 6D    // "ciSDYIUm"
            6C 46 34 68 71 39 58 4C    // "lF4hq9XL"
            50 4A 4E 7A 54 68 47 47    // "PJNzThGG"
            72 2E 57 74 64 41 37 6A    // "r.WtdA7j"
        }
        
        $dll_1_kernel32   = "I7xfQeEu4Ehv" ascii
        $dll_2_ntdll      = "6nb3ciOS0" ascii
        $dll_3_ws2_32     = "mlmSmr35w3-6" ascii
        $dll_4_wininet    = "EstuM0lMFK" ascii
        $dll_5_advapi32   = "qEA.J.wS6dsr" ascii
        $dll_6_crypt32    = "FDN5dPFOQxj" ascii

    condition:
        $key_bytes and 3 of ($dll_*)
}
