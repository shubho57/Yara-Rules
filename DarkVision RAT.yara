rule detect_DarkVision RAT: Event Viewer
{
	meta:
	    description = "detect_DarkVision RAT"
	    author = "Subhankar Hazra"
            date = "2025-3-17"
            sample hash = "ef9a8a12b1521b684d5587314033af29d5586e00f8a120fe5f5a2201cb3be482"
        
	    
    strings:
        $public_key_token = "6f05678fe9123789167" fullword ascii
               
        $s1 = "OpenMutex" fullword ascii
        $s2 = "wsprintw" fullword ascii
        $s3 = "CoCreateInstance" fullword ascii        
        $s3 = "RAZORSERVER32.EXE" fullword wide
        $s4 = "eventwr.exe" fullword wide
        $s5 = "wmic.exe" fullword wide
        
        
        $manifest = "AsInvoker" fullword wide
        
        
    condition:
         uint16(0) == 0x5A4D and filesize > 70KB and ($public_key_token  or  (3 of ($s*) and $manifest ))
            
