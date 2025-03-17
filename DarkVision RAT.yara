rule detect_DarkVision RAT: Event Viewer
{
	meta:
	    description = "detect_DarkVision RAT"
	    author = "Subhankar Hazra"
        date = "2025-3-17"
        sample hash = "ef9a8a12b1521b684d5587314033af29d5586e00f8a120fe5f5a2201cb3be482"
        
	    
    strings:
        $public_key_token = "6f05678fe9123789167"
               
        $s1 = "OpenMutex" wide ascii
        $s2 = "L'wsprintw" wide ascii
        $s3 = "CoCreateInstance" wide ascii        
        $s3 = "RAZORSERVER32.EXE" 
        $s4 = "eventwr.exe"
        $s5 = "wmic.exe/sdb" ascii wide
        
        
        $manifest = "AsInvoker" wide
        
        
    condition:
         uint16(0) == 0x5A4D and filesize > 70KB and ($public_key_token  or  (3 of ($s*) and $manifest ))
            