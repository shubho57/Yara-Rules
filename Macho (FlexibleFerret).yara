rule MacOS RAT : FlexibleFerret
{
	meta:
	    description = "MacOS RAT (FlexibleFerret)"
	    author = "Subhankar Hazra"
            date = "2025-3-24"
            sample hash = "14b652da5e6a3ecd79d083a63963528356b30a5ad7a7df1813852ffe55a6e211"
	    
    strings:

       
        $s1 = "EINVAL" fullword ascii
        $s2 = "EPERM" fullword wide
        $s3 = "EDREADLK" fullword wide
        $s4 = "ENOMEM" fullword ascii
        $s5 = "EAGAIN" fullword ascii
        $s6 = "EBUSY" fullword wide
        
        $a1 = "DriverPackX" fullowrd wide

        $shellcode_arch = "x64" and "arm64" fullword ascii
	    
      
    condition:
       Macho and (3 of ($s*) and ($a1) and($shellcode_arch)
