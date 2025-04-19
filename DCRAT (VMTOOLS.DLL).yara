rule DCRAT: VMTOOLS.DLL
{
meta:
	author = "Subhankar Hazra"
	Date = "2025-04-18"
	Description = "Detects DCRAT: VMTOOLS.DLL"
 
strings:
  	$pattern1 = {00 00 E8 59 EC 01 00 00 10 F5 D2 39 CB 00 00 00  
                 00 00 00 00 00 00 00 00 E0 5D EF 17 FE 7F 00 00   
                 01 00 00 00 00 00 00 00 CF A2 E0 17 FE 7F 00 00}

		$pattern2 = {03 00 00 00 04 00 00 00 30 12 EA 15 FE 7F 00 00  
                 02 00 00 00 06 00 00 00 70 19 EA 15 FE 7F 00 00  
                 02 00 00 00 0A 00 00 00 80 19 EA 15 FE 7F 00 00   
                 03 00 00 00 04 00 00 00 98 19 EA 15 FE 7F 00 00   
                 03 00 00 00 03 00 00 00 A8 19 EA 15 FE 7F 00 00}

  
condition:
		any of ($pattern1, $pattern2)
}
	