rule SUSP_OBF_NET_ConfuserEx_Name_Pattern_Jan24 {
	meta:
		description = "Detects Naming Pattern used by ConfuserEx. ConfuserEx is a widely used open source obfuscator often found in malware"
		author = "Jonathan Peters"
		date = "2024-01-03"
		reference = "https://github.com/yck1509/ConfuserEx/tree/master"
		hash = "2f67f590cabb9c79257d27b578d8bf9d1a278afa96b205ad2b4704e7b9a87ca7"
		score = 60
	strings:
		$s1 = "mscoree.dll" ascii
		$s2 = "mscorlib" ascii 
		$s3 = "System.Private.Corlib" ascii
		$s4 = "#Strings" ascii
		$s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }

		$name_pattern = { E2 ( 80 8? | 81 AA ) E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 80 AE}
	condition:
		uint16(0) == 0x5a4d
		and 2 of ($s*)
		and #name_pattern > 5
}

rule SUSP_OBF_NET_ConfuserEx_Packer_Jan24 {
	meta:
		description = "Detects binaries packed with ConfuserEx compression packer. This feature compresses and encrypts the actual image into a stub that unpacks and loads the original image on runtime."
		author = "Jonathan Peters"
		date = "2024-01-09"
		reference = "https://github.com/yck1509/ConfuserEx/tree/master"
		hash = "2570bd4c3f564a61d6b3d589126e0940af27715e1e8d95de7863579fbe25f86f"
		score = 70
	strings:
		$s1 = "GCHandle" ascii
		$s2 = "GCHandleType" ascii

		$op1 = { 5A 20 89 C0 3F 14 6A 5E [8-20] 5A 20 FB 56 4D 44 6A 5E 6D 9E }
		$op2 = { 20 61 FF 6F 00 13 ?? 06 13 ?? 16 13 [10-20] 20 1F 3F 5E 00 5A}
		$op3 = { 16 91 7E [3] 04 17 91 1E 62 60 7E [3] 04 18 91 1F 10 62 60 7E [3] 04 19 91 1F 18 62 }
	condition:
		uint16(0) == 0x5a4d
		and all of ($s*)
		and 2 of ($op*)
}
