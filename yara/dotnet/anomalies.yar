import "pe"

rule SUSP_NET_Large_Static_Array_In_Small_File_Jan24 {
   meta:
      description = "Detects large static arrays in small .NET files "
      author = "Jonathan Peters"
      date = "2024-01-11"
      reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
      hash = "7d68bfaed20d4d7cf2516c2b110f460cf113f81872cd0cc531cbfa63a91caa36"
      score = 60
   strings:
      $op = { 5F 5F 53 74 61 74 69 63 41 72 72 61 79 49 6E 69 74 54 79 70 65 53 69 7A 65 3D [6-] 00 }
   condition:
      uint16(0) == 0x5a4d and
	  pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0 and
	  filesize < 300KB and
	  #op == 1
}
