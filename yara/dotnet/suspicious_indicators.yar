rule SUSP_NET_Shellcode_Loader_Indicators_Jan24 {
   meta:
      description = "Detects indicators of shellcode loaders in .NET binaries"
      author = "Jonathan Peters"
      date = "2024-01-11"
      reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
      hash = "c48752a5b07b58596564f13301276dd5b700bd648a04af2e27d3f78512a06408"
      score = 65
   strings:
      $sa1 = "VirtualProtect" ascii
      $sa2 = "VirtualAlloc" ascii
      $sa3 = "WriteProcessMemory" ascii
      $sa4 = "CreateRemoteThread" ascii
      $sa5 = "CreateThread" ascii
      $sa6 = "WaitForSingleObject" ascii

      $x = "__StaticArrayInitTypeSize=" ascii
   condition:
      uint16(0) == 0x5a4d and
      3 of ($sa*) and
      #x == 1
}
