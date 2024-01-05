import "pe"

rule DOTNET_SingleFileHost_Bundled_App {
	meta:
		description = "Detects single file host .NET bundled apps."
		author = "Jonathan Peters"
		date = "2024-01-02"
		reference = "https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file"
	strings:
		$ = "singlefilehost.exe" ascii
		$ = "singlefilehost.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and
		1 of them and
		pe.exports("DotNetRuntimeInfo") and
		pe.exports("CLRJitAttachState")
}
