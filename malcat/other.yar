import "pe"

rule SingleFileHost_App_Bundle
{
	meta:
		name = "DotNet"
		category = "compiler"
		description = "DotNet singlefilehost app bundle"
		author = "Jonathan Peters"
		created = "2024-01-03"
		reliability = 90
		score = 40
	strings:
		$ = "singlefilehost.exe" ascii
		$ = "singlefilehost.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and
		1 of them and
		pe.exports("DotNetRuntimeInfo") and
		pe.exports("CLRJitAttachState")
}
