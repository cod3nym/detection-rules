# Yara Snippets and Little Tricks


## Check for string/pattern in PE Section

```
   condition:
      $pattern in (pe.sections[0].raw_data_offset .. pe.sections[0].raw_data_offset + pe.sections[0].raw_data_size)
```
## Check PE Resources for  string

```
   condition:
      for any i in (0..pe.number_of_resources-1) : (pe.resources[i].name_string == ".upx")
```

## Check physical size of first PE section
> [!TIP]
> This is a nice condition to identify a likely packed PE image. Images packed with packers like VMProtect create their first section with a physical size of 0. UPX does something similar with their `UPX0` section.

```
   condition:
      pe.sections[0].raw_data_size == 0
```

## Convert strings to hexstrings for templating
> [!TIP]
> This can save the effort of building a Regex pattern and benefit performance. For example instead of searching for `_CorDllMain` or `_CorExeMain` or some regex to detect the two we can do the following:

```
   strings:
      $s1 = { 5F 43 6F 72 [3] 4D 61 69 6E } // _Cor???Main
```
## Avoid modules when possible
> [!TIP]
> Modules add convenience at the cost of performance, so I tend to avoid them when possible. For example instead of using `dotnet.is_dotnet` we can just search for some managed imports we expect our sample to have or common strings of a .NET binary like `mscorlib`, `System.Private.Corlib` etc.

```
   strings:
      $s1 = "mscoree.dll" ascii
      $s2 = "mscorlib" ascii
      $s3 = "System.Private.Corlib" ascii
      $s4 = "#Strings" ascii
      $s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }
```
