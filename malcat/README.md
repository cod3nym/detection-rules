# Malcat specific rules

These rules are specifically formatted for the Malware Triage tool [Malcat](https://malcat.fr/)

## How to use

1. Go to your Malcat install folder and then navigate to `...\data\signatures`
2. Create a new folder I will name it `custom`
3. Copy the .yar files from this repository into your folder
4. In the `signatures` folder create a new .yar file (same name as your folder)
5. Copy the following code into that .yar file

```
include 'custom/obfuscators.yar'
```
*Change `custom` to your folder name*
