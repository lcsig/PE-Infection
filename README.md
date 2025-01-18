# PE-Infection
PE (Portable Executable) Infection Code in VB.NET

# Code Details 

## Explaination

- Load IMAGE_DOS_HEADER
- Load IMAGE_NT_HEADERS
- Load IMAGE_SECTION_HEADER
- Calculate Code Cave Position
- Inject Shellcode and Custom Code
- Modify Entry Point
- Serialize Changes and Return new PE

## Usage 
```vb
IO.File.WriteAllBytes(Application.StartupPath & "\injected.exe", Images_Changing.Modify_Linker_Version(IO.File.ReadAllBytes(Application.StartupPath & "\Project1.exe")))
```

## Disclaimer 
This code is intended strictly for educational and research purposes. Unauthorized use of this code to create or distribute malicious software is illegal and may result in severe criminal and civil penalties under cybersecurity and anti-malware laws. The authors or publishers do not endorse or condone any misuse of this material.

## Buy me a Coffee: 
BTC: bc1q2kqvggm552h0csyr0awa2zepdapxdqnacw0z5w

![BTC](https://raw.githubusercontent.com/lcsig/API-Hooking/refs/heads/master/img/btc.png)
