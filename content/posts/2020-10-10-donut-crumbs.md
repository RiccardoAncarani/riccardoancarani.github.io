---
title: Following Donut Crumbs
subtitle: The small traces left by donut shellcode
tags: [threat-hunting]
linkedin: "https://www.linkedin.com/in/riccardo-ancarani/"
twitter: "https://twitter.com/dottor_morte"
date: "2020-10-10"
---


<!-- MDTOC maxdepth:6 firsth1:1 numbering:0 flatten:0 bullets:1 updateOnSave:1 -->

   - [Intro](#intro)   
   - [Observations](#observations)   
      - [In-Memory PE](#in-memory-pe)   
      - [AMSI Bypass](#amsi-bypass)   

<!-- /MDTOC -->


## Intro

To deal with some rainy Sunday depression I decided to investigate how [Donut](https://github.com/TheWover/donut) operates in memory and to see what traces it leaves (if any). I've been using Donut for quite some time, and I find it extremely useful from an operator's perspective as it gives a lot of flexibility.

For those who don't know what Donut is, we could define it as a software that allows the conversion from PE/.NET assemblies/scripts into position independent code (PIC, or shellcode). When I first read the initial release paper, it sounded like black magic to me; but after some time and experience I started realising how it works (at an  high level, 90% still magic) it made more sense.

What also surprised me was the lack of technical defensive content on it. I can partially understand why; donut is meant to generate shellcode and most of the times the acts of injecting and executing the shellcode are the most "flagged" actions, not the shellcode itself. An example of such is the classic `CreateRemoteThread` function used to execute a shellcode we previously injected into another process' memory; EDRs and AVs are able to detect that quite well (if we do not consider API unhooking). The reason behind this - apparently - is because it's easier to put hooks and introspect API calls rather than scanning the memory of a process and look for anomalies.

However, it can happen that the injected shellcode leaves some traces in memory.

## Observations


### In-Memory PE

Under the hood, what donut does is "unpacking" the PE that was provided as input and executes it in-memory. The packed PE and the unpacking stub are shipped as a shellcode.

In order to better visualise this, we are going to execute donut ourself:

```
donut.exe mimikatz.exe

  [ Donut shellcode generator v0.9.3
  [ Copyright (c) 2019 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : ".\mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP     : continue
  [ Shellcode     : "loader.bin"
```

I injected the `loader.bin` shellcode using [UrbanBishop](https://github.com/FuzzySecurity/Sharp-Suite/tree/master/UrbanBishop) and after that the memory of the injected process was the following:

![](/assets/2020-10-10-donut-crumbs/d04c6103a30565adb980cc2aebffffe4.png)

Note the `RWX` memory within the notepad's memory. Isn't it strange? Digging a bit deeper (which for me usually means just checking for strings) what I found was that it was indeed the Mimikatz PE:

![](/assets/2020-10-10-donut-crumbs/ef64e75d13b3f39e0382f3ff6e30c190.png)

Using the Moneta scanner we can see some IoCs for injected memory:

![](/assets/2020-10-10-donut-crumbs/34bf9b92ad78a9ce410b3c7f82e79fd6.png)

In fact, private memory marked as read/write/exec is suspicious. I validated this reading the source code of the [inmem_pe.c](https://github.com/TheWover/donut/blob/master/loader/inmem_pe.c) file:

![](/assets/2020-10-10-donut-crumbs/c5e305b77559df50280adf534ecf12ff.png)

As it is possible to see, the memory allocated with `VirtualAlloc` is marked as `PAGE_EXECUTE_READWRITE`. This itself can be an IoC for detecting injected code (note that this issue is not donut specific!)

This is good from a memory forensic/hunting perspective but it must be noted that memory type cannot probably used alone for automatic detection. Usually, what might be flagged by an EDR's memory scanner should include a weird allocation type and something else like the PE headers floating in-memory (bytes `MZ`).  

To avoid that, donut wipes the PE headers after the loading is complete. We can observe similar features in Cobalt Strike post exploitation modules that use the `obfuscate` malleable PE option.


### AMSI Bypass

Another feature offered by Donut is the ability to bypass AMSI. As we know, .NET 4.8 introduced the ability to scan assemblies that are loaded via `Assembly.Load` from the reflection APIs and therefore if we are dealing with the injection of a .NET assembly it might be a sensible thing to do.

Donut bypasses AMSI from an unmanaged perspective, patching the `AmsiScanBuffer` function. This is the default option within Donut.

What I observed is that AMSI gets patched even if we are not trying to inject a .NET assembly. What does it mean from a detection perspective?

If we look at the [bypass.c](https://github.com/TheWover/donut/blob/master/loader/bypass.c) code, we can see the `LoadLibraryA` function that will load `amsi.dll`:

![](/assets/2020-10-10-donut-crumbs/00f01d97108d0af8dd58b3a3433f36b3.png)


After `amsi.dll` is loaded, the Donut shellcode will patch its code. The detection from the Moneta scanner shows that:
![](/assets/2020-10-10-donut-crumbs/915f5535b5aa9be93e575aac7672b2ab.png)

From WinDbg we can confirm that `amsi` was indeed patched. Look at the `xor eax,eax` and `ret` instructions:

![](/assets/2020-10-10-donut-crumbs/69f2e88ee8ac5d23c628b014b4f52b52.png)

The value of `eax = 0` indicates the result of the `AmsiScanBuffer` equals to `AMSI_RESULT_CLEAN`.

So what is strange with this? If we inject a shellcode generated using Donut with the default bypass options into a process that usually does not have `amsi.dll` loaded, Donut will load and bypass it.

An example of an anomalous AMSI load event is shown below:

![](/assets/2020-10-10-donut-crumbs/90819eb3509ba1d485fdc0b9f1b5b500.png)

The event is generated from Sysmon with a modified configuration that logs AMSI load events. The base configuration is the classic SwiftOnSecurity's:


```
<!--SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]-->
		<!--COMMENT:	Can cause high system load, disabled by default.-->
		<!--COMMENT:	[ https://attack.mitre.org/wiki/Technique/T1073 ] [ https://attack.mitre.org/wiki/Technique/T1038 ] [ https://attack.mitre.org/wiki/Technique/T1034 ] -->

		<!--DATA: UtcTime, ProcessGuid, ProcessId, Image, ImageLoaded, Hashes, Signed, Signature, SignatureStatus-->
	<RuleGroup name="" groupRelation="or">
		<ImageLoad onmatch="include">
			<ImageLoaded condition="contains">amsi</ImageLoaded>
			<!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
		</ImageLoad>
	</RuleGroup>

```

This is an interesting detection for Donut's default options, but for an operator it would be trivial to modify this behaviour and avoid bypassing AMSI.
