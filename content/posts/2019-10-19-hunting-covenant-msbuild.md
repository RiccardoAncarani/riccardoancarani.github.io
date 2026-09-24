---
title: Hunting for Anomalous Usage of MSBuild and Covenant
tags: [threat-hunting]
linkedin: "https://www.linkedin.com/in/riccardo-ancarani/"
twitter: "https://twitter.com/dottor_morte"
date: "2019-10-19"
---

Today's post will cover some of my experiments while practicing threat hunting. Specifically today we will cover hunting for malicious usage of `msbuild.exe` used by Covenant.

I literally started last week, so forgive me if I'm not following logging best practices or some detections are very unreliable!  

It must be noted that this specific case will fall under the class of tools default behaviours. For example, using similar techniques it would be possible to hunt for cobaltstrike's default `spawn` process `rundll32.exe`.

As in every threat hunting exercise, we will start with an hypothesis:

```
Attackers may use Windows builtin tools for executing code.
```
The specific technique we're going to hunt for falls under the `Execution` phase of the MITRE cyber killchain. More specifically under [T1127 - Trusted Developer Utilities](https://attack.mitre.org/techniques/T1127/).

In this case we'll focus just on `msbuild.exe`, but attackers have many more options. [LOLBAS Project - Execute](https://lolbas-project.github.io/#/execute) is a very comprehensive resource for such binaries.

In my HELK lab I executed the `msbuild.exe` Covenant stager to deploy a Grunt implant:

![](/assets/2019-10-19-hunting-covenant-msbuild/ce0aba35fc8c9f508132bb8aeac68d29.png)

What will happen now? The behaviour we want to catch is a suspicious binary (`msbuild.exe` in this case) that creates a remote connection. It must be noted, however, that malicious usage of such binaries do not always include creating remote connections, as it would be possible to create inline C# tasks with `msbuild.exe` that perform process injection to fetch the C2 implant from another proccess. But since I'm just a noob we'll focus on that just for now!

Within sysmon, the event ID associated with a new network connection is `3`; an example of a query that can be used to identify suspicious `msbuild.exe` binaries that create network connections can be the following:

```
winlog.event_id: "3" and winlog.event_data.Image:*MSBuild.exe
```
In the figure below it is possible to see that the aforementioned query does return some results:
![](/assets/2019-10-19-hunting-covenant-msbuild/d982eb9253172c446cc1b5fc745e4a3e.png)

As attackers, what could we do to avoid such rules? Since the search I wrote is based on process name, I could simply rename the `msbuild.exe` binary to something that legitimately performs network connections such as `iexplorer.exe`:

![](/assets/2019-10-19-hunting-covenant-msbuild/9323c00bb924f4b1d7d3aabb0fe24f3e.png)

 More elaborate detection based on hash may be used to overcome those bypasses! It's a chess game.

Back with our blue hat: This may rise some suspects but is some cases `msbuild.exe` will legitimately perform network connections, like developer workstations. It must be noted however, that as hunters is ultimately our responsability to know our estate and being able to spot those false positives.

Another hypothesis we could make to effectively validate that we're under active attack is the following:

```
Unexperienced attackers may use tool's default behaviour.
```

What does it mean? When attackers use COTS tools like cobaltstrike or Covenant, they may use the default options for their network profiles (malleable profiles within cobalt). Since we have access to the same COTS tools, the behaviour is known to defenders as well.

A very common example of a default behaviour that would give fairly good results is named pipe naming conventions. Named pipes are a mechanism for inter process communication and can be used by C2 implants to perform peer-to-peer communication over SMB.

By default Covenant's named pipes are called `\gruntsvc`:

![](/assets/2019-10-19-hunting-covenant-msbuild/182f1916c0b7572491b730f0a3243fdf.png)

We can hunt for sysmon event id 17 (Pipe Created) with a pipe name of `gruntsvc`:

![](/assets/2019-10-19-hunting-covenant-msbuild/24cd6e729e07c34162ece3e8a26712f1.png)

And as we can see, we got a hit.
From an attacker perspective bypassing this detection would be as easy as renaming the default named pipe!
