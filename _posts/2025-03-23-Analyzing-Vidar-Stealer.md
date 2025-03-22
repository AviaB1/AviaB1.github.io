---
title: "Analyzing Vidar Stealer🔎"
last_modified_at: 2025-03-23T12:39:14
---
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/0.jpg?raw=true)
# Overview
Vidar is an infostealing malware designed to collect a variety of sensitive information from an infected computer and exfiltrate it to an attacker. It operates as malware-as-a-service (MaaS) and has been widely used by cybercriminals since its discovery in late 2018.

Vidar is typically distributed to victims via phishing emails and fake installers. I have personally seen many fake installers containing some type of stealer, such as cracked software, game cheats, keygens, and more.

Here’s an infection flow that I’ve created for what we’re going to analyze today. This is just to give you a general idea of the infection chain and is not 100% accurate:
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/1.jpg?raw=true)


# Sample Information
**MD5:** `b6fff0854975fdd3a69fd2442672de42`
**SHA256:** `fe0d2c8f9e42e9672c51e3f1d478f9398fe88c6f31f83cadbb07d3bb064753c6`
**Size**: `270,336 bytes`
**Compilation date:** `2025-03-13 10:34:19`

# Loader Analysis

### Static Analysis
The first thing I do in every investigation involving files is gain an overview of the files and their capabilities, encryption used, obfuscation, and packers. At this stage, I make hypotheses about the file's capabilities and goals so I can focus on the important aspects and avoid unnecessary rabbit holes.

Dropping the file into Detect it easy,  it didn’t identify any known packers, and it seemed like the sample was compiled with ``Microsoft Visual C/C++(2022+)[-]`` using the ``Microsoft Linker(14.42)``
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/2.png?raw=true)
As seen above, the sample appears to be 64-bit. We can verify this by checking the magic header in the optional header of the PE file. A value of 0x20B indicates a 64-bit file, while 0x10B signifies a 32-bit file.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/3.png?raw=true)
As we can see, this is indeed 0x20B (Little Endian) which means this is 64-bit file.

Next, let's check the compilation time. We can examine the `TimeDateStamp`, which contains a DWORD (4 bytes) value representing the time of compilation.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/4.png?raw=true)
In order to get the actual value, we need to convert it to big endian and then to decimal. The value is stored as epoch time (also known as Unix time), which is how computers store and measure time, so we need to convert it accordingly.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/5.png?raw=true)
As we can see, after all the conversions, the compilation date is `2025-03-13`. We can verify this by checking any PE parser, i.e., CFF Explorer, PE Bear, and others.

Checking the entropy of the file reveals that the `.BSS` section has high entropy. This section usually contains uninitialized global and static objects, so high entropy could indicate that it contains encrypted shellcode or additional payloads for the malware. It's actually common for attackers to store encrypted shellcode in the `.BSS` and `.data` sections, but we'll revisit this later.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/6.png?raw=true)
Checking the imports reveals functionality that could be used for anti-analysis and anti-debugging, such as `UnhandledExceptionFilter`, `SetUnhandledExceptionFilter`, `IsDebuggerPresent`, and `GetEnvironmentStringsW`. Additionally, there are functions that suggest potential malicious functionality.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/7.png?raw=true)
Running Strings/Floss against the file didn't yield any interesting results.

Now that we have an overview of the file, its capabilities, and potential functionality, we can start analyzing it.

First thing that the program does is get it's full path in order to load itself into memory, it's using ``GetModuleHandleW`` and ``GetModuleFileNameA``.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/8.png?raw=true)
After that, we can see that it opens the file in binary mode. It uses `fopen`, then moves the file pointer to the end with `fseek`, retrieves the file size with `ftell`, and finally closes the file.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/9.png?raw=true)
Next, we can see that it allocates memory using the size returned from ftell, then reads the file's contents into the buffer.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/10.png?raw=true)
Next, we can see that it loads the file's content into the `R10` register. It then retrieves the `e_lfanew` offset, which contains the address of the PE header. After that, it extracts the number of sections and checks if it is zero, jumping accordingly.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/11.png?raw=true)
If the number of sections is non-zero, it loads the effective address of a variable named `.BSS`. As we recall, the `.BSS` section had very high entropy, which further supports the idea that it contains some form of encrypted shellcode that will eventually be injected into memory.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/12.png?raw=true)


### Walking the PEB (Process Environment Block)
"Walking the PEB" is an approach malware authors use to interact with the `Process Environment Block` in Windows. This data structure holds information about the process, loaded modules, environment variables, and more. By walking the PEB, malware authors can dynamically resolve APIs that are typically monitored by security products and may be detected during static analysis.

We can see that the malware accesses the PEB at `gs:60h`, which is how the PEB is accessed in a 64-bit architecture. In a 32-bit architecture, it would be accessed through `fs:30h`.

Next, the malware moves the address of `PEB_LDR_DATA` into `RCX`. `PEB_LDR_DATA` is a structure that holds three pointers to three doubly linked lists of loaded modules. It then accesses offset `0x20`, which corresponds to `InMemoryOrderModuleList` - a structure that contains all the loaded modules in memory, including DLLs.

We can see the string `"KERNEL32.DLL"`. The malware will parse the `InMemoryOrderModuleList`, searching for this module. If found, it returns its address.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/13.png?raw=true)


### API Hashing
API hashing is a common trick malware uses to hide its function calls and make static analysis harder. Instead of storing API names like `LoadLibrary` or `GetProcAddress` in plain text, it converts them into hash values. This way, security tools and analysts can’t easily spot which APIs the malware is using just by scanning the binary.

At runtime, the malware calculates hashes for loaded APIs and compares them against its stored values to resolve what it needs. This is often combined with walking the PEB to find loaded modules without relying on standard Windows API calls, making detection even more difficult.

As we can see, it's quite obvious that the malware implements API hashing. Hardcoded hash values are being passed to the `sub_1400011C0` function (`ResolveFunctionByHash`), and the returned address is saved on the stack.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/14.png?raw=true)
We can create an IDAPython script to retrieve the APIs by recreating the hashing algorithm used by the malware and computing it against a list of exports from the relevant DLL - in this case, `kernel32.dll`. Alternatively, we could debug it and resolve them dynamically.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/15.png?raw=true)
The combination of resolved APIs looks like a classic preparation for process injection. This also makes sense based on what we observed in the `.BSS` section.


### Decryption of Encrypted Shellcode
After that, I see a call to the function `sub_7FF7C53B13F0`, which is likely responsible for the decryption routine of the encrypted shellcode. The function likely uses RC4 encryption, as indicated by the initialization of an array of 256 bytes, which is part of the `Key Scheduling Algorithm (KSA)` in RC4.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/16.png?raw=true)
Once the array is initialized, it gets shuffled with a key.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/17.png?raw=true)
The final step is the `Pseudo-Random Generation Algorithm (PRGA)`, which uses the array to generate a keystream (a pseudo-random byte sequence) that is XORed with the plaintext to produce the ciphertext.
![](https://github.com/AviaB1/AviaB1.github.io/blob/master/assets/images/styling-syntax-test/VidarStealer/18.png?raw=true)
Instead of analyzing it statically, we can just dynamically analyze it, let the magic happen, and get the next stage (;


### Unpacking
Okay, at this point, I have enough information to confidently say that we're dealing with a loader that uses remote process injection to execute its next stage.

There's one neat trick that will help us unpack it with a single breakpoint. As we can see, the malware uses `WriteProcessMemory`. This API takes several parameters, but the third one, `lpBuffer`, is a pointer to the buffer that contains data to be written into the address space of the specified process.
