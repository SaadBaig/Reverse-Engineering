# Reversing WannaCry


This piece of malware is really half of the story. The other half of the story involved Marcus Hutchkins, the malware analyst that stopped WannaCry’s onslaught in May of 2017. His revelation of registering a domain he found while reverse engineering the malware was the key in stopping the viral infection. The URL he had discovered within the code was a killswitch. My goal is to try to find that URL. I’ll be using Ghidra to reverse. 

## Threat:
WannaCry was a ransomware that spread worldwide in May of 2017. Targeting Windows operating systems, it used the recently leaked NSA EternalBlue exploit as a propagation mechanism. Spreading to over 200,000 machines in 150 countries, it was a massive attack that was patched relatively quickly after it was discovered, but not after causing major disruptions. Sending requests on port 445 which SMB uses, it tried to spread like a worm to other systems. It would request crypto currency to gain access to the files it encrypted. 

## Behavior:
Being a Windows based ransomware, we load it up into an outdated Windows 7 VM, set up with a couple documents and pictures on the desktop. Within a minute of running the exploitation vector preview windows for images and files start to go away, and additional files get added to the desktop. A program called Wana Decrypt0r loads up with a familiar looking image: 

![image](https://user-images.githubusercontent.com/38113471/88589653-b2739a80-d016-11ea-9ead-5bdb0f55383a.png)

## Entry point: 
When we open the WannaCry.exe within Ghidra, we are greeted with a window showing us basic information about the binary. Once we have launched the .exe in Ghidra, we can start looking at its functions. Here’s an interesting function called ‘entry’ which was found under the Functions folder in the Symbol Tree pane:

![image](https://user-images.githubusercontent.com/38113471/88589662-b69fb800-d016-11ea-8637-f35bf49c12a6.png)
 

All of this initial information is a little busy. We have a couple open panes, such as program trees which shows us the Portable Executable (PE) code segment as they would be found in memory; we have our .text, .data as well as a couple other exe based info such as .rdata which is a read only data partition, and .rsrc which is a section for resources required by a module. When a program runs, it runs by calling main(). In Windows, this main function is called WinMain() or main() instead. 

## Functions

Digging through WannaCry’s function list pane, we see a list of functions, we see a lot of randomly named functions but we don’t see a main or WinMain() function. However we do see an entry function. Let’s check it out: 

![image](https://user-images.githubusercontent.com/38113471/88589668-ba333f00-d016-11ea-81bf-c08c7b18d195.png)
 
A neat little trick Ghidra has is Function Call Graphs which allow you to visually see what functions are called from other functions. Here’s the function calls that happen after entry:
 
![image](https://user-images.githubusercontent.com/38113471/88589678-bdc6c600-d016-11ea-82f8-31660524c06f.png)

## Killswitch

Going through the Symbol Tree pane on the side, we can see all the different decompiled functions that were found. I manually went through each one just to see if I could find what I was hunting for and lo and behold it did; it was the highlighted function in the function call graph above. The function within FUN_00408140 has some interesting calls, namely InternetOpenA, InternetOpenUrlA, and InternetCloseHandle. Anytime you can see a URL call from a piece of malware, you know you’re most likely onto something good, and in this case, it was the kill switch for the malware. 

The domain http://www.iuqerfsodp9ifjaposdfj_004313d0 is the domain that Marcus Hutchkins registered as soon as he discovered it wasn’t registered which was the accidental kill switch that stopped its propagation nationwide. 

![image](https://user-images.githubusercontent.com/38113471/88589690-c0c1b680-d016-11ea-8844-defe8f85aef0.png)

Line 22 is what I was after. Finding this was very simple, which is mostly not the case when reverse engineering malware. Since we reached our goal early on, lets poke around and see what else can learn about Ghidra and WannaCry.

In this scenario, the kill switch was not activated, and the malware continued through its infection and propagation lifecycle. 

## Indicator of Compromise

Lets take a couple steps back and take a look at our decompiled entry.  Using foresight of a seasoned Windows reverse engineer (which I am not), see that the entry function contains similar code that runs as a WinMain() function. We can take documentation provided to us by Microsoft about WinMain and replace our kill switch failure entry point with WinMain clearing up function names with names that will make sense to us.  

![image](https://user-images.githubusercontent.com/38113471/88589703-c4edd400-d016-11ea-844d-53283ad37208.png)

Now that we have renamed our entry function to WinMain(), lets see what it does exactly. 

![image](https://user-images.githubusercontent.com/38113471/88589709-c7e8c480-d016-11ea-980b-878d374b1860.png)

We can see functions in here from our function list, namely InternetOpenA, InternetOpenUrlA and InternetCloseHandle. We can see that there is an if function that does a comparison between iVar2 value which you can see being assigned to InternetOpenUrlA. If this comparison == 0 then it eventually calls another function FUN_00408090. Considering outside the for loop nothing happens, this function seems to be the entry if our kill switch doesn’t ring true; the real entry. Lets rename wannacry_entry it and take a look:

![image](https://user-images.githubusercontent.com/38113471/88589718-cae3b500-d016-11ea-86b5-0eff57c1c529.png)

Taking a preliminary look, we see allocations on the stack and then our first function, GetModuleFileName which seems to take in a FilePath. After an if statement, another function FUN_ 00407F20() gets called. Let’s keep following this function trail:

![image](https://user-images.githubusercontent.com/38113471/88589730-ce773c00-d016-11ea-98db-13c25f4ab73a.png)

Lets keep going down the rabbit hole; FUN_00407c40():

![image](https://user-images.githubusercontent.com/38113471/88589732-d0d99600-d016-11ea-93cf-4fd4a6aa6d53.png)

We’re somewhere juicy now! Looking through this function we can see some interesting things pop out such as a function call to CreateServiceA which creates a service called “Microsoft Security Center (2.0). This seems to create our malicious wannacry service, we we’ll call it wannacry_service. We can check in process manager within Windows for that service: 

![image](https://user-images.githubusercontent.com/38113471/88589745-d636e080-d016-11ea-818b-17bbb165a51d.png)

We’re infected, Huzzah! Let’s go back up the rabbit hole and look at our 2nd function FUN_00407ce4():

Couple interesting things that pop out; From kernel32.dll, we get the functions createprocessA, createfileA, WriteFile, CloseHandle. Lets rename them. Further down the program we also see references to Windows filesystem locations C:\%s\%s_00431358 and C:\%s\qeriuwjhrf_00431344:

 
![image](https://user-images.githubusercontent.com/38113471/88589759-d9ca6780-d016-11ea-8a80-0f0c36a3db9f.png)
![image](https://user-images.githubusercontent.com/38113471/88589783-df27b200-d016-11ea-81aa-ec38593f23e2.png)

With our wisdom in RE we can see that sprintf is trying to get to 2 locations, however both contain %s, a placeholder which when we hover over get a value in our listing pane:

![image](https://user-images.githubusercontent.com/38113471/88589790-e222a280-d016-11ea-8763-9702833266e2.png)
  

Overriding the function signature to include 2 more chars helps us make sense of this functions parameters and expected output:

![image](https://user-images.githubusercontent.com/38113471/88589801-e8188380-d016-11ea-9b14-4cd947284725.png)

As we continue down the program we can see that our kernel32.dll imported functions CreateFile and WriteFile get called most likely meaning that a file called tasksche.exe gets written to. 

When we step back and take a look at the big picture, we can start to make sense of what we’ve found so far. 

## Summary

Wannacry.exe is launched. First thing it checks for is the kill switch URL using the OpenUrlA function. If that succeeds it does doesn’t do anything. If it fails, then it starts the actual entry function which we named wannacry_entry. From there it creates a service called mssecsvc which can be seen in the services list of process manager on Windows. This is our true entry point and a foothold on the OS has been gained. 

Now it needs some tools to start running, so it borrows kernel32.dll and gets a few functions from it, namely CreateProcessA, CreateFile, WriteFile functions. With this new capability, it tries to write to a new file located C:\Windows_00431364\tasksche.exe. During my reversal I had missed a few critical steps that I ended up reading about. 

When Wannacry initially loads and fails the killswitch check, it enters wannacry_entry, however it also checks if it launched with any arguments. If there were arguments, then it enters into a service mode which we’ll discover later is the propagation mechanism that is used. If there aren’t any arguments, it starts a service with a “-m security” argument. This specific part was very crucial as it was a step in the exploitation process that we’ll be getting into later. As we continue through the lifecycle after creation of service mssecsvc, we find the path C:\Windows_00431364\tasksche.exe this path was used to copy over another program but still run as tasksche.exe with the security argument that we had defined earlier. Using the kernel32.dll WriteFile function was crucial for this because this is how we can feed in the code we need for the exploitation stage. 

The -m security an important argument because it allowed changes to be made to the ServiceConfig so that “it changes the config so that failure actions occur if the service exits without entering a SERVICE_STOPPED state.” This allows wannacry to change the state so that failure actions can occur. Because this triggers a failure action, the program can exit without entering a SERVICE_STOPPED state. 

Now we’re in the exploitation state of Wannacry. Now that a specially crafted service has been created, a malicious tasksche.exe has been crafted and ready to take advantage of a service config change exploit, it drops in another binary, which exploits MS17-010, EternalBlue! Guess what I'll be RE'ing next?


## Sources
https://blog.kartone.ninja/2019/05/23/malware-analysis-a-wannacry-sample-found-in-the-wild/
http://www.csn.ul.ie/~caolan/pub/winresdump/winresdump/doc/pefile2.html
http://www.equestionanswers.com/vcpp/winmain-application-entry.php
https://www.youtube.com/watch?v=Sv8yu12y5zM
https://research.checkpoint.com/2017/eternalblue-everything-know/
https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html
https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
https://www.bankinfosecurity.com/5-emergency-mitigation-strategies-combat-wannacry-outbreak-a-9914