---
title: [Malware Analysis Techniques: Solving the 'UnpackMe' Challenge]
date: 2024-10-20 00:00:00 +0800
categories: [Malware Analysis]
tags: [unpackme,ir,malware analysis]     # TAG names should always be lowercase
---


As a malware analyst, we received an unknown piece of malware and our task is to dissect its components, understand its operational mechanics, and uncover its functionalities.

Often, as a malware analyst, I receive vague file samples and get asked to analyze them. What I mean by vague is that they either unknown to most Public threat intelligence platforms or they do exist with low/high detection rate often labeled with generic detection names. Those are mostly hueristic detections which rely on behavioral patterns or characteristics rather than specific signatures.

Heuristic detections often provide limited details, requiring further investigation.This is due to relying on generalized behavior, such as unusual system interactions or network activities, which might not be explicitly malicious but suspicious enough to trigger a deeper analysis.

In all cases, I usually perform the analysis with the following goals in mind:
* <code class="highlighter-rouge">Determine if the sample is actually doing something harmful, that is true or false positive.</code>
* <code class="highlighter-rouge">The second most important thing to be concerned about is the malware capabilities & the risk associated with it.</code>

In our current scenario, we are mostly going to uncover & highlight some of the main capabilities of the sample and answering the challenge questions as we progress.
Along the way, we will learn various techniques and work arounds to tackle some of the challenges encountered that hindered our dynamic analysis of the malware.

First of all, I`d like to examine my sample using basic static analysis by throwing the sample on PEstudio, DIE for quick triage. We will not spend too much time in this phase as the sample seems to be packed, no visible strings, entropy seems to be high which indicates some degree of packing.

![Entropy](/assets/images/unpackme/Entropy.png)
_Entropy_

We saw <code class="highlighter-rouge">VirtualAlloc</code> as one of the API calls being imported from the imports address table of the sample, so,
Load the sample in x32dbg, and let`s simply start by adding a breakpoint on VirtualAlloc


![VirutallAlloc](/assets/images/unpackme/[2].adding_breakpoint.png)
_ViruallAlloc_


After we run the program, we hit our breakpoint

![VirutallAlloc](/assets/images/unpackme/3.VirtualAlloc.png)
_ViruallAlloc_

Continue until we return back from the system DLLs <code class="highlighter-rouge">(kernal32, etc)</code>, and observe the address returned in EAX

![EAX Address](/assets/images/unpackme/4.Follow.png)
_EAX Address_

Allocated space by VirtualAlloc is currently empty, stepping over a few instructions, particularly after the next call <code class="highlighter-rouge">(call 763E52 in my case)</code>, the memory address started to populate, this memory segment will contains the unpacked binary that malware execution will be transferred to.

![Empty Allocated Space](/assets/images/unpackme/3.EXTRA-Empty.png)
_Empty Allocated Space_

![Function 763E52](/assets/images/unpackme/5.Dump-deobfuscation-call.png)
_Function 763E52_

Scrolling down a bit, we can see the start of an executable file <code class="highlighter-rouge">(MZ header).</code>

![MZ Header](/assets/images/unpackme/6.MZ-Header-After-Scrolling.png)
_MZ Header_

We can follow on memory map, then right-click on the specified memory region and dump it to a file

![dump memory region](/assets/images/unpackme/7.dump-it.png)
_dump memory region_

Open the dumped file in any hex editor and get rid of the extra bytes before the MZ header, then save the file

![Removing Extra Bytes](/assets/images/unpackme/8.remove-extra-HxD.png)
_Removing Extra Bytes_


Now, we should have the clean unpacked sample, and to make sure, we can inspect its imports and strings again. In fact, from strings alone, we have a pretty good idea about what the malware sample might be doing <code class="highlighter-rouge">(information stealer)</code> as we see below

![Strings](/assets/images/unpackme/[9].strings-1.png)
![Strings](/assets/images/unpackme/[9].strings-2.png)
_strings_

Among other things, strings also reveal the internal path of the project build 

![Strings](/assets/images/unpackme/[9].strings-3.png)

Furthermore, if we search for some of the unique strings it would give away the sample varient which is one varient of RacoonStealer.

Now, let`s start examining the malware by Loading the unpacked sample into IDA. The malware begins by creating a mutex <code class="highlighter-rouge">(function sub_DD2DF7)</code> to prevent the malware from being executed twice on the same host.

![Main Function](/assets/images/unpackme/10-MAIN-Function.png)
_Main Function_

We can see the API <code class="highlighter-rouge">OpenMutexA</code> inside the function, with ESI register holding the mutex name.

![CreateMutex](/assets/images/unpackme/11.RenamingFunction.png)
_CreateMutex_


If we debug the sample using IDA, and we examine the address at ESI, we can obtain the Mutex name as below

![IDA Debugging to Find Mutex Name](/assets/images/unpackme/12.MUTEX-ESI-string.png)
_IDA Debugging to Find Mutex Name_

![Mutex Name](/assets/images/unpackme/13.Mutex-STRING.png)
_Mutex Name_


Next, the malware calls (435AE5) which I renamed <code class="highlighter-rouge">CheckPrivs</code> below to check if the process is running with LOCAL SYSTEM privileges, if so, it will proceed by finding explorer.exe process, duplicate its token and continue execution with its privileges.

![checking Priviliges](/assets/images/unpackme/13.2.check-privs-then-compare.png)
_checking Priviliges_

Here is the portion within the next function (435B8A), renamed <code class="highlighter-rouge">Findingexplorerprocess</code> where it is trying to find explorer.exe

![Comparison Loop](/assets/images/unpackme/14.0.loop-comparison-with-explorer-from-ID.png)
_Comparison Loop_

Comparison looking for explorer.exe is shown below from X32dbg

![X64dbg looking for explorer process](/assets/images/unpackme/14.comparison-with-explorer-from-x64dbg-to-show-actual-values.png)
_X64dbg looking for explorer process_

Next up, the execution will continue to find the local machine language by calling both <code class="highlighter-rouge">GetUserDefaultLCID</code> and <code class="highlighter-rouge">GetLocaleInfoA</code>.

![Checking Language](/assets/images/unpackme/16.Checking-language-portions-repeated-section-of-XOR.png)
_Checking Language_

Then it dynamically uses XOR in a bunch of loops to check a set of languages (Russia, Kazakhstan, Uzbekistan, etc) if they match, the malware will stop execution and exit.
The malware uses repetitive XOR blocks to decrypts each segment during execution. At the block location <code class="highlighter-rouge">(loc_429AE3)</code>, before jumping into a different block of code that appears to have some base64 strings, it reveals a special string after finishing the XOR loop.

![Last XOR spits out the key](/assets/images/unpackme/17.Key_from_IDA.png)
_Last XOR spits out the key_

The key is revealed in the memory segment below

![RC4 Key](/assets/images/unpackme/15.111.last-loop-of-XOR-spits-out-the-KEY.png)
_RC4 Key_

This will turn out to be the RC4 key that the malware uses to encrypt all command and control (C2) communications.

In the next section, we encounter three Base64-encoded strings. These are likely to contain critical data such as C2 server addresses.

![Three Base64 strings](/assets/images/unpackme/17.2.00some-base64-being-pushed.png)
_Three Base64 strings_

Stepping over in x32dbg until we hit function <code class="highlighter-rouge">(DB47F6)</code>, after the function call, we immediately notice a C2 domain pops up

```bash
https[::]//tttttt.me/ch0koalpengold
```

![staging domain appearance](/assets/images/unpackme/17.3.Hit-by-the-fun-7F6-after-that-we-saw-the-resolution-of-a-domain-in-EAX.png)
_staging domain appearance_

Let`s step back for a moment and look back before the function gets called, the function had two parameters that were pushed into the stack, one is the base64 decoded value of the first base64 string shown previously, the other is the RC4 Key we just discovered.

![RC4 Decryption Function](/assets/images/unpackme/17.4.Take-a-look-at-the-function-args-it-takes-the-key-and-the-decoded-base64.png)
_RC4 Decryption Function_

Therefore, we know that this function is using the decoded string along with the RC4 key to decrypt its first C2 domain.
If we look back even further, we can get the function that performs the base64 decoding, let`s rename & label those two important functions.
 
![Renaming Functions](/assets/images/unpackme/18.1.base64_and_RC4_decrypt.png)
![Renaming Functions](/assets/images/unpackme/18.0.Base64_fn.png)
_Renaming Functions_

Digging deeper into the RC4 Decryption function, we notice 4 subroutines, from there we can identify the RC4 algorithm by checking both functions <code class="highlighter-rouge">(41468E)</code> and <code class="highlighter-rouge">(414712)</code>

![Inside RC4 Decryption Function](/assets/images/unpackme/18.3stepping-into-this-func-in-IDA-we-see-4-subroutines.png)
_Inside RC4 Decryption Function_

below screenshots clearly shows the key Scheduling Algorithm (KSA) generation  of the RC4 (the 256 loop is a quick giveaway), then the key stream is being XORed with each byte of the payload in the other function.

![RC4 Algorithm](/assets/images/unpackme/RC4-algorithm.png)
_RC4 Algorithm_


Going further after RC4 decryption of the domain, we should expect to see some network communication to that C2 domain, this takes place at function <code class="highlighter-rouge">(430F27)</code> as we see below 

![HTTP REQ Function](/assets/images/unpackme/21.HTTP_REQ_Func.png)
_HTTP REQ Function_

Next function appears to be checking for certain strings in the response body of the HTTP request. We clearly see some html tags <code class="highlighter-rouge">"description and dir=auto></code>

![HTTP Response Comparison](/assets/images/unpackme/22.0.The-function-call-for-resposnce-comparison.png)
_HTTP Response Comparison_

We labeled the function <code class="highlighter-rouge">Rsponse_comparsison</code> in IDA

![HTTP Response Comparison](/assets/images/unpackme/22.1.The-function-call-for-resposnce-comparison-IDA.png)
_HTTP Response Comparison_

To make sense of it, we checked the C2 link that the malware was trying to request <code class="highlighter-rouge">tttttt.me/ch0koalpengol</code>, then looking for the html strings needed, nothing was found. It became clear that the C2 server was no longer active at the time of our analysis.

![Telegram Page](/assets/images/unpackme/the-telegram-page.png)
_Telegram Page_

![Telegram HTML Page](/assets/images/unpackme/the-telegram-code.png)
_Telegram HTML Page_

As a result of that, the malware was stuck at the next block of code, Which is a loop that sleeps for 5 sec. , then continues to request the same domain until the string match is found.

![HTTP REQ Loop](/assets/images/unpackme/22.2.The_HTTP_loop_where_we_first_stucked.png)
_HTTP REQ Loop_


Apparently, this lack of communication with the C2 server hindered our dynamic analysis as the malware was not able to retrieve this string to continue its operation, limiting our ability to observe the full extent of the malware's intended behavior.

So, we have to come up with a different approach to emulate this on our local network to further continue debugging and discover the rest of the stealer operation.

<br>

---
# MALWARE C2 EMULATION

So far, we’ve understood how the malware utilizes RC4 encryption to decrypt its command and control (C2) communications. We also identified that the Base64 string <code class="highlighter-rouge">qSVdAbi/K2pP9eTPjNld5MgaAL+bQsyox4MDv0iVTuA=</code> was actually a Telegram C2 domain after decoding and decryption. To continue with our debugging, we need to modify the code by replacing this Base64 string with our own, which will simulate a C2 server on a local network.

To proceed, we’ll set up an HTTP server on our localhost. Then, prepare a similar C2 page by copying the Telegram HTML code from the original C2 domain to our new page. Additionally, we’ll add the missing HTML strings that the malware would expect to retrieve, ensuring that the local C2 server behaves in a way the malware expects. This setup allows us to continue analyzing the malware's interactions with the C2 and track its behavior in our own environment.

I have added a simple string for testing, Mine would be saved and hosted at <code class="highlighter-rouge">localhost/telegram.html<code>

![Local Modified Copy of Telegram Page](/assets/images/unpackme/23.0.emulated_the_telegram_page_on_our_local_server_and_added_the_expected_response_string.png)
_Local Modified Copy of Telegram Page_

knowing the RC4 key, we can assemble our base64 with the help of CyberChef as below

![CyberChef Base64](/assets/images/unpackme/23-0000modifying_the_telegram_c2_for_emulation.png)
_CyberChef Base64_

Now, let's edit our malware file with a hex editor and search for the base64 string <code class="highlighter-rouge">(qSVdAbi/K2pP9eTPjNld5MgaAL+bQsyox4MDv0iVTuA=)</code>, our goal is to replace that portion with our own base64 so that after malware decodes it, we get our own telegram.html page.

![Malware with HexEditor](/assets/images/unpackme/23.00-HexEditor.png)
_Malware with HexEditor_


After highlighting the reqiured string, Write-click, then choose <code class="highlighter-rouge">paste write</code> and save the file.

Let`s test it by going to the RC4 Decryption instruction (*7F6) and continue debugging, we should see our telegram page being resolved. 

![Local Telegram Page](/assets/images/unpackme/pic.png)
_Local Telegram Page_

Now, if we continue debugging from where we left off, we should jump at the block after the HTTP request, and our embedded string - <code class="highlighter-rouge">representing the simulated C2 domain</code> - should appear as expected

![Modified String](/assets/images/unpackme/23.1.laterom-string.png)
_Modified String_

Next, if we step over a few instruction, we would start to see the string being filtered.

![Filtered String](/assets/images/unpackme/23.2.laterom-filter-string.png)
_Filtered String_


If we look closer after the function that extracts the string, we can observe two successive calls to the same function, which we have renamed <code class="highlighter-rouge">filter_out</code> for clarity. This function plays an important role in filtering the extracted data. In the first call, the value <code class="highlighter-rouge">5</code> is being pushed into the stack before the function call, and value <code class="highlighter-rouge">6</code> in the second function call, which corresponds to filtering out the first 5 characters from the strings, and the last 6 characters respectively.

![Filtered String Function](/assets/images/unpackme/23.3.After_Extracting_Value_it_gets_filtered_Twice_beginning_and_end.png)
_Filtered String Function_

Here is the code inside the function

![Filtered String Function](/assets/images/unpackme/23.4.Inside_the_first_filter_out_functions.png)
_Filtered String Function_

Moving on, after our string was filtered, we observe additional calls to both the <code class="highlighter-rouge">Base64</code> decoding and <code class="highlighter-rouge">RC4</code> decryption functions. These calls reference one of the hardcoded Base64 strings we saw earlier. This indicates that the malware is once again decoding and decrypting data.

![2nd RC4 Decryptian to get the main C2](/assets/images/unpackme/23.5.2nd-RC4-Decryption-of-C2.png)
_2nd RC4 Decryptian to get the main C2_


We know that RaccoonStealer leverages the middle stage we identified earlier (a Telegram channel) to retrieve its main C2 domain from the string, which was missing in our case.

In the screenshot above, the RC4 Decryptian function <code class="highlighter-rouge">(RC4 Decrypt)</code> is used to decrypt our retrieved and filtered string using the referenced hardcoded base64 string as the RC4 key. The output of this decryption process should reveal the malware’s main C2 domain.

Obviously,  our test string currenly does not make sense to the malware opertion. So, we can simulate the operation by reversing the process, similar to what we have done with the telegram domain. Given the new RC4 key, we can asssume a C2 domain hosted in our local server <code class="highlighter-rouge">(localhost/dump.php)</code>, encrypt it using the RC4 Key <code class="highlighter-rouge">(6af7fae138b9752d1d76736dcb534c9d)</code> and produce a base64 sting that can be replaced by our test string in our telegram HTML page.

![producing a main C2 in base64](/assets/images/unpackme/This_time_we_will_use_the_6af_key_instead_for_the_2nd_C2_comm.png)
_2nd RC4 Decryptian to get the main C2_

Now, the generated Base64 string will serve as the main C2, replacing the old string. Remember, we need to pad the string with 5 characters at the beginning and 6 characters at the end. This padding ensures that when the string is passed through the filtering function, it results in the correct domain <code class="highlighter-rouge">(localhost/dump.php)</code>.

![Main C2 Base64 String](/assets/images/unpackme/24.Modifed_the_string_for_the_2nd_c2_to_dump_the_request_to_our_local_server.png)
_Main C2 Base64 String_


let`s puase for a moment and understand how this stealer works and how it usually communicates to its C2.

<br>

-----------------------------
# RacoonStealer C2 Operations

We can understand the C2 operations from various samples that exist on public sandboxes like any.run.

![C2 Operation](/assets/images/unpackme/24.8-C2-Operations.png)
_C2 Operation_

RacconStealer operations usually works by following the below sequence:

1. POST Request to its main C2 server (localhost/dump.php in our case) with identification paramters in the body (botID, configID, etc).

2. The server replies with important malware configuration including a URL for the malware to download additional DLLs required for its stealing operations.


![Malware Config with the URL](/assets/images/unpackme/24.1.Server-Reply-with-config.png)
_Malware Config with the URL_

3. The malware Download/Request the required DLLs (legitimate DLLs) and continue by collecting host information based on its config, finally, exfiltrate all data to the C2 server.

We could use a proxy to capture the malware request to the server and observe the payload, in our case, we prepared a PHP (duip.php) page that will dump the request to a file on disk.

A very handy php script that can perfrom this can be found here

```C++
https://gist.github.com/magnetikonline/650e30e485c0f91f2f40
```

Now, if we return back to our X32dbg and continue after the RC4 Decrypt function of the main C2 (duip.php), few instructions later we hit the first POST request to the server.

![POST Request](/assets/images/unpackme/24.999-2nd-post-duip.png)
_POST Request_

The dumped request is shown below, The payload contians the Bot-ID and Machine ID ecrypted with the same RC4 key.

![First Request dumped](/assets/images/unpackme/23.6-verify-thepost-reuqest-being-dumped.png)
_First Request dumped_


Looking closer at the script <code class="highlighter-rouge">(duip.php)</code>, it returns the string <code class="highlighter-rouge">"Done"</code> which is not expected by the malware, this will cuase the malware to stop and exit later on when it tries to check the server response. 

![Return Value](/assets/images/unpackme/23.return-value.png)
_Return Value_


After the below section which checks the return values, malware exists.

![Checking Configuration](/assets/images/unpackme/23.7-check-config.png)
_Checking Configuration_

To fix this, we need to edit the response wihthin the script, and provide the malware with an expected payload response <code class="highlighter-rouge">(we got a fake response from the same sandbox sample shown earlier)</code>.


![Replacing string with our payload](/assets/images/unpackme/23.9.duip-script-edited.png)
_Replacing string with our payload within the PHP script_


As mentioned, after decoding this payload with the RC4 key, it will reveal several DLLs that the malware downloads to the infected host.

Once downloaded, these DLLs will be placed in the <code class="highlighter-rouge">AppData\LocalLow</code> directory under the user's profile, a location often used by malware to avoid detection.

![Malware Config with the URL](/assets/images/unpackme/24.1.Server-Reply-with-config.png)
_Malware Config with the URL_

![Payload decoded from X32dbg](/assets/images/unpackme/24.999999-decoded.png)
_Payload decoded from X32dbg_


Since we don’t have access to the correct URL to download the required DLLs and as we are emulating the stealer on our own network, we obtained the necessary files from a different RaccoonStealer sample available on the <code class="highlighter-rouge">any.run</code> sandbox.

This way, the malware will continue its operation, allowing us to uncover more of its capabilities. By supplying the DLLs from a similar RaccoonStealer sample, we enable the malware to proceed as it would in a real-world infection, executing its next steps

![DLLs Zipped](/assets/images/unpackme/24.9-Download-DLLs.png)
_DLLs Zipped_

Then, we placed the files in the location where the malware expects to find them, that is under locallow directory.

![Files dropped in LocalLow folder](/assets/images/unpackme/23.8-drops-to-locallow.png)
_Files dropped in LocalLow folder_

Those are legitmate third-party DLLs required by the malware to gather information about the infected machine, some of the DLLs includes <code class="highlighter-rouge">softokn3.dll
, sqlite3.dll, nss3.dll, nssdbm3.dll</code> and others.


DLLs are shown below:


![sqlite3.dll](/assets/images/unpackme/DLLs.png)
_sqlite3.dll_

At this point, the malware would perform the bulk of its stealing functionality, including stealing passwords, credit card information, browser cookies, history, etc.

As an example, sqlite3.dll is utilized to perfrom SQL commands to steal information from browsers of the infected machine.

![sqlite3.dll](/assets/images/unpackme/5000.2sqlite3.png)
_sqlite3.dll_


Continuing the debugging process with X32dbg, we observe that the malware successfully dumps a file named <code class="highlighter-rouge">machineinfo.txt</code> in the <code class="highlighter-rouge">AppData\LocalLow</code> directory. This file contains detailed information about the infected machine, including system-specific data such as hardware details, OS version, and other identifying characteristics. Additionally, it includes the version number of RaccoonStealer.


![Machineinfo.txt](/assets/images/unpackme/50000000.3_machineinfo.txt.png)
_Machineinfo.txt_


Turning our attention to the registry key function calls, if we search for <code class="highlighter-rouge">OpenRegKey</code>, we encounter multiple calls within the code. Focusing on the highlighted function below


![Looking for RegOpenKey](/assets/images/unpackme/30-Function-Call-to-openregkey.png)
_Looking for RegOpenKey_

By tracing this particular call, we can identify which registry keys the malware is targeting, the key name <code class="highlighter-rouge">Uninstall</code> is  a common registry key used to check installed software running on the host

![Installed Software Key](/assets/images/unpackme/30.1.the-registry-key-uninstall.png)
_Installed Software Key_


Malware commonly uses the API call <code class="highlighter-rouge">GdipSaveImageToFile</code> to save images to a file, and by examining this section of code, we can determine that it is being used to perform screen capture from the infected host.

![GdipSaveImageToFile](/assets/images/unpackme/39-The-Function-respnsible-with-capturing-screenshots.png)
_GdipSaveImageToFile_

Checking this API Call cross references, we can obtain the main function address

![screencapture address](/assets/images/unpackme/9000-screencapture.png)
_screencapture address_

Finally, the malware attempts to remove all its traces by executing a command commonly found in many public instances of RaccoonStealer.


![Malware Deletion](/assets/images/unpackme/6000-COMMAND-TO-DELETE-ITSELF.png)
_Malware Deletion_