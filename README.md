<pre>
##############   ####              ####   ####        ####
##############   ####     ####     ####     ####    ####
####             ####    ######    ####       ########
##########       ####   ########   ####         ####
##########        #### ####  #### ####        ########
####               #######    #######       ####    ####
####                 ####       ####      ####        ####                                 :)
</pre>

&nbsp;

# A firmware analysis TUI for reverse engineers.


<img width="854" height="480" alt="fwx" src="https://github.com/user-attachments/assets/33c86986-c4b4-4582-b1d1-ecbf61aa47d4" />


It utilizes the binwalk crate for firmware analysis and extraction, the capstone and object crate for disassembly, the rust_strings crate for embedded strings, and the ratatui crate for the TUI.

# Usage

There is an optimized ELF binary in the **release** directory. Download it and add it to your PATH. This tool has not been tested on windows, if you want to use it you will need to clone the repo and compile it yourself.

The program should be called like: *fwx \<filepath\>* where filepath is the firmware image you are analyzing. This is the only argument.

The UI has 4 windows, one for the disassembly listing, the files found/extracted, the strings extracted, and the entropy. The controls can be found in the bottom left, and there are also vim-like controls like **[j]** and **[k]** to navigate up and down.
It should be noted that the disassembly will most likely fail to populate on its own, as most firmware images do not contain a .text section like a typical binary. There are two ways to generate the disassembly, 

1: *(easier option)* press **[e]** to 
extract the files recursively, and the navigate to the file you want to disassemble and click **[enter]**, or 

2: press m and manually enter binary metadata like architecture, endianess, and offset. 

It should also be noted that if the file is compressed, 
the strings section will most likely not contain anything useful until you perform the extraction, so I recommend doing that before anything.

You will not be able to use **[ctrl + c]** to exit the program, use **[q]** or **[esc]** instead. 
