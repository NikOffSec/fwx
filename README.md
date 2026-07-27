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
[![crates.io](https://img.shields.io/crates/v/fwx.svg)](https://crates.io/crates/fwx)
[![downloads](https://img.shields.io/crates/d/fwx.svg)](https://crates.io/crates/fwx)
[![license](https://img.shields.io/crates/l/fwx.svg)](./LICENSE)

# A firmware analysis TUI for reverse engineers.


<img width="854" height="480" alt="fwx" src="https://github.com/user-attachments/assets/33c86986-c4b4-4582-b1d1-ecbf61aa47d4" />


It utilizes the binwalk crate for firmware analysis and extraction, the capstone and object crate for disassembly, the rust_strings crate for embedded strings, and the ratatui crate for the TUI.

Licensed under the MIT License. See [LICENSE](LICENSE).

# Usage

The program can be installed with *cargo install fwx* and the crates.io page can be found here: https://crates.io/crates/fwx 

The program should be called like: *fwx \<filepath\>* where filepath is the firmware image you are analyzing. This is the only argument.

The UI has 4 windows, one for the disassembly listing, the files found/extracted, the strings extracted, and the entropy. The controls can be found in the bottom left, and there are also vim-like controls like **[j]** and **[k]** to navigate up and down.

It should be noted that the disassembly will most likely not populate on its own, as the firmware image itself most liekly will not contain a .text section like a typical binary, isntead you should select the embedded file that you want to disassemble. There are two ways to generate the disassembly, 

1: *(easier option)* press **[e]** to 
extract the files recursively, and the navigate to the file you want to disassemble and click **[enter]**, or 

2: press m and manually enter binary metadata like architecture, endianess, and offset. 

It should also be noted that if the file is compressed, you will want to extract the files BEFORE you analyze the strings.

You will not be able to use **[ctrl + c]** to exit the program, use **[q]** or **[esc]** instead. 
