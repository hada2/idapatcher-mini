
## IDA Patcher (Mini)

IDA Patcher (Mini) is a ported version of [IDA Patcher](https://github.com/iphelix/ida-patcher) to IDA Pro 7.7. 

The original tool is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's ability to patch binary files and memory. The plugin is useful for tasks related to malware analysis, exploit development as well as bug patching. IDA Patcher blends into the standard IDA user interface through the addition of a subview and several menu items.

## Requirement

* IDA Pro 7.7

## Install

Copy 'idapatcher.py' to IDA's plugins folder. The plugin will be automatically loaded the next time you start IDA Pro.

## Usage

![1.png](img/1.png)

### Edit binary data

* Set the cursor to any position.
* Select `'Edit'` -> `'Patch program'` -> `'Edit selection'`.
* Input hex data in the form. (**The length isn't limited.**)
* Press 'OK'.

![2.png](img/2.png)

* Overwritten with patched data.

![3.png](img/3.png)

### Fill binary data

* Set the cursor to any position.
* Select `'Edit'` -> `'Patch program'` -> `'Fill selection'`.
* Input start address, end address, and new value in the form.
* Press 'Fill'.

![4.png](img/4.png)

* Overwritten with patched data.

![5.png](img/5.png)

## Copyright
* Copyright (C) 2014 Peter Kacherginsky
* Copyright (C) 2022 Hiroki Hada
* All rights reserved.





