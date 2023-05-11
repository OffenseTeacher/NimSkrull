# NimSkrull
<p align="center">
    <img width="500" src="https://github.com/OffenseTeacher/NimSkrull/blob/main/NimSkrull.gif">
</p>
An experiment in improving existing anti-copy techniques. This one allows a binary to rewrite itself on disk after the first execution with the hardcoded function ordinals of the current system instead of function names. As with the original POC (https://github.com/aaaddress1/Skrull), the anti-copy technique won't work between Windows systems that have the same versions of system DLLS.

<br>
<br>
For more information regarding Nim Offensive developpment, see: [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim).
<br>
Special thanks to Fabian Mosch [@S3cur3Th1sSh1t](https://twitter.com/ShitSecure) for it's Nim-RunPE repo, which was used as a foundation.

## How to use
- Install Nim on Linux
- Clone this repo
- compile NimSkrull.nim
- Execute it on arbitrary systems

## How to cross-compile from Linux to Windows
- nim c -d=mingw -d=release --app=console --cpu=amd64 NimSkrull.nim
