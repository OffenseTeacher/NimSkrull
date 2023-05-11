import winim
import std/tables
import strutils except fromHex
from ptr_math import `+=`, `[]`
import segfaults
import streams
from os import getAppFileName

type
  CUSTOM_IMAGE_THUNK_DATA64_u1* {.pure, union.} = object
    ForwarderString*: ULONGLONG
    Function*: ULONGLONG
    Ordinal*: csize_t
    AddressOfData*: ULONGLONG
  CUSTOM_IMAGE_THUNK_DATA64* {.pure.} = object
    u1*: CUSTOM_IMAGE_THUNK_DATA64_u1
  CUSTOM_PIMAGE_THUNK_DATA64* = ptr CUSTOM_IMAGE_THUNK_DATA64
  CUSTOM_PIMAGE_THUNK_DATA* = CUSTOM_PIMAGE_THUNK_DATA64
  BASE_RELOCATION_ENTRY* {.bycopy.} = object
    Offset* {.bitsize: 12.}: WORD
    Type* {.bitsize: 4.}: WORD
const 
  MZ* = 0x5A4D
  RELOC_32BIT_FIELD* = 3

var DS_STREAM_RENAME = newWideCString(":Mr.Bones")

proc ds_open_handle(pwPath: PWCHAR): HANDLE =
    return CreateFileW(pwPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)

proc ds_rename_handle(hHandle: HANDLE): WINBOOL =
    var fRename: FILE_RENAME_INFO
    RtlSecureZeroMemory(addr fRename, sizeof(fRename))

    var lpwStream: LPWSTR = DS_STREAM_RENAME
    fRename.FileNameLength = sizeof(lpwStream).DWORD;
    RtlCopyMemory(addr fRename.FileName, lpwStream, sizeof(lpwStream))

    return SetFileInformationByHandle(hHandle, fileRenameInfo, addr fRename, sizeof(fRename) + sizeof(lpwStream))

proc ds_deposite_handle(hHandle: HANDLE): WINBOOL =
    var fDelete: FILE_DISPOSITION_INFO
    RtlSecureZeroMemory(addr fDelete, sizeof(fDelete))

    fDelete.DeleteFile = TRUE;

    return SetFileInformationByHandle(hHandle, fileDispositionInfo, addr fDelete, sizeof(fDelete).cint)

proc deleteItself() =
    var  wcPath: array[MAX_PATH + 1, WCHAR]
    var  hCurrent: HANDLE

    RtlSecureZeroMemory(addr wcPath[0], sizeof(wcPath));

    if GetModuleFileNameW(0, addr wcPath[0], MAX_PATH) == 0:
        quit(QuitFailure)

    hCurrent = ds_open_handle(addr wcPath[0])
    if hCurrent == INVALID_HANDLE_VALUE:
        quit(QuitFailure)

    if not ds_rename_handle(hCurrent).bool:
        quit(QuitFailure)

    CloseHandle(hCurrent)

    hCurrent = ds_open_handle(addr wcPath[0])
    if hCurrent == INVALID_HANDLE_VALUE:
        quit(QuitFailure)

    if not ds_deposite_handle(hCurrent).bool:
        quit(QuitFailure)

    CloseHandle(hCurrent)


template RVA*(atype: untyped, base_addr: untyped, rva: untyped): untyped = cast[atype](cast[ULONG_PTR](cast[ULONG_PTR](base_addr) + cast[ULONG_PTR](rva)))

template RVASub*(atype: untyped, base_addr: untyped, rva: untyped): untyped = cast[atype](cast[ULONG_PTR](cast[ULONG_PTR](base_addr) - cast[ULONG_PTR](rva)))

template RVA2VA(casttype, dllbase, rva: untyped): untyped =
  cast[casttype](cast[ULONG_PTR](dllbase) + rva)

proc `+`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) + cast[uint](b * a[].sizeof))

proc `-`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) - cast[uint](b * a[].sizeof))


proc getBytesFromFile(path: string): seq[byte] =
    try:
        var
            s = newFileStream(path, fmRead)
            valSeq = newSeq[byte]()
        while not s.atEnd:
            let element = s.readUInt8
            valSeq.add(element)
        s.close()
        return valSeq
    except:
        echo "!! ", path, " was not found !!"
        quit(1)

proc OriginalFirstThunk*(self: ptr IMAGE_IMPORT_DESCRIPTOR): DWORD {.inline.} = self.union1.OriginalFirstThunk

proc getNtHdrs*(pe_buffer: ptr BYTE): ptr BYTE =
  if pe_buffer == nil:
    return nil
  var idh: ptr IMAGE_DOS_HEADER = cast[ptr IMAGE_DOS_HEADER](pe_buffer)
  if idh.e_magic != IMAGE_DOS_SIGNATURE:
    return nil
  let kMaxOffset: LONG = 1024
  var pe_offset: LONG = idh.e_lfanew
  if pe_offset > kMaxOffset:
    return nil
  var inh: ptr IMAGE_NT_HEADERS32 = cast[ptr IMAGE_NT_HEADERS32]((
      cast[ptr BYTE](pe_buffer) + pe_offset))
  if inh.Signature != IMAGE_NT_SIGNATURE:
    return nil
  return cast[ptr BYTE](inh)

proc getPeDir*(pe_buffer: PVOID; dir_id: csize_t): ptr IMAGE_DATA_DIRECTORY =
  if dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES:
    return nil
  var nt_headers: ptr BYTE = getNtHdrs(cast[ptr BYTE](pe_buffer))
  if nt_headers == nil:
    return nil
  var peDir: ptr IMAGE_DATA_DIRECTORY = nil
  var nt_header: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](nt_headers)
  peDir = addr((nt_header.OptionalHeader.DataDirectory[dir_id]))
  if peDir.VirtualAddress == 0:
    return nil
  return peDir

proc Lookup_funcOrdinal*(hLibrary: HMODULE; fname: cstring, specialCase: BOOL): size_t =
  var dos: PIMAGE_DOS_HEADER
  var nt: PIMAGE_NT_HEADERS
  var data: array[0..15, IMAGE_DATA_DIRECTORY]
  var exp: PIMAGE_EXPORT_DIRECTORY
  var exp_size: DWORD
  var adr: PDWORD
  var ord: PDWORD
  var functionAddress: PVOID

  dos = cast[PIMAGE_DOS_HEADER](hLibrary)
  nt = RVA(PIMAGE_NT_HEADERS, cast[PVOID](hLibrary), dos.e_lfanew)
  
  data = nt.OptionalHeader.DataDirectory
  
  exp = RVA(PIMAGE_EXPORT_DIRECTORY, hLibrary, data[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
  exp_size = data[0].Size

  adr = RVA2VA(PDWORD, cast[DWORD_PTR](hLibrary), exp.AddressOfFunctions)
  ord = RVA2VA(PDWORD, cast[DWORD_PTR](hLibrary), exp.AddressOfNameOrdinals)
  
  functionAddress = nil

  var numofnames = cast[DWORD](exp.NumberOfNames)
  var functions = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfFunctions)
  var functionsOrd = functions
  var addressOfFunctionsvalue = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfFunctions)[]
  var names = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfNames)[]
  
  if fname != "":
    ##  iterate over all the exports

    for i in 0 .. numofnames:
      # Getting the function name value
      var funcname = RVA2VA(cstring, cast[PVOID](hLibrary), names)
      var finalfunctionAddress = RVA(PVOID, cast[PVOID](hLibrary), addressOfFunctionsvalue)
      # We are comparing against function names, which include "." because for some reason all function names in this loop also contain references to other DLLs, e.g. "api-ms-win-core-libraryloader-l1-1-0.AddDllDirectory" in kernel32.dll
      var test = StrRStrIA(cast[LPCSTR](funcname),nil,cast[LPCSTR]("."))

      if test != nil:
        # As we found a trash (indirect reference, normally this is in the address field and not in the names field) function, we have to increase this value -> Not an official function
        numofnames = numofnames + 1
      else:
        functions = functions + 1
        addressOfFunctionsvalue = functions[]
      names += cast[DWORD](len(funcname) + 1)
      if fname == funcname:
        functionAddress = finalfunctionAddress
        var functionAddressOrd : PVOID = nil

        for i in 0 .. 5000: #Small hack, no ordinal is above that.
          functionsOrd += 1
          try:
            functionAddressOrd = RVA(PVOID, hLibrary, functionsOrd[])
            if repr(functionAddressOrd) == repr(functionAddress):
              return i
          except:
            discard


proc patchIAT*(modulePtr: PVOID): bool =
  var successPatch = false
  echo "[+] Fix Import Address Table"
  var importsDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(modulePtr,
      IMAGE_DIRECTORY_ENTRY_IMPORT)
  if importsDir == nil:
    return false
  var maxSize: csize_t = cast[csize_t](importsDir.Size)
  var impAddr: csize_t = cast[csize_t](importsDir.VirtualAddress)
  
  var impLibDesc: ptr IMAGE_IMPORT_DESCRIPTOR
  var parsedSize: csize_t = 0
  while parsedSize < maxSize:
    impLibDesc = cast[ptr IMAGE_IMPORT_DESCRIPTOR]((impAddr + parsedSize + cast[uint64](modulePtr)))
    
    if (impLibDesc.OriginalFirstThunk == 0) and (impLibDesc.FirstThunk == 0):
      break
    var szImpLib: LPSTR = cast[LPSTR](cast[ULONGLONG](modulePtr) + impLibDesc.Name)
    #echo "\r\n    [+] Import DLL: ", $szImpLib
    var callVia: csize_t = cast[csize_t](impLibDesc.FirstThunk)
    var orgThunk: csize_t = cast[csize_t](impLibDesc.OriginalFirstThunk)
    if orgThunk == 0:
      orgThunk = csize_t(impLibDesc.FirstThunk)
    var offsetField: csize_t = 0
    var offsetThunk: csize_t = 0
    var impLib: HMODULE = LoadLibraryA(szImpLib)
    #-----
    while true:
      var callVia: CUSTOM_PIMAGE_THUNK_DATA = cast[CUSTOM_PIMAGE_THUNK_DATA]((
          cast[csize_t](modulePtr) + offsetField + callVia))
      var orgThunk: CUSTOM_PIMAGE_THUNK_DATA = cast[CUSTOM_PIMAGE_THUNK_DATA]((
          cast[csize_t](modulePtr) + offsetThunk + orgThunk))

      var boolvar: bool
      if ((cast[int](orgThunk.u1.Ordinal) and IMAGE_ORDINAL_FLAG32) != 0):
        boolvar = true
      elif((cast[int](orgThunk.u1.Ordinal) and IMAGE_ORDINAL_FLAG64) != 0):
        boolvar = true
      if (boolvar):
        var libaddr: size_t = cast[size_t](GetProcAddress(LoadLibraryA(szImpLib),cast[LPSTR]((orgThunk.u1.Ordinal and 0xFFFF))))
        callVia.u1.Function = ULONGLONG(libaddr)
      if callVia.u1.Function == 0:
        break
      if callVia.u1.Function == orgThunk.u1.Function:
        var nameData: PIMAGE_IMPORT_BY_NAME = cast[PIMAGE_IMPORT_BY_NAME](orgThunk.u1.AddressOfData)
        var byname: PIMAGE_IMPORT_BY_NAME = cast[PIMAGE_IMPORT_BY_NAME](cast[ULONGLONG](modulePtr) + cast[DWORD](nameData))
      
        #var func_name: LPCSTR = cast[LPCSTR](addr byname.Name)
        var func_name: cstring = cast[cstring](addr byname.Name)
        var numOrdinal = Lookup_funcOrdinal(impLib, func_name, false) #WIP
        if $szImpLib == "api-ms-win-core-memory-l1-1-0.dll" or $szImpLib == "api-ms-win-core-libraryloader-l1-2-0.dll":
          numOrdinal = numOrdinal + 3
          callVia.u1.Ordinal = cast[csize_t](cast[uint](numOrdinal) or cast[uint](IMAGE_ORDINAL_FLAG64)) #WIP
          orgThunk.u1.Ordinal = callVia.u1.Ordinal # WIP
          #echo "    [+] ", $szImpLib, ",", func_name, ",", numOrdinal, ",", callVia.u1.Ordinal
          successPatch = true
        if $szImpLib == "msvcrt.dll" or $szImpLib == "KERNEL32.dll":
          numOrdinal = numOrdinal + 2
          if func_name == "memmove":
            numOrdinal = numOrdinal + 2
          callVia.u1.Ordinal = cast[csize_t](cast[uint](numOrdinal) or cast[uint](IMAGE_ORDINAL_FLAG64)) #WIP
          orgThunk.u1.Ordinal = callVia.u1.Ordinal
          #echo "    [+] ", $szImpLib, ",", func_name, ",", numOrdinal, ",", callVia.u1.Ordinal
          successPatch = true
        if startsWith($func_name, "Nt") or startsWith($func_name, "Tp"):
          numOrdinal = numOrdinal + 10
          callVia.u1.Ordinal = cast[csize_t](cast[uint](numOrdinal) or cast[uint](IMAGE_ORDINAL_FLAG64)) #WIP
          orgThunk.u1.Ordinal = callVia.u1.Ordinal
          #echo "    [+] ", $szImpLib, ",", func_name, ",", numOrdinal, ",", callVia.u1.Ordinal
          successPatch = true

      inc(offsetField, sizeof((IMAGE_THUNK_DATA)))
      inc(offsetThunk, sizeof((IMAGE_THUNK_DATA)))
    inc(parsedSize, sizeof((IMAGE_IMPORT_DESCRIPTOR)))
  return successPatch

proc flushImgToExe(image: ptr BYTE ) =
  deleteItself()
  var szTarget = getAppFileName()
  var ntHeader: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](getNtHdrs(image))
  var sectionHeaderArr: ptr IMAGE_SECTION_HEADER = cast[ptr IMAGE_SECTION_HEADER]((cast[size_t](ntHeader) + sizeof((IMAGE_NT_HEADERS))))
  var exeFileSize = 
    sectionHeaderArr[cast[int](ntHeader.FileHeader.NumberOfSections) - 1].PointerToRawData +
    sectionHeaderArr[cast[int](ntHeader.FileHeader.NumberOfSections) - 1].SizeOfRawData
  var exeFileData = newSeq[byte](exeFileSize)
  copymem(cast[ptr byte](exeFileData[0].addr), image, ntHeader.OptionalHeader.SizeOfHeaders)
  for i in 0 .. (cast[int](ntHeader.FileHeader.NumberOfSections) - 1):
    copymem(&exeFileData[sectionHeaderArr[i].PointerToRawData], &image[sectionHeaderArr[i].VirtualAddress], sectionHeaderArr[i].SizeOfRawData);
  
  var f = newFileStream(szTarget, fmWrite)
  if not f.isNil:
    for current_byte in exeFileData:
      f.write current_byte
  f.flush

proc skrullDRM() =

  var memloadBytes = getBytesFromFile(getAppFileName())
  var shellcodePtr: ptr = memloadBytes[0].addr

  var pImageBase: ptr BYTE = nil
  var preferAddr: LPVOID = nil
  var ntHeader: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](getNtHdrs(shellcodePtr))
  if (ntHeader == nil):
    echo "[+] File isn\'t a PE file."
    quit()

  var relocDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(shellcodePtr,IMAGE_DIRECTORY_ENTRY_BASERELOC)
  preferAddr = cast[LPVOID](ntHeader.OptionalHeader.ImageBase)

  pImageBase = cast[ptr BYTE](VirtualAlloc(preferAddr,
                                        ntHeader.OptionalHeader.SizeOfImage,
                                        MEM_COMMIT or MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE))

  if (pImageBase == nil and relocDir == nil):
    echo "[-] Allocate Image Base At Failure.\n"
    quit()
  if (pImageBase == nil and relocDir != nil):
    echo"[+] Try to Allocate Memory for New Image Base\n"
    pImageBase = cast[ptr BYTE](VirtualAlloc(nil,
        ntHeader.OptionalHeader.SizeOfImage, MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE))
    if (pImageBase == nil):
      echo"[-] Allocate Memory For Image Base Failure.\n"
      quit()
  echo"[+] Mapping Section ..."
  ntHeader.OptionalHeader.ImageBase = cast[ULONGLONG](pImageBase)
  copymem(pImageBase, shellcodePtr, ntHeader.OptionalHeader.SizeOfHeaders)
  var SectionHeaderArr: ptr IMAGE_SECTION_HEADER = cast[ptr IMAGE_SECTION_HEADER]((cast[size_t](ntHeader) + sizeof((IMAGE_NT_HEADERS))))
  var i: int = 0
  while i < cast[int](ntHeader.FileHeader.NumberOfSections):
    echo "    [+] Mapping Section :", $(addr SectionHeaderArr[i].addr.Name)
    var dest: LPVOID = (pImageBase + SectionHeaderArr[i].VirtualAddress)
    var source: LPVOID = (shellcodePtr + SectionHeaderArr[i].PointerToRawData)
    copymem(dest,source,cast[DWORD](SectionHeaderArr[i].SizeOfRawData))
    inc(i)

  var goodrun = patchIAT(pImageBase)

  if goodrun:
    flushImgToExe(pImageBase)
    echo "[!] first time running? it's ok! under armer now."
  else:
    echo "[v] anti-copy armer mode ;)"

when isMainModule:
    skrullDRM()
    
