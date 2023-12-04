using System;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace COFFLoader
{
    unsafe class CoffParser
    {
        private delegate int tmpFuncDelegate(char* argData, int argSize);
        private delegate char* FuncDelegate_GetOutput(int* argSize);
        private static List<IntPtr> beaconSectionMapping;
        private static List<IntPtr> coffSectionMapping;
        private static List<BEACON_FUNCTION> BeaconInternalMapping;

        private static IntPtr beaconFunctionMapping;
        private static IntPtr coffFunctionMapping;

        private static uint hash_djb(byte[] data)
        {
            byte c;
            uint hash = 5381;

            for (int count = 0; count < data.Length; count++)
            {
                c = data[count];
                hash = ((hash << 5) + hash) + c;
            }
            return hash;
        }

        private static void memset(IntPtr dst, byte src, int size)
        {
            int index = 0;
            byte* d = (byte*)dst;
            for (index = 0; index < size; index++)
            {
                d[index] = src;
            }
        }

        private static void memcpy(IntPtr dst, byte* src, int size)
        {
            int index = 0;
            byte* d = (byte*)dst;
            for (index = 0; index < size; index++)
            {
                d[index] = src[index];
            }
        }

        private static int memcmp(byte* dst, string src)
        {
            int index = 0;
            int size = src.Length;
            byte[] d = new byte[size];
            for (index = 0; index < size; index++)
            {
                d[index] = dst[index];
                if (dst[index] == '\x00')
                    break;
            }
            string dd = Encoding.Default.GetString(d);
            if (dd == src)
                return 0;
            return 1;
        }

        /* Helper function to process a symbol string, determine what function and
         * library its from, and return the right function pointer. Will need to
         * implement in the loading of the beacon internal functions, or any other
         * internal functions you want to have available. */
        private static void* process_symbol(string symbolstring)
        {
            int PREPENDSYMBOLVALUELEN = 6; // TODO Move to global
            void* functionaddress;
            string localfunc;
            string[] subs;
            string locallib;
            string localfunc2;
            IntPtr hModule;

            if (symbolstring.Contains("__ms_"))
                PREPENDSYMBOLVALUELEN = 5;
            if (symbolstring.Length < PREPENDSYMBOLVALUELEN)
            {
                return null;
            }

            if (symbolstring.StartsWith("MSVCRT") == true)
            {
                localfunc = symbolstring;
            }
            else
            {
                localfunc = symbolstring.Substring(PREPENDSYMBOLVALUELEN);
            }
            foreach (BEACON_FUNCTION tmp in BeaconInternalMapping)
            {
                if (hash_djb(Encoding.Default.GetBytes(localfunc)) == tmp.hash)
                {
                    Debug.WriteLine(String.Format("\t\tInternalFunction: {0}", localfunc));
                    functionaddress = tmp.function;
                    return functionaddress;
                }
            }

            Debug.WriteLine(String.Format("\t\tlocalfunc : ({0})", localfunc));
			if ( (localfunc== "LoadLibraryA") || (localfunc== "GetProcAddress") || (localfunc== "FreeLibrary")|| (localfunc== "GetModuleHandleA"))
			{
                Debug.WriteLine(String.Format("\t\tFOUND IT: {0}\n", localfunc));

				hModule = Win32.LoadLibrary("Kernel32.dll");
                functionaddress = (void*)Win32.GetProcAddress(hModule, localfunc);
                Debug.WriteLine(String.Format("\t\tProcaddress: 0x{0:X}", ((IntPtr)functionaddress).ToInt64()));

                return functionaddress;
			}
            if (symbolstring.Contains("$") == false)
            {
                Debug.WriteLine(String.Format("Error: process_symbol. No library found in {0}", localfunc));
                return null;
            }
            subs = localfunc.Split(new char[] { '$' });
            locallib = subs[0] + ".dll";
            Debug.WriteLine(String.Format("\t\tLibrary: {0}", locallib));
            subs = localfunc.Substring(subs[0].Length + 1).Split(new char[] { '@' });
            localfunc2 = subs[0];
            Debug.WriteLine(String.Format("\t\tFunction: {0}", localfunc2));

            hModule = Win32.GetModuleHandle(locallib);
            if (hModule == IntPtr.Zero)
            {
                hModule = Win32.LoadLibrary(locallib);
            }
            functionaddress = (void*)Win32.GetProcAddress(hModule, localfunc2);
            Debug.WriteLine(String.Format("\t\tProcaddress: 0x{0:X}", ((IntPtr)functionaddress).ToInt64()));

            return functionaddress;
        }

        public static int parseCOFF(
            byte[] functionname,
            byte[] data,
            int filesize,
            byte[] argumentdata,
            int argumentSize
        )
        {
            COFF_FILE_HEADER* coff_header;
            COFF_SECT* coff_sect;
            COFF_RELOC* coff_reloc;
            COFF_SYM* coff_sym;
            int functionMappingCount = 0;

            int retcode = 0;
            int counter = 0;
            int reloccount = 0;
            int tempcounter = 0;
            int symptr = 0;
            uint offsetvalue = 0;
            bool isBeaconObject = argumentdata == null;

            List<IntPtr> sectionMapping;
            IntPtr functionMapping;
            IntPtr unmanagedData = IntPtr.Zero;
            try
            {
                unmanagedData = Marshal.AllocHGlobal(data.Length);
            }catch (Exception e)
            {
                Debug.WriteLine(string.Format("Exception: '{0}'", e));
                retcode = 1;
                goto cleanup;
            }


            if (isBeaconObject == true)
            {
                // This section should always be done first. Parse beacon obj before the coff or else it won't work
                beaconSectionMapping = new List<IntPtr>();
                coffSectionMapping = new List<IntPtr>();
                BeaconInternalMapping = new List<BEACON_FUNCTION>();
                sectionMapping = beaconSectionMapping;
                beaconFunctionMapping = Win32.VirtualAlloc(
                    IntPtr.Zero,
                    2048,
                    (uint)(
                        Win32.AllocationType.Commit
                        | Win32.AllocationType.Reserve
                        | Win32.AllocationType.TopDown
                    ),
                    (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE
                );
                coffFunctionMapping = Win32.VirtualAlloc(
                    IntPtr.Zero,
                    2048,
                    (uint)(
                        Win32.AllocationType.Commit
                        | Win32.AllocationType.Reserve
                        | Win32.AllocationType.TopDown
                    ),
                    (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE
                );
                functionMapping = beaconFunctionMapping;
                Debug.WriteLine(string.Format("functionMapping 0x{0:X}", functionMapping.ToInt64()));
            }
            else
            {
                sectionMapping = coffSectionMapping;
                functionMapping = coffFunctionMapping;
            }

            if (data == null)
            {
                Debug.WriteLine("Can't execute NULL\n");
                goto cleanup;
            }

            Marshal.Copy(data, 0, unmanagedData, data.Length);
            byte* coff_data = (byte*)unmanagedData.ToPointer();
            coff_header = (COFF_FILE_HEADER*)coff_data;
            Debug.WriteLine(StructHelper.PrintStruct(coff_header));

            for (counter = 0; counter < coff_header->NumberOfSections; counter++)
            {
                Debug.WriteLine(string.Format(
                    "header size: 0x{0:X} size char 0x{1:X} size byte 0x{2:X}",
                    sizeof(COFF_FILE_HEADER),
                    sizeof(char),
                    sizeof(byte))
                );
                Debug.WriteLine(string.Format(
                    "sect size: {0}, 0x{1:X} 0x{2:X}",
                    counter,
                    sizeof(COFF_SECT),
                    counter * sizeof(COFF_SECT))
                );
                coff_sect = (COFF_SECT*)(
                    coff_data + sizeof(COFF_FILE_HEADER) + (counter * sizeof(COFF_SECT))
                );
                Debug.WriteLine(StructHelper.PrintStruct(coff_sect));
                int rawSize = coff_sect->SizeOfRawData;

                Debug.WriteLine(String.Format(
                    "size: 0x{0:X}\nalloctype: 0x{1:X}\nProtect: 0x{2:X}",
                    rawSize,
                    (uint)(
                        Win32.AllocationType.Commit
                        | Win32.AllocationType.Reserve
                        | Win32.AllocationType.TopDown
                    ),
                    (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE)
                );
                IntPtr tmpAddr = Win32.VirtualAlloc(
                    IntPtr.Zero,
                    (uint)rawSize,
                    (uint)(
                        Win32.AllocationType.Commit
                        | Win32.AllocationType.Reserve
                        | Win32.AllocationType.TopDown
                    ),
                    (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE
                );
                if (tmpAddr == IntPtr.Zero)
                {
                    Debug.WriteLine("TmpAddr == 0");
                    Debug.WriteLine(Win32.GetLastError());
                }
                Debug.WriteLine(string.Format("Allocated section 0x{0} at 0x{1:X}\n", counter, tmpAddr.ToInt64()));
                if (coff_sect->PointerToRawData > 0)
                {
                    memcpy(tmpAddr, coff_data + coff_sect->PointerToRawData, rawSize);
                }

                sectionMapping.Add(tmpAddr);
            }

            /* Start parsing the relocations, and *hopefully* handle them correctly. */
            for (counter = 0; counter < coff_header->NumberOfSections; counter++)
            {
                Debug.WriteLine(String.Format("Doing Relocations of section: {0}\n", counter));
                coff_sect = (COFF_SECT*)(
                    coff_data + sizeof(COFF_FILE_HEADER) + (counter * sizeof(COFF_SECT))
                );
                Debug.WriteLine(StructHelper.PrintStruct(coff_sect));

                for (reloccount = 0; reloccount < coff_sect->NumberOfRelocations; reloccount++)
                {
                    Debug.WriteLine("----------------------- new relocation ----");
                    coff_reloc = (COFF_RELOC*)(
                        coff_data
                        + coff_sect->PointerToRelocations
                        + (sizeof(COFF_RELOC) * reloccount)
                    );
                    Debug.WriteLine(StructHelper.PrintStruct(coff_reloc));

                    coff_sym = (COFF_SYM*)(
                        coff_data
                        + coff_header->PointerToSymbolTable
                        + (coff_reloc->SymbolTableIndex * sizeof(COFF_SYM))
                    );
                    Debug.WriteLine(StructHelper.PrintStruct(coff_sym));

                    if (coff_sym->value_u[0] != 0)
                    {
                        if (coff_reloc->Type == Win32.IMAGE_REL_AMD64_ADDR64) // Type == 1 relocation is the 64-bit VA of the relocation target
                        {
                            ulong longoffsetvalue = 0;
                            Debug.WriteLine("coff_sym->value_u[0] != 0  <==> coff_reloc->type = 1");
                            Debug.WriteLine(sectionMapping[counter]);
                            Debug.WriteLine(coff_reloc->VirtualAddress);

                            longoffsetvalue = (ulong)
                                Marshal.ReadInt64(
                                    new IntPtr(
                                        sectionMapping[counter].ToInt64()
                                            + coff_reloc->VirtualAddress
                                    )
                                );
                            Debug.WriteLine(string.Format(
                                "\tReadin longOffsetValue : 0x{0:llX}",
                                longoffsetvalue)
                            );
                            longoffsetvalue =
                                (ulong)sectionMapping[coff_sym->SectionNumber - 1].ToInt64()
                                + longoffsetvalue;
                            Debug.WriteLine(string.Format(
                                "\tModified longOffsetValue : 0x{0:llX} Base Address: 0x{1:llX}",
                                longoffsetvalue,
                                sectionMapping[coff_sym->SectionNumber - 1])
                            );
                            Marshal.WriteInt64(
                                new IntPtr(
                                    sectionMapping[counter].ToInt64() + coff_reloc->VirtualAddress
                                ),
                                (long)longoffsetvalue
                            );
                        }
                        else if (coff_reloc->Type == Win32.IMAGE_REL_AMD64_ADDR32NB) /* This is Type == 3 relocation code */
                        {
                            Debug.WriteLine("coff_sym->value_u[0] != 0  <==> coff_reloc->type = 3");
                            Debug.WriteLine(String.Format("\tReadin counter: 0x{0:X}", counter));
                            offsetvalue = (uint)
                                Marshal.ReadInt32(
                                    new IntPtr(
                                        sectionMapping[counter].ToInt64()
                                            + coff_reloc->VirtualAddress
                                    )
                                );
                            long a =
                                sectionMapping[coff_sym->SectionNumber - 1].ToInt64() + offsetvalue;
                            long b =
                                sectionMapping[counter].ToInt64() + coff_reloc->VirtualAddress + 4;
                            Debug.WriteLine(String.Format("\tReadin OffsetValue : 0x{0:X}", offsetvalue));
                            Debug.WriteLine(String.Format("\t\tReferenced Section: 0x{0:X}", a));
                            Debug.WriteLine(String.Format("\t\tEnd of Relocation Bytes: 0x{0:X}", b));
                            if ((a - b) > 0xffffffff)
                            {
                                Console.WriteLine("Relocations > 4 gigs away, exiting");
                                retcode = 1;
                                goto cleanup;
                            }
                            offsetvalue = (uint)(a - b);
                            Debug.WriteLine(String.Format("\tOffsetValue : 0x{0:X}\n", offsetvalue));
                            Debug.WriteLine(String.Format(
                                "\t\tSetting 0x{0:X} to 0x{1:X}\n",
                                sectionMapping[counter].ToInt64() + coff_reloc->VirtualAddress,
                                offsetvalue)
                            );
                            Marshal.WriteInt32(new IntPtr(b - 4), (int)offsetvalue);
                        }
                        else if (coff_reloc->Type == Win32.IMAGE_REL_AMD64_REL32) /* This is Type == 4 relocation code, needed to make global variables to work correctly */
                        {
                            Debug.WriteLine("coff_sym->value_u[0] != 0  <==> coff_reloc->type = 4");
                            offsetvalue = (uint)
                                Marshal.ReadInt32(
                                    new IntPtr(
                                        sectionMapping[counter].ToInt64()
                                            + coff_reloc->VirtualAddress
                                    )
                                );
                            Debug.WriteLine(String.Format("\t\tReadin offset value: 0x{0:X}", offsetvalue));
                            if (coff_sym->SectionNumber == 0 && coff_sym->Value == 0)
                            {
                                Debug.WriteLine("External Function found: ");
                            }
                            else
                            {
                                long a = sectionMapping[coff_sym->SectionNumber - 1].ToInt64();
                                long b =
                                    sectionMapping[counter].ToInt64()
                                    + coff_reloc->VirtualAddress
                                    + 4;

                                if ((a - b) > 0xffffffff)
                                {
                                    Console.WriteLine("Relocations > 4 gigs away, exiting");
                                    retcode = 1;
                                    goto cleanup;
                                }

                                offsetvalue += (uint)(a - b);
                                offsetvalue += (uint)coff_sym->Value;
                                offsetvalue += (uint)(
                                    coff_reloc->Type - Win32.IMAGE_REL_AMD64_REL32
                                );
                                Debug.WriteLine(String.Format("\t\tRelative address: 0x{0:X}", offsetvalue));
                                Marshal.WriteInt32(new IntPtr(b - 4), (int)offsetvalue);
                            }
                        }
                        else
                        {
                            Debug.WriteLine(String.Format("No code for relocation type: {0}", coff_reloc->Type));
                        }
                    }
                    else
                    {
                        symptr = coff_sym->value_u[1];

                        Debug.WriteLine(symptr);
                        int offset =
                            coff_header->PointerToSymbolTable
                            + (coff_header->NumberOfSymbols * sizeof(COFF_SYM))
                            + symptr;
                        string functionName = Marshal.PtrToStringAnsi(
                            new IntPtr((char*)(coff_data + offset))
                        );
                        Debug.WriteLine(String.Format("offset 0x{0:X}, functionName {1}", offset, functionName));

                        void* funcptrlocation = process_symbol(functionName);
                        if (funcptrlocation == null && isBeaconObject == false)
                        {
                            Debug.WriteLine("Failed to resolve symbol! Fatal!\n");
                            retcode = 1;
                            goto cleanup;
                        }
                        if (coff_reloc->Type == Win32.IMAGE_REL_AMD64_REL32)
                        {
                            /* This is Type == 4 relocation code */
                            Debug.WriteLine("coff_sym->value_u[0] == 0  <==> coff_reloc->type = 4");
                            long tmp = functionMapping.ToInt64();
                            Debug.WriteLine("Doing function relocation\n");
                            Debug.WriteLine(String.Format("\tbase functionMapping \t0x{0:X}", tmp));
                            Debug.WriteLine(String.Format(
                                "\tsectionMapping[{0}] \t 0x{1:X}",
                                counter,
                                sectionMapping[counter].ToInt64() )
                            );
                            Debug.WriteLine( string.Format(
                                "\tdifference 0x{0:X}",
                                tmp - sectionMapping[counter].ToInt64() )
                            );
                            long a = tmp + functionMappingCount * 8;
                            long b =
                                sectionMapping[counter].ToInt64() + coff_reloc->VirtualAddress + 4;
                            // Checks the distance between the raw code section and the relocation table
                            if ((a - b) > 0xffffffff)
                            {
                                Console.WriteLine("Relocations > 4 gigs away, exiting\n");
                                retcode = 1;
                                goto cleanup;
                            }

                            Win32.memcpy(
                                new IntPtr(a),
                                BitConverter.GetBytes(new IntPtr(funcptrlocation).ToInt64()),
                                sizeof(long)
                            );
                            Debug.WriteLine(string.Format("\tfunctionMapping addr:\t0x{0:X}", a));
                            Debug.WriteLine(string.Format(
                                "\t\tRelative address : 0x{0:X}",
                                new IntPtr(b - 4).ToInt64())
                            );
                            Debug.WriteLine(string.Format("\t\toffset value: 0x{0:X}", (a - b)));
                            Win32.memcpy(
                                new IntPtr(b - 4),
                                BitConverter.GetBytes(a - b),
                                sizeof(uint)
                            );
                            functionMappingCount++;
                        }
                        else if (
                            coff_reloc->Type >= Win32.IMAGE_REL_AMD64_REL32
                            && coff_reloc->Type <= Win32.IMAGE_REL_AMD64_REL32_5
                        )
                        {
                            Debug.WriteLine(
                                "coff_sym->value_u[0] == 0  <==> coff_reloc->type between 4 and 9"
                            );
                            /* This shouldn't be needed here, but incase there's a defined symbol
                             * that somehow doesn't have a function, try to resolve it here.*/
                            long a = sectionMapping[coff_sym->SectionNumber - 1].ToInt64();
                            long b =
                                sectionMapping[counter].ToInt64() + coff_reloc->VirtualAddress + 4;
                            IntPtr c = new IntPtr(b - 4);
                            long offsetvalue1 = (long)Marshal.ReadInt32(c);

                            if ((a - b) > 0xffffffff)
                            {
                                Console.WriteLine("Relocations > 4 gigs away, exiting\n");
                                retcode = 1;
                                goto cleanup;
                            }
                            Debug.WriteLine(string.Format("\t\tReadin offset value: 0x{0:X}", offsetvalue1));
                            offsetvalue1 +=
                                sectionMapping[coff_sym->SectionNumber - 1].ToInt64() - b;
                            offsetvalue1 += coff_sym->Value;
                            offsetvalue1 += (coff_reloc->Type - Win32.IMAGE_REL_AMD64_REL32);
                            Debug.WriteLine(string.Format("\t\tRelative address: 0x{0:X}", offsetvalue1));
                            Marshal.WriteIntPtr(c, new IntPtr(offsetvalue1));
                        }
                        else
                        {
                            Debug.WriteLine(string.Format("No code for relocation type: {0}", coff_reloc->Type));
                        }
                    }
                }
            }

            Debug.WriteLine("Symbols:");
            for (tempcounter = 0; tempcounter < coff_header->NumberOfSymbols; tempcounter++)
            {
                coff_sym = (COFF_SYM*)(
                    coff_data + coff_header->PointerToSymbolTable + (tempcounter * sizeof(COFF_SYM))
                );
                Debug.WriteLine(StructHelper.PrintStruct(coff_sym));
                if (isBeaconObject == false)
                {
                    if (memcmp(coff_sym->Name, Encoding.Default.GetString(functionname)) == 0)
                    {
                        Debug.WriteLine(string.Format(
                            "\t\tFound entry {1}! \n\t\t\t Address to execute: 0x{0:X}",
                            sectionMapping[coff_sym->SectionNumber - 1].ToInt64() + coff_sym->Value,
                            Encoding.Default.GetString(functionname))
                        );
                        tmpFuncDelegate foo = (tmpFuncDelegate)
                            Marshal.GetDelegateForFunctionPointer(
                                new IntPtr(
                                    sectionMapping[coff_sym->SectionNumber - 1].ToInt64()
                                        + coff_sym->Value
                                ),
                                typeof(tmpFuncDelegate)
                            );
                        int size = Encoding.Default.GetString(argumentdata).Length;
                        byte* funcName = (byte*)
                            Win32.VirtualAlloc(
                                IntPtr.Zero,
                                (uint)size,
                                (uint)(
                                    Win32.AllocationType.Commit
                                    | Win32.AllocationType.Reserve
                                    | Win32.AllocationType.TopDown
                                ),
                                (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE
                            );
                        for (int i = 0; i < size; i++)
                        {
                            funcName[i] = argumentdata[i];
                        }

                        foo((char*)funcName, argumentSize);
                        Debug.WriteLine("Beacon Object File Completed.");
                        Win32.VirtualFreeEx(
                            IntPtr.Zero,
                            (IntPtr)funcName,
                            IntPtr.Zero,
                            Win32.AllocationType.Release
                        );
                        break;
                    }
                }
                else
                {
                    if (
                        coff_sym->value_u[0] != 0
                        || coff_sym->Type != 0x20
                        || coff_sym->SectionNumber != 1
                    )
                        continue;
                    string functionName = Marshal.PtrToStringAnsi(
                        new IntPtr(
                            (char*)(
                                coff_data
                                + coff_header->PointerToSymbolTable
                                + (coff_header->NumberOfSymbols * sizeof(COFF_SYM))
                                + coff_sym->value_u[1]
                            )
                        )
                    );
                    Debug.WriteLine(string.Format("\tFunction Name {0} ", functionName));
                    string localfunc;

                    localfunc = functionName;
                    Debug.WriteLine(string.Format(
                        "\tFunction Name {0} Hash: 0x{1:X}",
                        localfunc,
                        hash_djb(Encoding.Default.GetBytes(localfunc)))
                    );
                    IntPtr functionAddress = new IntPtr(
                        sectionMapping[coff_sym->SectionNumber - 1].ToInt64() + coff_sym->Value
                    );
                    BeaconInternalMapping.Add(
                        new BEACON_FUNCTION(
                            hash_djb(Encoding.Default.GetBytes(localfunc)),
                            functionAddress.ToPointer()
                        )
                    );
                }
            }
            cleanup:
            if (unmanagedData != IntPtr.Zero)
                Marshal.FreeHGlobal(unmanagedData);

            if (isBeaconObject == false)
            {
                CleanUpMemoryAllocations();
            }
            return retcode;
        }

        public static int ZeroAndFree(IntPtr ptr, int size)
        {
            try
            {
                if (size > 0)
                    memset(ptr, (byte)'\x00', size);
                Win32.VirtualFreeEx(IntPtr.Zero, ptr, IntPtr.Zero, Win32.AllocationType.Release);
            }
            catch (Exception e)
            {
                Debug.WriteLine(string.Format("Exception: '{0}'", e));
            }
            return 0;
        }

        public static int CleanUpMemoryAllocations()
        {
            // TODO: Optionally, zero out or stomp memory of loaded object file, Would need to reparse the sectons or store the size somewhere
            foreach (IntPtr ptr in beaconSectionMapping)
                ZeroAndFree(ptr, 0);
            foreach (IntPtr ptr in coffSectionMapping)
                ZeroAndFree(ptr, 0);
            if (beaconFunctionMapping != IntPtr.Zero)
                ZeroAndFree(beaconFunctionMapping, 2048);
            if (coffFunctionMapping != IntPtr.Zero)
                ZeroAndFree(coffFunctionMapping, 2048);
            return 0;
        }

        public static string getBeaconOutputData()
        {
            void* functionaddress = null;
            int output_size = 0;

            uint local_hash = hash_djb(Encoding.Default.GetBytes("BeaconGetOutputData"));
            foreach (BEACON_FUNCTION tmp in BeaconInternalMapping)
            {
                if (local_hash == tmp.hash)
                {
                    Debug.WriteLine("\t\tInternalFunction: BeaconGetOutputData\n");
                    functionaddress = tmp.function;
                    break;
                }
            }
            if (functionaddress == null)
            {
                return "";
            }
            Debug.WriteLine("Getoutput Function 0x{0:X}", new IntPtr(functionaddress).ToInt64());
            FuncDelegate_GetOutput foo = (FuncDelegate_GetOutput)
                Marshal.GetDelegateForFunctionPointer(
                    new IntPtr(functionaddress),
                    typeof(FuncDelegate_GetOutput)
                );

            char* output = foo(&output_size);
            return new string((sbyte*)output);
        }
    }
}
