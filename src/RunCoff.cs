using System;
using System.IO;
using System.Text;
using System.Diagnostics;

// TODO: run prettifier to keep code style consistant

namespace COFFLoader
{
    public class COFFLoader
    {
        private static string beaconOutputData;
        private static int beaconOutputData_sz = 0;

        public static string RunCoff(string functionName, string coffData, string argDataHex)
        {
            string Result = "";

            try
            {
                Debug.WriteLine("Calling COFFLoader.RunCoff()");

                byte[] functionname = Encoding.ASCII.GetBytes(functionName);
                byte[] coff_data = Decode(coffData);
                string tmp_arg_data = unhexlify(Encoding.Default.GetString(Decode(argDataHex)));
                byte[] arg_data = Encoding.Default.GetBytes(tmp_arg_data);
                byte[] beacon_data = Decode("{{BEACON_DATA}}");

                // Call coffloader once with beacon_compatibility.o before loading BOF to initialize Beacon* functions
                if (
                    CoffParser.parseCOFF(new byte[] { }, beacon_data, beacon_data.Length, null, 0)
                    == 1
                )
                {
                    CoffParser.CleanUpMemoryAllocations();
                    return "parseCOFF Beacon compat failed: 1";
                }

                Debug.WriteLine(
                    "************************ BEACON PROCESSING DONE ***********************"
                );

                if (
                    CoffParser.parseCOFF(
                        functionname,
                        coff_data,
                        coff_data.Length,
                        arg_data,
                        arg_data.Length
                    ) == 1
                )
                {
                    Result = "ERROR";
                    beaconOutputData = "parseCOFF failed: 1";
                    beaconOutputData_sz = beaconOutputData.Length;
                }
                else
                {
                    beaconOutputData = CoffParser.getBeaconOutputData();
                    beaconOutputData_sz = beaconOutputData.Length;
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(string.Format("Exception: '{0}'", e));
            }

            return Result;
        }

        public static int BeaconGetOutputData_Size()
        {
            return beaconOutputData_sz;
        }

        public static string BeaconGetOutputData()
        {
            return beaconOutputData;
        }

        public static string unhexlify(string hex)
        {
            string ret = null;
            for (int i = 0; i < hex.Length - 1; i += 2)
            {
                int value = Convert.ToInt32(hex.Substring(i, 2), 16);
                ret += char.ConvertFromUtf32(value);
            }
            return ret;
        }

        public static byte[] Decode(string encodedBuffer)
        {
            return Convert.FromBase64String(encodedBuffer);
        }

#if DEBUG_MAIN
        static void Main(string[] args)
        {
            TextWriterTraceListener myWriter = new TextWriterTraceListener(Console.Out);
            Debug.Listeners.Add(myWriter);
            // Display the number of command line arguments.
            Debug.WriteLine("CS_COFFLoader main function Debug");
            if (args.Length != 3)
            {
                Console.WriteLine(
                    "USAGE: coffloader.exe <functionName> <bof filename> <arguments>"
                );
                Console.WriteLine("\tExample: coffloader.exe go whoami.o 00");
                return;
            }
            string functionname = args[0];
            byte[] rawcoff = File.ReadAllBytes(args[1]);
            string coff = Convert.ToBase64String(rawcoff);
            string arguments = Convert.ToBase64String(Encoding.Default.GetBytes(args[2]));
            RunCoff(functionname, coff, arguments);

            string output = BeaconGetOutputData();
            int output_sz = BeaconGetOutputData_Size();
            Console.WriteLine("Output size of {0}: See below\n", output_sz);
            Console.WriteLine(output);
        }
#endif
    }
}
