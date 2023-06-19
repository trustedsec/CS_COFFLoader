#!/usr/bin/sh

libs="-r:/opt/microsoft/powershell/7/System.Management.dll"

echo "Building the beacon functions"
beacon_dir=beacon_object/
x86_64-w64-mingw32-gcc -o bin/beacon_compatibility.o -I $beacon_dir/include/ -Os $beacon_dir/src/beacon_compatibility.c -lws2_32 -c
contents=`cat bin/beacon_compatibility.o | base64 -w 0`


mkdir tmp
mkdir bin
cp src/RunCOFF.cs tmp/RunCOFF.cs
sed -i -e "s#{{BEACON_DATA}}#${contents}#g" tmp/RunCOFF.cs

echo "Building the Executable"
if [ $# -eq 0 ]; 
	then
    echo 'Building Release'
	mcs -unsafe -platform:x64 $libs -out:bin/coffloader.exe -d:DEBUG_MAIN src/CoffParser.cs tmp/RunCoff.cs src/CoffStructs.cs
else
    echo 'Building DEBUG'
	mcs -unsafe -platform:x64 $libs -out:bin/coffloader.exe -d:DEBUG_MAIN -d:DEBUG  src/CoffParser.cs tmp/RunCoff.cs src/CoffStructs.cs
fi
rm -rf tmp
