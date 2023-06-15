#!/usr/bin/sh

libs="-r:/opt/microsoft/powershell/7/System.Management.dll"

contents=`cat beacon_object/beacon_compatibility.o | base64 -w 0`
mkdir tmp
mkdir bin
cp src/RunCOFF.cs tmp/RunCOFF.cs
sed -i -e "s#{{BEACON_DATA}}#${contents}#g" tmp/RunCOFF.cs

if [ $# -eq 0 ]; 
	then
    echo 'Building Release'
	mcs -unsafe -platform:x64 $libs -out:bin/coffloader.exe -d:DEBUG_MAIN src/CoffParser.cs tmp/RunCoff.cs src/CoffStructs.cs
else
    echo 'Building DEBUG'
	mcs -unsafe -platform:x64 $libs -out:bin/coffloader.exe -d:DEBUG_MAIN -d:DEBUG  src/CoffParser.cs tmp/RunCoff.cs src/CoffStructs.cs
fi
rm -rf tmp
