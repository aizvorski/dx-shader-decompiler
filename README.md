dx-shader-decompiler
====================

A decompiler for DirectX 9 shaders

This currently supports decompiling pixel shader and vertex shader 3_0
Reference for the assembly language: 
http://msdn.microsoft.com/en-us/library/bb219840%28v=vs.85%29.aspx

Reference for the machine language: http://msdn.microsoft.com/en-us/library/windows/hardware/ff552891%28v=vs.85%29.aspx

Compile:
fxc.exe fx_examples/PP_ColorBloomH.fx /E PostProcessPS /T ps_3_0 /Fx test.txt
(note, this produces a text file containing the hex of the compiled shaders, but binary works as input also)

Decompile:
python dx-shader-decompiler.py test.txt
