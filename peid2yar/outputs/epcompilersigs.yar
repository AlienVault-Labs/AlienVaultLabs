rule _WATCOM_CCpp_32_RunTime_System_19881994_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1994"
	strings:
		$0 = {E9 57}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v60_
{
	meta:
		description = "Borland Delphi v6.0"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 45 ?? E8 FF A1 45 ?? 8B ?? E8 FF FF 8B}
		$1 = {55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF A1 72 40 ?? 33 D2 E8 FF FF A1 72 40 ?? 8B ?? 83 C0 14 E8 FF FF E8 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_
{
	meta:
		description = "Microsoft Visual C++"
	strings:
		$0 = {8B 44 24 08 83}
		$1 = {53 56 57 BB 8B 55 3B FB}
		$2 = {FF FF FF ?? ?? ?? ?? ?? ?? 30 ?? ?? ??}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Cygwin32_
{
	meta:
		description = "Cygwin32"
	strings:
		$0 = {6A FF 15}
	condition:
		$0 at entrypoint
}
rule _Borland_Cpp_for_Win32_1995_
{
	meta:
		description = "Borland C++ for Win32 1995"
	strings:
		$0 = {A1 C1 A3 83 75 80}
		$1 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_v42_
{
	meta:
		description = "Microsoft Visual C++ v4.2"
	strings:
		$0 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89}
		$1 = {53 B8 8B 56 57 85 DB 55}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MinGW_v32x__mainCRTStartup_
{
	meta:
		description = "MinGW v3.2.x (_mainCRTStartup)"
	strings:
		$0 = {E8 FF FF E8 FF}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v50_
{
	meta:
		description = "Microsoft Visual Basic v5.0"
	strings:
		$0 = {68}
	condition:
		$0 at entrypoint
}
rule _FASM_v13x_
{
	meta:
		description = "FASM v1.3x"
	strings:
		$0 = {E8 ?? 6E ?? ?? 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10}
	condition:
		$0 at entrypoint
}
rule _LCC_Win32_DLL_
{
	meta:
		description = "LCC Win32 DLL"
	strings:
		$0 = {8B 44 24 08 56 83 E8 74 48}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v60_KOL_
{
	meta:
		description = "Borland Delphi v6.0 KOL"
	strings:
		$0 = {55 8B EC 83 C4 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0}
	condition:
		$0 at entrypoint
}
rule _LCC_Win32_v1x_
{
	meta:
		description = "LCC Win32 v1.x"
	strings:
		$0 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 FF 75 10 FF 75 0C FF 75 08}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_SPx_
{
	meta:
		description = "Microsoft Visual C++ v6.0 SPx"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 6A 01 8B F0 FF}
		$1 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_DLL_
{
	meta:
		description = "Microsoft Visual C++ v6.0 DLL"
	strings:
		$0 = {83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? 10 E8 8B FF FF}
		$1 = {55 8B EC 83 EC 50 53 56 57 BE 8D 7D F4 A5 A5 66 A5}
		$2 = {55 8B EC 53 8B 5D 08 56 8B 75}
		$3 = {0D ??}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _Free_Pascal_v09910_
{
	meta:
		description = "Free Pascal v0.99.10"
	strings:
		$0 = {64 A1 55 89 E5 6A FF 68 68 9A 10 40}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_vxx_Component_
{
	meta:
		description = "Borland Delphi vx.x (Component)"
	strings:
		$0 = {55 8B EC 83 C4 B4 B8 E8 E8 8D}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v50v60_MFC_
{
	meta:
		description = "Microsoft Visual C++ v5.0/v6.0 (MFC)"
	strings:
		$0 = {55 8B EC ??}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_C_v70__Basic_NET_
{
	meta:
		description = "Microsoft Visual C# v7.0 / Basic .NET"
	strings:
		$0 = {53 55 56 8B 74 24 14 85 F6 57 B8}
	condition:
		$0 at entrypoint
}
rule _MinGW_GCC_DLL_v2xx_
{
	meta:
		description = "MinGW GCC DLL v2xx"
	strings:
		$0 = {55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 ?? ?? 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D ?? 30 ?? 10 85}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v60__v70_
{
	meta:
		description = "Borland Delphi v6.0 - v7.0"
	strings:
		$0 = {E8 6A E8 89 05 E8 89 05 C7 05 0A B8}
		$1 = {53 8B D8 33 C0 A3 ?? 6A ?? E8 ?? FF A3 ?? A1 ?? A3 ?? 33 C0 A3 ?? 33 C0 A3 ??}
		$2 = {55 8B EC B9 6A ?? 6A ??}
		$3 = {55 8B EC 83 C4 F0 B8 E8 FB FF A1 8B E8 FF FF 8B 0D A1 8B ?? 8B 15 E8 FF FF A1 8B E8 FF}
		$4 = {55 8B EC}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint
}
rule _Borland_Delphi_Component_
{
	meta:
		description = "Borland Delphi (Component)"
	strings:
		$0 = {55 89 E5 83 EC 04 83}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v20_
{
	meta:
		description = "Borland Delphi v2.0"
	strings:
		$0 = {50 6A E8 FF FF BA 52 89 05 89 42 04 E8 5A 58 E8 C3 55 8B EC 33}
	condition:
		$0 at entrypoint
}
rule _Borland_Pascal_v70_for_Windows_
{
	meta:
		description = "Borland Pascal v7.0 for Windows"
	strings:
		$0 = {A1 C1 A3 83 75 57 51 33 C0}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v40__v50_
{
	meta:
		description = "Borland Delphi v4.0 - v5.0"
	strings:
		$0 = {55 8B EC 83}
		$1 = {50 6A ?? E8 FF FF BA 52 89 05 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 5A 58 E8}
		$2 = {BA 83 7D 0C 01 75 50 52 C6 05 8B 4D 08 89 0D 89 4A}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Borland_Delphi_v30_
{
	meta:
		description = "Borland Delphi v3.0"
	strings:
		$0 = {55 8B EC 83}
		$1 = {50 6A E8 FF FF BA 52 89 05 89 42 04 C7 42 08 C7 42 0C E8 5A 58 E8}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MinGW_v32x_WinMain_
{
	meta:
		description = "MinGW v3.2.x (WinMain)"
	strings:
		$0 = {55 89 E5 83 EC 08 6A ?? 6A ?? 6A ?? 6A ?? E8 0D ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 90 90 90 90 90 90 FF 25 38 20 ?? 10 90 90 ?? ?? ?? ?? ?? ?? ?? ?? FF FF FF FF ?? ?? ?? ?? FF FF FF}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_Setup_Module_
{
	meta:
		description = "Borland Delphi Setup Module"
	strings:
		$0 = {55 8B EC 83 C4}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v60_DLL_
{
	meta:
		description = "Microsoft Visual Basic v6.0 DLL"
	strings:
		$0 = {55 89 E5 E8 C9 C3 45 58}
	condition:
		$0 at entrypoint
}
rule _WATCOM_CCpp_
{
	meta:
		description = "WATCOM C/C++"
	strings:
		$0 = {53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_Dll_WinMain_
{
	meta:
		description = "MinGW v3.2.x (Dll_WinMain)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 ?? ?? ?? FF 15 E4 40 40 ?? E8 68 ?? ?? ?? 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 ?? ?? ?? FF 15 E4 40 40 ?? E8 48 ?? ?? ?? 89 EC 31 C0 5D C3 89}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v50_KOL_
{
	meta:
		description = "Borland Delphi v5.0 KOL"
	strings:
		$0 = {53 8B D8 33 C0 A3 6A ?? E8 FF A3 A1 A3 33 C0 A3 33 C0 A3}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_DLL_
{
	meta:
		description = "Microsoft Visual C++ DLL"
	strings:
		$0 = {53 56 57 BB 01 8B 24}
		$1 = {53 B8 01 ?? ?? ?? 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D 75 09 33}
		$2 = {55 8B EC 56 57 BF 01 ?? ?? ?? 8B 75}
		$3 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _Microsoft_Visual_C_v20_
{
	meta:
		description = "Microsoft Visual C v2.0"
	strings:
		$0 = {55 8B EC 56 57 BF 8B 3B F7}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v42_DLL_
{
	meta:
		description = "Microsoft Visual C++ v4.2 DLL"
	strings:
		$0 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_Dll_main_
{
	meta:
		description = "MinGW v3.2.x (Dll_main)"
	strings:
		$0 = {55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 ?? ?? 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D ?? 30 ?? 10 85}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v70_
{
	meta:
		description = "Microsoft Visual C++ v7.0"
	strings:
		$0 = {6A 68}
		$1 = {55 8D 6C 81 EC 8B 45 83 F8 01 56 0F 84 85 C0 0F}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _WATCOM_CCpp_32_RunTime_System_19881995_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1995"
	strings:
		$0 = {FB 83 89 E3 89 89 66 66 BB 29 C0 B4 30 CD}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v50_KOLMCK_
{
	meta:
		description = "Borland Delphi v5.0 KOL/MCK"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF E8 FF FF E8 FF FF 8B}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_vxx_
{
	meta:
		description = "Microsoft Visual C++ vx.x"
	strings:
		$0 = {53 55 56 8B 85 F6 57 B8 75 8B 85 C9 75 33 C0 5F 5E 5D 5B}
		$1 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
		$2 = {55 8B EC 83 EC 44 56 FF 15 8B F0 8A 3C}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Stranik_13_ModulaCPascal_
{
	meta:
		description = "Stranik 1.3 Modula/C/Pascal"
	strings:
		$0 = {E9 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D}
	condition:
		$0 at entrypoint
}
rule _Borland_Cpp_for_Win32_1994_
{
	meta:
		description = "Borland C++ for Win32 1994"
	strings:
		$0 = {A1 C1 A3 57 51 33 C0 BF B9 3B CF}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_DLL_
{
	meta:
		description = "Borland Delphi DLL"
	strings:
		$0 = {55 8B EC 83}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_Debug_Version_
{
	meta:
		description = "Microsoft Visual C++ v6.0 (Debug Version)"
	strings:
		$0 = {6A 68 E8 BF 8B C7 E8 89 65 8B F4 89 3E 56 FF 15 8B 4E 89 0D 8B 46}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v4x_
{
	meta:
		description = "Microsoft Visual C++ v4.x"
	strings:
		$0 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v50_
{
	meta:
		description = "Microsoft Visual C++ v5.0"
	strings:
		$0 = {24 ?? 8B 24}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v50_DLL_
{
	meta:
		description = "Microsoft Visual C++ v5.0 DLL"
	strings:
		$0 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_Dll_mainCRTStartup_
{
	meta:
		description = "MinGW v3.2.x (Dll_mainCRTStartup)"
	strings:
		$0 = {55 89 E5 83 EC 08 6A ?? 6A ?? 6A ?? 6A ?? E8 0D ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 90 90 90 90 90 90 FF 25 38 20 40 ?? 90 90 ?? ?? ?? ?? ?? ?? ?? ?? FF FF FF FF ?? ?? ?? ?? FF FF FF}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v70_DLL_
{
	meta:
		description = "Microsoft Visual C++ v7.0 DLL"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10}
		$1 = {FF 25 ??}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Borland_Cpp_
{
	meta:
		description = "Borland C++"
	strings:
		$0 = {A1 C1 E0 02}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_
{
	meta:
		description = "Microsoft Visual C++ v6.0"
	strings:
		$0 = {51}
		$1 = {55 8D 6C 81 EC 8B 45 83 F8 01 56 0F 84 85 C0 0F}
		$2 = {55 8B EC 51}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Borland_Cpp_for_Win32_1999_
{
	meta:
		description = "Borland C++ for Win32 1999"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B}
		$1 = {A1 C1 E0 02 A3 57 51 33 C0 BF B9 3B CF 76 05 2B CF FC F3 AA 59}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MinGW_GCC_v2x_
{
	meta:
		description = "MinGW GCC v2.x"
	strings:
		$0 = {55 89 E5 FF}
		$1 = {55 89 E5 E8 C9 C3 45 58}
		$2 = {55 89}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _MinGW_v32x_main_
{
	meta:
		description = "MinGW v3.2.x (main)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 ?? ?? ?? FF 15 FC 40 40 ?? E8 68 ?? ?? ?? 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 ?? ?? ?? FF 15 FC 40 40 ?? E8 48 ?? ?? ?? 89 EC 31 C0 5D C3 89}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_
{
	meta:
		description = "Borland Delphi"
	strings:
		$0 = {C3 E9 FF 8D}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v50__v60_
{
	meta:
		description = "Microsoft Visual Basic v5.0 / v6.0"
	strings:
		$0 = {5A 68 68 52 E9}
	condition:
		$0 at entrypoint
}
rule _Borland_Cpp_DLL_
{
	meta:
		description = "Borland C++ DLL"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90}
		$1 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
		$2 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
		$3 = {C3 E9 FF 8D}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
