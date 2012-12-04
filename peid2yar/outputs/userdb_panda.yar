/*
	http://research.pandasecurity.com/blogs/images/userdb.txt Oct 10 2012
*/

rule _Nullsoft_Install_System_v20_
{
	meta:
		description = "Nullsoft Install System v2.0"
	strings:
		$0 = {83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00}
	condition:
		$0
}
rule _Vx_Keypress1212_
{
	meta:
		description = "Vx: Keypress.1212"
	strings:
		$0 = {E8 ?? ?? E8 ?? ?? E8 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EA ?? ?? ?? ?? 1E 33 DB 8E DB BB}
	condition:
		$0 at entrypoint
}
rule _E2C_by_DoP_
{
	meta:
		description = "E2C by DoP"
	strings:
		$0 = {BE ?? ?? BF ?? ?? B9 ?? ?? FC 57 F3 A5 C3}
	condition:
		$0 at entrypoint
}
rule _MSLRH_v032a__emadicius_h_
{
	meta:
		description = "[MSLRH] v0.32a -> emadicius (h)"
	strings:
		$0 = {E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8}
	condition:
		$0
}
rule _LaunchAnywhere_v4001_
{
	meta:
		description = "LaunchAnywhere v4.0.0.1"
	strings:
		$0 = {55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3}
	condition:
		$0 at entrypoint
}
rule _PECompact_v09781_
{
	meta:
		description = "PECompact v0.978.1"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87}
	condition:
		$0 at entrypoint
}
rule _RLPack_Full_Edition_117_iBox_LZMA__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 iBox [LZMA] -> Ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 67 30 00 00 8D 9D 66 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A}
	condition:
		$0 at entrypoint
}
rule _Petite_v14_
{
	meta:
		description = "Petite v1.4"
	strings:
		$0 = {B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00}
	condition:
		$0 at entrypoint
}
rule _VcAsm_Protector__VcAsm_
{
	meta:
		description = "VcAsm Protector -> VcAsm"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3}
	condition:
		$0 at entrypoint
}
rule _PESpin_v01__Cyberbob_h_
{
	meta:
		description = "PESpin v0.1 -> Cyberbob (h)"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF}
	condition:
		$0 at entrypoint
}
rule _PECompact_v134__v140b1_
{
	meta:
		description = "PECompact v1.34 - v1.40b1"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 00 80 ?? 40 90 90 01 85 9E 80 ?? 40 BB F8 10}
	condition:
		$0 at entrypoint
}
rule _PECompact_v14xp_
{
	meta:
		description = "PECompact v1.4x+"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81}
	condition:
		$0 at entrypoint
}
rule _VcasmProtector_10e__vcasm_
{
	meta:
		description = "Vcasm-Protector 1.0e -> vcasm"
	strings:
		$0 = {EB 0A 5B 56 50 72 6F 74 65 63 74 5D}
	condition:
		$0 at entrypoint
}
rule _UPX_290_LZMA_Delphi_stub__Markus_Oberhumer_Laszlo_Molnar__John_Reiser_
{
	meta:
		description = "UPX 2.90 [LZMA] (Delphi stub) -> Markus Oberhumer, Laszlo Molnar & John Reiser"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04}
	condition:
		$0 at entrypoint
}
rule _SLR_OPTLINK_
{
	meta:
		description = "SLR (OPTLINK)"
	strings:
		$0 = {BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB B4 30 CD 21}
	condition:
		$0 at entrypoint
}
rule _eXPressor_v14__CGSoftLabs_h_
{
	meta:
		description = "eXPressor v1.4 -> CGSoftLabs (h)"
	strings:
		$0 = {55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8}
	condition:
		$0 at entrypoint
}
rule _WinZip_32bit_SFX_v6x_module_
{
	meta:
		description = "WinZip 32-bit SFX v6.x module"
	strings:
		$0 = {FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 ?? ?? ?? ?? FF 15}
	condition:
		$0 at entrypoint
}
rule _ROD_High_TECH__Ayman_
{
	meta:
		description = "ROD High TECH -> Ayman"
	strings:
		$0 = {60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00}
	condition:
		$0 at entrypoint
}
rule _PECompact_v155_
{
	meta:
		description = "PECompact v1.55"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12}
	condition:
		$0 at entrypoint
}
rule _PECompact_v100_
{
	meta:
		description = "PECompact v1.00"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v260_
{
	meta:
		description = "Armadillo v2.60"
	strings:
		$0 = {55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84}
	condition:
		$0 at entrypoint
}
rule _Vx_VirusConstructorbased_
{
	meta:
		description = "Vx: VirusConstructor.based"
	strings:
		$0 = {BB ?? ?? B9 ?? ?? 2E ?? ?? ?? ?? 43 43 ?? ?? 8B EC CC 8B ?? ?? 81 ?? ?? ?? 06 1E B8 ?? ?? CD 21 3D ?? ?? ?? ?? 8C D8 48 8E D8}
		$1 = {E8 ?? ?? 5D 81 ?? ?? ?? 06 1E E8 ?? ?? E8 ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B4 4A BB FF FF CD 21 83 ?? ?? B4 4A CD 21}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _EXECryptor_V21X__softcompletecom_
{
	meta:
		description = "EXECryptor V2.1X -> softcomplete.com"
	strings:
		$0 = {83 C6 14 8B 55 FC E9 ?? FF FF FF}
	condition:
		$0
}
rule _WWPack32_v100_v111_v112_v120_
{
	meta:
		description = "WWPack32 v1.00, v1.11, v1.12, v1.20"
	strings:
		$0 = {53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32}
	condition:
		$0 at entrypoint
}
rule _A3E_TXT2COM_
{
	meta:
		description = "A3E (TXT2COM)"
	strings:
		$0 = {1E 33 C0 50 BE ?? ?? 81 C6 ?? ?? B8 ?? ?? 8E C0 BF ?? ?? B9 ?? ?? F3 A5 CB}
	condition:
		$0 at entrypoint
}
rule _PUNiSHER_V15_FEUERRADER_
{
	meta:
		description = "PUNiSHER V1.5-> FEUERRADER"
	strings:
		$0 = {3F 00 00 80 66 20 ?? 00 7E 20 ?? 00 92 20 ?? 00 A4 20 ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32}
	condition:
		$0
}
rule _PECompact_v140__v145_
{
	meta:
		description = "PECompact v1.40 - v1.45"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v180_
{
	meta:
		description = "Armadillo v1.80"
	strings:
		$0 = {55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _BJFnt_v12_RC_
{
	meta:
		description = ".BJFnt v1.2 RC"
	strings:
		$0 = {EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB}
	condition:
		$0 at entrypoint
}
rule _Upack_V036__Dwing_
{
	meta:
		description = "Upack V0.36 -> Dwing"
	strings:
		$0 = {BE ?? ?? ?? ?? FF 36 E9 C3 00 00 00}
	condition:
		$0 at entrypoint
}
rule _MASM32_
{
	meta:
		description = "MASM32"
	strings:
		$0 = {6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20}
	condition:
		$0 at entrypoint
}
rule _Upack_V01XV02X__Dwing_
{
	meta:
		description = "Upack V0.1X-V0.2X -> Dwing"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 95}
	condition:
		$0 at entrypoint
}
rule _ChinaProtect__dummy____SignByfly_
{
	meta:
		description = "ChinaProtect -> dummy   * Sign.By.fly"
	strings:
		$0 = {C3 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 56 8B ?? ?? ?? 6A 40 68 00 10 00 00 8D ?? ?? 50 6A 00 E8 ?? ?? ?? ?? 89 30 83 C0 04 5E C3 8B 44 ?? ?? 56 8D ?? ?? 68 00 40 00 00 FF 36 56 E8 ?? ?? ?? ?? 68 00 80 00 00 6A 00 56 E8 ?? ?? ?? ?? 5E C3}
	condition:
		$0
}
rule _eXPressor_V1451__CGSoftLabs_
{
	meta:
		description = "eXPressor V1.4.5.1 -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D}
		$1 = {55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Necropolis1963_
{
	meta:
		description = "Vx: Necropolis.1963"
	strings:
		$0 = {B4 30 CD 21 3C 03 ?? ?? B8 00 12 CD 2F 3C FF B8 ?? ?? ?? ?? B4 4A BB 40 01 CD 21 ?? ?? FA 0E 17 BC ?? ?? E8 ?? ?? FB A1 ?? ?? 0B C0}
	condition:
		$0 at entrypoint
}
rule _CrypWrap_vxx_
{
	meta:
		description = "CrypWrap vx.x"
	strings:
		$0 = {E8 B8 ?? ?? ?? E8 90 02 ?? ?? 83 F8 ?? 75 07 6A ?? E8 ?? ?? ?? ?? FF 15 49 8F 40 ?? A9 ?? ?? ?? 80 74 0E}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_PESHiELD_025__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PESHiELD 0.25] --> Anorganix"
	strings:
		$0 = {60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9}
		$1 = {60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cpp_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)"
	strings:
		$0 = {1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13}
		$1 = {1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13}
		$2 = {C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _MESS_v120_
{
	meta:
		description = "MESS v1.20"
	strings:
		$0 = {FA B9 ?? ?? F3 ?? ?? E3 ?? EB ?? EB ?? B6}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_REALBasic__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [REALBasic] --> Anorganix"
	strings:
		$0 = {55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01}
		$1 = {55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Hymn1865_
{
	meta:
		description = "Vx: Hymn.1865"
	strings:
		$0 = {E8 ?? ?? 5E 83 EE 4C FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 ?? ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 50 06 56 1E 0E 1F B8 00 C5 CD 21}
	condition:
		$0 at entrypoint
}
rule _Alex_Protector_v04_beta_1_by_Alex_
{
	meta:
		description = "Alex Protector v0.4 beta 1 by Alex"
	strings:
		$0 = {60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68}
		$1 = {60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68}
	condition:
		$0 or $1
}
rule _Shrinker_v32_
{
	meta:
		description = "Shrinker v3.2"
	strings:
		$0 = {83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 00 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF}
	condition:
		$0 at entrypoint
}
rule _eXPressor_V145x__CGSoftLabs_
{
	meta:
		description = "eXPressor V1.4.5.x -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 83 EC ?? 53 56 57 83 65 ?? 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 ?? ?? ?? 00 A1 ?? ?? ?? 00 B9 ?? ?? ?? 00 2B 48 18 89 0D ?? ?? ?? 00 83 3D}
	condition:
		$0 at entrypoint
}
rule _dUP_v2x_Patcher__wwwdiablo2oo2cjbnet_
{
	meta:
		description = "dUP v2.x Patcher --> www.diablo2oo2.cjb.net"
	strings:
		$0 = {54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F}
	condition:
		$0
}
rule _EXE32Pack_v136_
{
	meta:
		description = "EXE32Pack v1.36"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v19x_
{
	meta:
		description = "Armadillo v1.9x"
	strings:
		$0 = {55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15}
	condition:
		$0 at entrypoint
}
rule _Alex_Protector_10_beta_2_by_Alex_
{
	meta:
		description = "Alex Protector 1.0 beta 2 by Alex"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25}
		$1 = {60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25}
	condition:
		$0 or $1
}
rule _LCC_Win32_v1x_
{
	meta:
		description = "LCC Win32 v1.x"
	strings:
		$0 = {64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50}
	condition:
		$0 at entrypoint
}
rule _PROPACK_v208_emphasis_on_packed_size_locked_
{
	meta:
		description = "PRO-PACK v2.08, emphasis on packed size, locked"
	strings:
		$0 = {83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B}
	condition:
		$0 at entrypoint
}
rule _PCPEC_alpha__preview_
{
	meta:
		description = "PCPEC alpha - preview"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 00}
	condition:
		$0 at entrypoint
}
rule _Packanoid__Arkanoid_
{
	meta:
		description = "Packanoid -> Arkanoid"
	strings:
		$0 = {BF 00 10 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8}
	condition:
		$0 at entrypoint
}
rule _ASPack_v211c_
{
	meta:
		description = "ASPack v2.11c"
	strings:
		$0 = {60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00}
	condition:
		$0 at entrypoint
}
rule _Symantec_C_v400_p_Libraries_
{
	meta:
		description = "Symantec C v4.00 + Libraries"
	strings:
		$0 = {FA B8 ?? ?? DB E3 8E D8 8C 06 ?? ?? 8B D8 2B 1E ?? ?? 89 1E ?? ?? 26}
	condition:
		$0 at entrypoint
}
rule _DIET_v144_v145f_
{
	meta:
		description = "DIET v1.44, v1.45f"
	strings:
		$0 = {F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA ?? ?? 03 D0 52}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v210b2_
{
	meta:
		description = "Armadillo v2.10b2"
	strings:
		$0 = {55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PENinja_modified_
{
	meta:
		description = "PENinja modified"
	strings:
		$0 = {5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD}
	condition:
		$0 at entrypoint
}
rule _CodeCrypt_v014b_
{
	meta:
		description = "CodeCrypt v0.14b"
	strings:
		$0 = {E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F}
	condition:
		$0 at entrypoint
}
rule _ENIGMA_Protector_V10V12_Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.0-V1.2-> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ?? ?? 81}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_70_DLL_
{
	meta:
		description = "Microsoft Visual C++ 7.0 DLL"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01}
	condition:
		$0
}
rule _PseudoSigner_02_PESHiELD_025__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PESHiELD 0.25] --> Anorganix"
	strings:
		$0 = {60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC}
		$1 = {60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _yP_v10b_by_Ashkbiz_Danehkar_
{
	meta:
		description = "yP v1.0b by Ashkbiz Danehkar"
	strings:
		$0 = {55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 C2 E8 03 00 00 00 EB 01 ?? AC ?? ?? ?? ?? ?? ?? ?? EB 01 E8}
	condition:
		$0
}
rule _UPX_v0761_dos_exe_
{
	meta:
		description = "UPX v0.76.1 [dos exe]"
	strings:
		$0 = {B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8C C8 05 ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC}
	condition:
		$0 at entrypoint
}
rule _Private_exe_Protector_V20__SetiSoft_Team_
{
	meta:
		description = "Private exe Protector V2.0 -> SetiSoft Team"
	strings:
		$0 = {00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00}
	condition:
		$0
}
rule _RLP_V073beta__ap0x_
{
	meta:
		description = "RLP V0.7.3.beta -> ap0x"
	strings:
		$0 = {2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0}
	condition:
		$0
}
rule _WWPACK_v305c4_Modified_
{
	meta:
		description = "WWPACK v3.05c4 (Modified)"
	strings:
		$0 = {B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _nPack_v11xxx__NEOx_
{
	meta:
		description = "nPack v1.1.xxx -> NEOx"
	strings:
		$0 = {83 3D ?? ?? ?? 00 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 08 ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 ?? 02 00 00 E8 ?? 06 00 00 E8 ?? 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? 00 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00}
	condition:
		$0 at entrypoint
}
rule _PESpin_v13beta__Cyberbob_h_
{
	meta:
		description = "PESpin v1.3beta -> Cyberbob (h)"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF}
	condition:
		$0 at entrypoint
}
rule _InstallAnywhere_61__Zero_G_Software_Inc_
{
	meta:
		description = "InstallAnywhere 6.1 -> Zero G Software Inc"
	strings:
		$0 = {60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0}
	condition:
		$0 at entrypoint
}
rule _Shrink_v10_
{
	meta:
		description = "Shrink v1.0"
	strings:
		$0 = {50 9C FC BE ?? ?? BF ?? ?? 57 B9 ?? ?? F3 A4 8B ?? ?? ?? BE ?? ?? BF ?? ?? F3 A4 C3}
	condition:
		$0 at entrypoint
}
rule _PE_Diminisher_v01__Teraphy_
{
	meta:
		description = "PE Diminisher v0.1 -> Teraphy"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 50 E8 02 01 00 00 8B FD 8D 9D 9A 33 40 00 8B 1B 8D 87}
	condition:
		$0 at entrypoint
}
rule _Pack_Master_v10_
{
	meta:
		description = "Pack Master v1.0"
	strings:
		$0 = {60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46}
		$1 = {60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_02_Borland_Delphi_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Borland Delphi DLL] --> Anorganix"
	strings:
		$0 = {55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00}
		$1 = {55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cpp__ASM_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++ / ASM)"
	strings:
		$0 = {EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4}
	condition:
		$0 at entrypoint
}
rule _Sentinel_SuperPro_Automatic_Protection_v640__Safenet_
{
	meta:
		description = "Sentinel SuperPro (Automatic Protection) v6.4.0 -> Safenet"
	strings:
		$0 = {68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15}
	condition:
		$0 at entrypoint
}
rule _ENIGMA_Protector_V11V12_Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.1-V1.2-> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ED 06 81}
	condition:
		$0 at entrypoint
}
rule _Macromedia_Windows_Flash_ProjectorPlayer_v60_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v6.0"
	strings:
		$0 = {83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C}
	condition:
		$0 at entrypoint
}
rule _DevCpp_4992__Bloodshed_Software_
{
	meta:
		description = "Dev-C++ 4.9.9.2 -> Bloodshed Software"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D}
	condition:
		$0 at entrypoint
}
rule _RLPack_v073beta__ap0x_h_
{
	meta:
		description = "RLPack v0.7.3beta -> ap0x (h)"
	strings:
		$0 = {60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8 42 31 40 00 BB 41 30 40 00 2B C3 03 C5 33 D2 8A 10 40 B9 ?? ?? 00 00 8B F9 30 10 8A 10 40 49 75 F8 64 EF 86 3D 30 00 00 0F B9 FF 4B 89 52 5C 4C BD 77 C2 0C CE 88 4E 2D E8 00 00 00 5D 0D DB 5E 56}
	condition:
		$0
}
rule _PcShare__v40___
{
	meta:
		description = "PcShare 文件捆绑器 v4.0 -> 无可非议"
	strings:
		$0 = {55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1}
	condition:
		$0 at entrypoint
}
rule _EmbedPE_v124__cyclotron_
{
	meta:
		description = "EmbedPE v1.24 -> cyclotron"
	strings:
		$0 = {83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00}
	condition:
		$0 at entrypoint
}
rule _Soft_Defender_v10__v11_
{
	meta:
		description = "Soft Defender v1.0 - v1.1"
	strings:
		$0 = {74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 ?? ?? ?? ?? 58 05 BA 01 ?? ?? 03 C8 74 BE 75 BC E8}
	condition:
		$0 at entrypoint
}
rule _Upack_v031_beta__Dwing_
{
	meta:
		description = "Upack v0.31 beta -> Dwing"
	strings:
		$0 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31}
	condition:
		$0 at entrypoint
}
rule _ENIGMA_Protector_V11_CracKed_By_shoooo__fly__Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.1 CracKed By: shoooo & fly -> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 C5 FA 81}
	condition:
		$0 at entrypoint
}
rule _tElock_v096_
{
	meta:
		description = "tElock v0.96"
	strings:
		$0 = {E9 59 E4 FF FF 00}
	condition:
		$0 at entrypoint
}
rule _ASPack_v2001_
{
	meta:
		description = "ASPack v2.001"
	strings:
		$0 = {60 E8 72 05 00 00 EB 4C}
	condition:
		$0 at entrypoint
}
rule _LTC_v13_
{
	meta:
		description = "LTC v1.3"
	strings:
		$0 = {54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06}
	condition:
		$0 at entrypoint
}
rule _PEiDBundle_v101__BoB__BobSoft_
{
	meta:
		description = "PEiD-Bundle v1.01 --> BoB / BobSoft"
	strings:
		$0 = {60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A}
	condition:
		$0 at entrypoint
}
rule _HACKSTOP_v110p1_
{
	meta:
		description = "HACKSTOP v1.10p1"
	strings:
		$0 = {B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 ?? ?? 58 EB}
		$1 = {B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 ?? ?? 58 EB}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v140b2__v140b4_
{
	meta:
		description = "PECompact v1.40b2 - v1.40b4"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11}
	condition:
		$0 at entrypoint
}
rule _Vx_Kuku448_
{
	meta:
		description = "Vx: Kuku.448"
	strings:
		$0 = {AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB}
	condition:
		$0 at entrypoint
}
rule _NsPacK_V31__LiuXingPing_
{
	meta:
		description = "NsPacK V3.1 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74}
	condition:
		$0 at entrypoint
}
rule _GHF_Protector_pack_only__GPcH_
{
	meta:
		description = "GHF Protector (pack only) -> GPcH"
	strings:
		$0 = {60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 00 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41}
	condition:
		$0
}
rule _Vx_Necropolis_
{
	meta:
		description = "Vx: Necropolis"
	strings:
		$0 = {50 FC AD 33 C2 AB 8B D0 E2 F8}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_DEF_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [DEF 1.0] --> Anorganix"
	strings:
		$0 = {BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9}
		$1 = {BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v110_Eng__bartxt__WinRARSFX_
{
	meta:
		description = "FSG v1.10 (Eng) -> bart/xt -> WinRAR-SFX"
	strings:
		$0 = {80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0}
		$1 = {EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _LCCWin32_
{
	meta:
		description = "LCC-Win32"
	strings:
		$0 = {64 A1 00 00 00 00 55 89 E5 6A FF 68 10 30 40 00 68 9A 10 40}
	condition:
		$0 at entrypoint
}
rule _PE_Lock_NT_v201_
{
	meta:
		description = "PE Lock NT v2.01"
	strings:
		$0 = {EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD}
	condition:
		$0 at entrypoint
}
rule _Dropper_Creator_V01__Conflict_
{
	meta:
		description = "Dropper Creator V0.1 -> Conflict"
	strings:
		$0 = {60 E8 00 00 00 00 5D 8D 05 ?? ?? ?? ?? 29 C5 8D 85 ?? ?? ?? ?? 31 C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09}
	condition:
		$0
}
rule _PowerBASICCC_30x_
{
	meta:
		description = "PowerBASIC/CC 3.0x"
	strings:
		$0 = {55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85}
	condition:
		$0 at entrypoint
}
rule _MS_RunTime_Library_1992_11_
{
	meta:
		description = "MS Run-Time Library 1992 (11)"
	strings:
		$0 = {B4 51 CD 21 8E DB B8 ?? ?? 83 E8 ?? 8E C0 33 F6 33 FF B9 ?? ?? FC F3 A5}
	condition:
		$0 at entrypoint
}
rule _FreePascal_200_Win32__Brczi_Gbor_Pierre_Muller__Peter_Vreman_
{
	meta:
		description = "FreePascal 2.0.0 Win32 -> (B閞czi G醔or, Pierre Muller & Peter Vreman)"
	strings:
		$0 = {C6 05 ?? ?? ?? ?? 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00}
		$1 = {C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _SCAN_AV_
{
	meta:
		description = "SCAN /AV"
	strings:
		$0 = {1E 0E 1F B8 ?? ?? 8E C0 26 8A 1E ?? ?? 80 ?? ?? 72}
	condition:
		$0 at entrypoint
}
rule _Zortech_C_v30_
{
	meta:
		description = "Zortech C v3.0"
	strings:
		$0 = {FA FC B8 ?? ?? ?? 8C C8 8E D8}
	condition:
		$0 at entrypoint
}
rule _PECompact_v156_
{
	meta:
		description = "PECompact v1.56"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12}
	condition:
		$0 at entrypoint
}
rule _CodeCrypt_v016b__v0163b_
{
	meta:
		description = "CodeCrypt v0.16b - v0.163b"
	strings:
		$0 = {E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v305c4_Unextractable_p_Password_checking_
{
	meta:
		description = "WWPACK v3.05c4 (Unextractable + Password checking)"
	strings:
		$0 = {03 05 80 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _Petite_12__c1998_Ian_Luck_h_
{
	meta:
		description = "Petite 1.2 -> (c)1998 Ian Luck (h)"
	strings:
		$0 = {66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0D 00 0F 00 11 00 13 00 17 00 1B 00 1F 00 23 00 2B 00 33 00 3B 00 43 00 53 00 63 00 73 00 83 00 A3 00 C3 00 E3 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 02 02 02}
	condition:
		$0 at entrypoint
}
rule _Duals_eXe_10_
{
	meta:
		description = "Dual's eXe 1.0"
	strings:
		$0 = {55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 08 03 00 00 89 28 33 FF 8D 85 7D 02 00 00 8D 8D 08 03 00 00 2B C8 8B 9D 58 03 00 00 E8 1C 02 00 00 8D 9D 61 02 00 00 8D B5 7C 02 00 00 46 80 3E 00 74 24 56 FF 95 0A 04 00 00 46 80 3E 00}
		$1 = {55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 08 03 00 00 89 28 33 FF 8D 85 7D 02 00 00 8D 8D 08 03 00 00 2B C8 8B 9D 58 03 00 00 E8 1C 02 00 00 8D 9D 61 02 00 00 8D B5 7C 02 00 00 46 80 3E 00 74 24 56 FF 95 0A 04 00 00 46 80 3E 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Symantec_C_v210_v400_or_Zortech_C_v30r1_
{
	meta:
		description = "Symantec C v2.10, v4.00 or Zortech C v3.0r1"
	strings:
		$0 = {FA FC B8 ?? ?? 8E D8}
	condition:
		$0 at entrypoint
}
rule _yodas_Protector_v10b__Ashkbiz_Danehkar_h_
{
	meta:
		description = "yoda's Protector v1.0b -> Ashkbiz Danehkar (h)"
	strings:
		$0 = {55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01}
	condition:
		$0 at entrypoint
}
rule _SDProtector_1x__Randy_Li_
{
	meta:
		description = "SDProtector 1.x -> Randy Li"
	strings:
		$0 = {55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41}
	condition:
		$0 at entrypoint
}
rule _Program_Protector_XP_v10_
{
	meta:
		description = "Program Protector XP v1.0"
	strings:
		$0 = {E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50}
	condition:
		$0 at entrypoint
}
rule _32Lite_v003a_
{
	meta:
		description = "32Lite v0.03a"
	strings:
		$0 = {60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v190c_
{
	meta:
		description = "Armadillo v1.90c"
	strings:
		$0 = {55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__MASM32__TASM32__Microsoft_Visual_Basic_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32 / Microsoft Visual Basic)"
	strings:
		$0 = {F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Borland_Delphi_50_KOLMCK__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Borland Delphi 5.0 KOL/MCK] --> Anorganix"
	strings:
		$0 = {55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0E 00 90 90 90 90 90 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0A 00 00 00 90 90 90 90 90 00 00 00 01 E9}
		$1 = {55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90}
		$2 = {55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _UPX_v081__v084_Modified_
{
	meta:
		description = "UPX v0.81 - v0.84 Modified"
	strings:
		$0 = {01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_PEX_099__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PEX 0.99] --> Anorganix"
	strings:
		$0 = {60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9}
		$1 = {60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _BobSoft_Mini_Delphi__BoB__BobSoft_
{
	meta:
		description = "BobSoft Mini Delphi -> BoB / BobSoft"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8}
		$1 = {55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8}
		$2 = {55 8B EC 83 C4 F0 53 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 ?? ?? ?? ?? E8}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _RECrypt_v07x__Crudd_RET_h1_
{
	meta:
		description = "RE-Crypt v0.7x -> Crudd [RET] (h1)"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B}
	condition:
		$0 at entrypoint
}
rule _EXE_Packer_v70_by_TurboPower_Software_
{
	meta:
		description = "EXE Packer v7.0 by TurboPower Software"
	strings:
		$0 = {1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE}
	condition:
		$0 at entrypoint
}
rule _Fusion_10__jaNooNi_
{
	meta:
		description = "Fusion 1.0 -> jaNooNi"
	strings:
		$0 = {68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00}
	condition:
		$0 at entrypoint
}
rule _yodas_Protector_v1033_exescrcom__Ashkbiz_Danehkar_h_
{
	meta:
		description = "yoda's Protector v1.03.3 (.exe,.scr,.com) -> Ashkbiz Danehkar (h)"
	strings:
		$0 = {E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75}
	condition:
		$0 at entrypoint
}
rule _RCryptor_v1__Vaska_
{
	meta:
		description = "RCryptor v1.?? -> Vaska"
	strings:
		$0 = {90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at entrypoint
}
rule _Prepared_by_SLR_OPTLINK_
{
	meta:
		description = "Prepared by SLR (OPTLINK)"
	strings:
		$0 = {87 C0 55 56 57 52 51 53 50 9C FC 8C DA 83 ?? ?? 16 07 0E 1F}
	condition:
		$0 at entrypoint
}
rule _yodas_Protector_10_beta__Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Protector 1.0 beta -> Ashkbiz Danehkar"
	strings:
		$0 = {55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt_15__BitShape_Software_
{
	meta:
		description = "PE Crypt 1.5 -> BitShape Software"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 55 20 40 00 B9 7B 09 00 00 8D BD 9D 20 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_MinGW_GCC_2x__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [MinGW GCC 2.x] --> Anorganix"
	strings:
		$0 = {55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45}
		$1 = {55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Private_EXE_v20a_
{
	meta:
		description = "Private EXE v2.0a"
	strings:
		$0 = {53 E8 00 00 00 00 5B 8B C3 2D}
		$1 = {53 E8 ?? ?? ?? ?? 5B 8B C3 2D}
	condition:
		$0 at entrypoint or $1
}
rule _BeRoEXEPacker_v100__BeRo__Farbrausch_
{
	meta:
		description = "BeRoEXEPacker v1.00 -> BeRo / Farbrausch"
	strings:
		$0 = {60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 BA ?? ?? ?? ?? 8D B2}
		$1 = {60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8}
		$2 = {60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10}
		$3 = {60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _ACProtect_14x__RISCO_soft_
{
	meta:
		description = "ACProtect 1.4x -> RISCO soft"
	strings:
		$0 = {47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70}
		$1 = {47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70}
	condition:
		$0 or $1
}
rule _ASProtect_v12__Alexey_Solodovnikov_h1_
{
	meta:
		description = "ASProtect v1.2 -> Alexey Solodovnikov (h1)"
	strings:
		$0 = {90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 ?? ?? ?? 00}
	condition:
		$0
}
rule _ASPack_v100b_
{
	meta:
		description = "ASPack v1.00b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_Modified_Stub_c__Farbrausch_Consumer_Consulting_
{
	meta:
		description = "UPX Modified Stub c -> Farb-rausch Consumer Consulting"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48}
	condition:
		$0 at entrypoint
}
rule _VcAsm_Protector_V10X_VcAsm_
{
	meta:
		description = "VcAsm Protector V1.0X-> VcAsm"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Microsoft_C_19901992_
{
	meta:
		description = "Microsoft C (1990/1992)"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7}
	condition:
		$0 at entrypoint
}
rule _eXPressor_v1451__CGSoftLabs_h_
{
	meta:
		description = "eXPressor v1.4.5.1 -> CGSoftLabs (h)"
	strings:
		$0 = {55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? ?? 05 00 ?? ?? ?? A3 08 ?? ?? ?? A1 08 ?? ?? ?? B9 81 ?? ?? ?? 2B 48 18 89 0D 0C ?? ?? ?? 83 3D 10 ?? ?? ?? 00 74 16 A1 08 ?? ?? ?? 8B 0D 0C ?? ?? ?? 03 48 14}
		$1 = {55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? ?? 05 00 ?? ?? ?? A3 08 ?? ?? ?? A1 08 ?? ?? ?? B9 81 ?? ?? ?? 2B 48 18 89 0D 0C ?? ?? ?? 83 3D 10 ?? ?? ?? 00 74 16 A1 08 ?? ?? ?? 8B 0D 0C ?? ?? ?? 03 48 14}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_ASPack_2xx_Heuristic__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [ASPack 2.xx Heuristic] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_02_LCC_Win32_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [LCC Win32 DLL] --> Anorganix"
	strings:
		$0 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1}
		$1 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _WebCops_EXE__LINK_Data_Security_
{
	meta:
		description = "WebCops [EXE] -> LINK Data Security"
	strings:
		$0 = {EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72}
	condition:
		$0 at entrypoint
}
rule _REC_C0ded_by_ROSE_
{
	meta:
		description = "REC, C0ded by ROSE"
	strings:
		$0 = {06 1E 0E 0E 07 1F B4 30 CD 21 86 E0 3D 00 03 73 ?? CD 20 EB}
	condition:
		$0 at entrypoint
}
rule _Petite_14__c199899_Ian_Luck_h_
{
	meta:
		description = "Petite 1.4 -> (c)1998-99 Ian Luck (h)"
	strings:
		$0 = {66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6}
	condition:
		$0 at entrypoint
}
rule _Inno_Setup_Module_v109a_
{
	meta:
		description = "Inno Setup Module v1.09a"
	strings:
		$0 = {55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0}
	condition:
		$0 at entrypoint
}
rule _TurboBAT_v310__50_Patched_
{
	meta:
		description = "TurboBAT v3.10 .. 5.0 (Patched)"
	strings:
		$0 = {90 90 90 90 90 90 90 06 B8 ?? ?? 8E C0 B9 ?? ?? 26 ?? ?? ?? ?? 80 ?? ?? 26 ?? ?? ?? 24 ?? 3A C4 90 90}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Basic_Compiler_v560_198297_
{
	meta:
		description = "Microsoft Basic Compiler v5.60 1982-97"
	strings:
		$0 = {9A ?? ?? ?? ?? 9A ?? ?? ?? ?? 9A ?? ?? ?? ?? 33 DB BA ?? ?? 9A ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 33 DB}
	condition:
		$0 at entrypoint
}
rule _PEStubOEP_v1x_
{
	meta:
		description = "PEStubOEP v1.x"
	strings:
		$0 = {40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3}
	condition:
		$0
}
rule _eXPressor_V13__CGSoftLabs_
{
	meta:
		description = "eXPressor V1.3 -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 83 EC ?? 53 56 57 EB 0C 45}
	condition:
		$0 at entrypoint
}
rule _ExeSafeguard_v10__simonzh_h_
{
	meta:
		description = "ExeSafeguard v1.0 -> simonzh (h)"
	strings:
		$0 = {C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE}
		$1 = {C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE}
	condition:
		$0 or $1
}
rule _Microsoft_Visual_Cpp_v4x_
{
	meta:
		description = "Microsoft Visual C++ v4.x"
	strings:
		$0 = {64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57}
	condition:
		$0 at entrypoint
}
rule _Mew_11_SE_v12_Eng__Northfox_
{
	meta:
		description = "Mew 11 SE v1.2 (Eng) -> Northfox"
	strings:
		$0 = {E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C}
	condition:
		$0 at entrypoint
}
rule _UPX_v072_
{
	meta:
		description = "UPX v0.72"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 83 ?? ?? 31 DB 5E 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? EB}
	condition:
		$0 at entrypoint
}
rule _FileShield_
{
	meta:
		description = "FileShield"
	strings:
		$0 = {50 1E EB ?? 90 00 00 8B D8}
	condition:
		$0 at entrypoint
}
rule _UPX_Protector_v10x_2_
{
	meta:
		description = "UPX Protector v1.0x (2)"
	strings:
		$0 = {EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB}
	condition:
		$0
}
rule _RLPack__Ap0x_
{
	meta:
		description = "RLPack -> Ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 3A 0A}
		$1 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 CD 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 14 0A}
		$2 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 ?? ?? ?? ?? EB 03 ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 9B 0A}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _aPack_v098b__Jibz_
{
	meta:
		description = "aPack v0.98b -> Jibz"
	strings:
		$0 = {93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA}
	condition:
		$0
}
rule _Noodlecrypt2__rsc_
{
	meta:
		description = "Noodlecrypt2 -> r!sc"
	strings:
		$0 = {EB 01 9A E8 76 00 00 00}
	condition:
		$0 at entrypoint
}
rule _SLVc0deProtector_v11__SLV_h_
{
	meta:
		description = "SLVc0deProtector v1.1 -> SLV (h)"
	strings:
		$0 = {E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C}
	condition:
		$0 at entrypoint
}
rule _MicroJoiner_16__coban2k_
{
	meta:
		description = "MicroJoiner 1.6 -> coban2k"
	strings:
		$0 = {33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B}
	condition:
		$0 at entrypoint
}
rule _PCIENC_Cryptor_
{
	meta:
		description = "PCIENC Cryptor"
	strings:
		$0 = {06 50 43 49 45 4E}
	condition:
		$0
}
rule _TurboBAT_v310__50_
{
	meta:
		description = "TurboBAT v3.10 .. 5.0"
	strings:
		$0 = {BA ?? ?? B4 09 ?? ?? 06 B8 ?? ?? 8E C0 B9 ?? ?? 26 ?? ?? ?? ?? 80 ?? ?? 26 ?? ?? ?? 24 0F 3A C4 ?? ?? 26 ?? ?? ?? 24 0F 3A C4}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_
{
	meta:
		description = "Microsoft Visual C++"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00}
		$1 = {8B 44 24 08 83 ?? ?? 74}
		$2 = {8B 44 24 08 56 83 E8 ?? 74 ?? 48 75}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _EXECryptor_V21X__SoftCompletecom_
{
	meta:
		description = "EXECryptor V2.1X -> SoftComplete.com"
	strings:
		$0 = {E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1}
	condition:
		$0 at entrypoint
}
rule _ASPack_v2xx_
{
	meta:
		description = "ASPack v2.xx"
	strings:
		$0 = {A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95}
		$1 = {A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95}
		$2 = {A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Metrowerks_CodeWarrior_DLL_v20_
{
	meta:
		description = "Metrowerks CodeWarrior (DLL) v2.0"
	strings:
		$0 = {55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 ?? ?? ?? ?? 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9}
	condition:
		$0
}
rule _PseudoSigner_02_VideoLanClient__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Video-Lan-Client] --> Anorganix"
	strings:
		$0 = {55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01}
		$1 = {55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Spanz_
{
	meta:
		description = "Vx: Spanz"
	strings:
		$0 = {E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84}
	condition:
		$0 at entrypoint
}
rule _Upack_v024__v028alpha__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.24 ~ v0.28alpha -> Sign by hot_UNP"
	strings:
		$0 = {BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD}
	condition:
		$0 at entrypoint
}
rule _EXE32Pack_v137_
{
	meta:
		description = "EXE32Pack v1.37"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40}
	condition:
		$0 at entrypoint
}
rule _Upack_v035_alpha__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.35 alpha -> Sign by hot_UNP"
	strings:
		$0 = {8B F2 8B CA 03 4C 19 1C 03 54 1A 20}
	condition:
		$0
}
rule _Zurenava_DOS_Extender_v045_v049_
{
	meta:
		description = "Zurenava DOS Extender v0.45, v0.49"
	strings:
		$0 = {BE ?? ?? BF ?? ?? B9 ?? ?? 56 FC F3 A5 5F E9}
	condition:
		$0 at entrypoint
}
rule _SmokesCrypt_v12_
{
	meta:
		description = "SmokesCrypt v1.2"
	strings:
		$0 = {60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1}
	condition:
		$0 at entrypoint
}
rule _Upack_01x_beta__Dwing_
{
	meta:
		description = "Upack 0.1x beta -> Dwing"
	strings:
		$0 = {BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1}
	condition:
		$0 at entrypoint
}
rule _ASPack_v211b_
{
	meta:
		description = "ASPack v2.11b"
	strings:
		$0 = {60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00}
	condition:
		$0 at entrypoint
}
rule _Obsidium_v1304__Obsidium_Software_
{
	meta:
		description = "Obsidium v1.3.0.4 -> Obsidium Software"
	strings:
		$0 = {EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00}
	condition:
		$0 at entrypoint
}
rule _InstallShield_2000_
{
	meta:
		description = "InstallShield 2000"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57}
	condition:
		$0 at entrypoint
}
rule _UltraPro_V10__SafeNet_
{
	meta:
		description = "UltraPro V1.0 -> SafeNet"
	strings:
		$0 = {A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15}
	condition:
		$0 at entrypoint
}
rule _CipherWall_SelfExtratorDecryptor_GUI_v15_
{
	meta:
		description = "CipherWall Self-Extrator/Decryptor (GUI) v1.5"
	strings:
		$0 = {90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4}
		$1 = {90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v110_Eng__bartxt_
{
	meta:
		description = "FSG v1.10 (Eng) -> bart/xt"
	strings:
		$0 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00}
	condition:
		$0 at entrypoint
}
rule _PolyEnE_001p_by_Lennart_Hedlund_
{
	meta:
		description = "PolyEnE 0.01+ by Lennart Hedlund"
	strings:
		$0 = {60 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 00 00 E0}
	condition:
		$0
}
rule _ACProtect_v190g__Risco_software_Inc_
{
	meta:
		description = "ACProtect v1.90g -> Risco software Inc."
	strings:
		$0 = {60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3}
	condition:
		$0 at entrypoint
}
rule _EXE_Stealth_v274_
{
	meta:
		description = "EXE Stealth v2.74"
	strings:
		$0 = {EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9}
		$1 = {EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9}
	condition:
		$0 or $1
}
rule _tElock_v095_
{
	meta:
		description = "tElock v0.95"
	strings:
		$0 = {E9 D5 E4 FF FF 00}
	condition:
		$0 at entrypoint
}
rule _NsPack_v31__North_Star_h_
{
	meta:
		description = "NsPack v3.1 -> North Star (h)"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00}
	condition:
		$0 at entrypoint
}
rule _FSG_131__dulekxt_
{
	meta:
		description = "FSG 1.31 -> dulek/xt"
	strings:
		$0 = {BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80}
	condition:
		$0 at entrypoint
}
rule _RJcrush_v100_
{
	meta:
		description = "RJcrush v1.00"
	strings:
		$0 = {06 FC 8C C8 BA ?? ?? 03 D0 52 BA ?? ?? 52 BA ?? ?? 03 C2 8B D8 05 ?? ?? 8E DB 8E C0 33 F6 33 FF B9}
	condition:
		$0 at entrypoint
}
rule _FSG_v20__bartxt_
{
	meta:
		description = "FSG v2.0 -> bart/xt"
	strings:
		$0 = {87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13}
	condition:
		$0 at entrypoint
}
rule _ACProtect_V14X__risco_
{
	meta:
		description = "ACProtect V1.4X -> risco"
	strings:
		$0 = {60 E8 01 00 00 00 7C 83 04 24 06 C3}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_Armadillo_300__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Armadillo 3.00] --> Anorganix"
	strings:
		$0 = {60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85}
		$1 = {60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _NTkrnl_Secure_Suite_V01_DLL__NTkrnl_Software_
{
	meta:
		description = "NTkrnl Secure Suite V0.1 DLL -> NTkrnl Software"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 8B 44 24 04 05 ?? ?? ?? ?? 50 E8 01 00 00 00 C3 C3}
	condition:
		$0
}
rule _PENinja_
{
	meta:
		description = "PENinja"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint
}
rule _StarForce_V3X__StarForce_Copy_Protection_System_
{
	meta:
		description = "StarForce V3.X -> StarForce Copy Protection System"
	strings:
		$0 = {68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _XPack_v142_
{
	meta:
		description = "X-Pack v1.4.2"
	strings:
		$0 = {72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3}
	condition:
		$0
}
rule _ENIGMA_Protector_V1X_Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.X-> Sukhov Vladimir"
	strings:
		$0 = {45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31}
	condition:
		$0
}
rule _A_program_by_Jupiter__
{
	meta:
		description = "A program by Jupiter .."
	strings:
		$0 = {2B C0 74 05 68 ?? ?? ?? ?? 50}
	condition:
		$0 at entrypoint
}
rule _PolyCryptor_by_SMT_Version_v3v4_
{
	meta:
		description = "PolyCryptor by SMT Version %v3.%v4"
	strings:
		$0 = {EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29}
	condition:
		$0 at entrypoint
}
rule _MinGW_GCC_DLL_v2xx_
{
	meta:
		description = "MinGW GCC DLL v2xx"
	strings:
		$0 = {55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _ASPack_v2000_
{
	meta:
		description = "ASPack v2.000"
	strings:
		$0 = {60 E8 70 05 00 00 EB 4C}
	condition:
		$0 at entrypoint
}
rule _MinGW_GCC_v2x_
{
	meta:
		description = "MinGW GCC v2.x"
	strings:
		$0 = {55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45}
		$1 = {55 89 E5 ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v160a_
{
	meta:
		description = "Armadillo v1.60a"
	strings:
		$0 = {55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v300a_
{
	meta:
		description = "Armadillo v3.00a"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB}
		$1 = {60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _xPEP_03x__xIkUg_
{
	meta:
		description = "xPEP 0.3x -> xIkUg"
	strings:
		$0 = {55 53 56 51 52 57 E8 16 00 00 00}
	condition:
		$0 at entrypoint
}
rule _SoftComp_1x__BG_Soft_PT_
{
	meta:
		description = "SoftComp 1.x -> BG Soft PT"
	strings:
		$0 = {E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00}
	condition:
		$0
}
rule _Vx_VCL_encrypted_
{
	meta:
		description = "Vx: VCL (encrypted)"
	strings:
		$0 = {01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3}
		$1 = {01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_VCL_
{
	meta:
		description = "Vx: VCL"
	strings:
		$0 = {AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89}
	condition:
		$0 at entrypoint
}
rule _eXpressor_v11__CGSoftLabs_
{
	meta:
		description = "eXpressor v1.1 -> CGSoftLabs"
	strings:
		$0 = {E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00}
		$1 = {E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v25x__v26x_
{
	meta:
		description = "Armadillo v2.5x - v2.6x"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC}
		$1 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _RLPack_Full_Edition_117_DLL_aPLib__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 DLL [aPLib] -> Ap0x"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 53 03 00 00 8D 9D 02 02 00 00 33 FF E8 ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75}
	condition:
		$0 at entrypoint
}
rule _PE_Pack_v099_
{
	meta:
		description = "PE Pack v0.99"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2}
	condition:
		$0 at entrypoint
}
rule _PUNiSHER_v15_DEMO__FEUERRADERAHTeam_
{
	meta:
		description = "PUNiSHER v1.5 (DEMO) -> FEUERRADER/AHTeam"
	strings:
		$0 = {EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04}
	condition:
		$0 at entrypoint
}
rule _Upack_v033__v034_Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.33 ~ v0.34 Beta -> Sign by hot_UNP"
	strings:
		$0 = {59 F3 A5 83 C8 FF 8B DF AB 40 AB 40}
	condition:
		$0 at entrypoint
}
rule _PEZip_v10_by_BaGIE_
{
	meta:
		description = "PEZip v1.0 by BaGIE"
	strings:
		$0 = {D9 D0 F8 74 02 23 DB F5 F5 50 51 52 53 8D 44 24 10 50 55 56 57 D9 D0 22 C9 C1 F7 A0 55 66 C1 C8 B0 5D 81 E6 FF FF FF FF F8 77 07 52 76 03 72 01 90 5A C1 E0 60 90 BD 1F 01 00 00 87 E8 E2 07 E3 05 17 5D 47 E4 42 41 7F 06 50 66 83 EE 00 58 25 FF FF FF FF 51}
	condition:
		$0
}
rule _CreateInstall_Stub_vxx_
{
	meta:
		description = "CreateInstall Stub vx.x"
	strings:
		$0 = {55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56}
		$1 = {55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _CRYPT_Version_17_c_Dismember_EXE_
{
	meta:
		description = "CRYPT Version 1.7 (c) Dismember (EXE)"
	strings:
		$0 = {0E 17 9C 58 F6 ?? ?? 74 ?? E9}
	condition:
		$0 at entrypoint
}
rule _SuckStop_v111_
{
	meta:
		description = "SuckStop v1.11"
	strings:
		$0 = {EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B}
	condition:
		$0 at entrypoint
}
rule _Upack_v021Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.21Beta -> Sign by hot_UNP"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v305c4_Unextractable_p_Virus_Shield_
{
	meta:
		description = "WWPACK v3.05c4 (Unextractable + Virus Shield)"
	strings:
		$0 = {03 05 40 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _VProtector_V10D__vcasm_
{
	meta:
		description = "VProtector V1.0D -> vcasm"
	strings:
		$0 = {55 8B EC 6A FF 68 CA 31 41 00 68 06 32 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50}
	condition:
		$0 at entrypoint
}
rule _PC_Shrinker_v020_
{
	meta:
		description = "PC Shrinker v0.20"
	strings:
		$0 = {E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68}
	condition:
		$0 at entrypoint
}
rule _UPX_v0896__v102__v105_v124__Markus__Laszlo_overlay_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 -v1.24 -> Markus & Laszlo [overlay]"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 ?? 8B 1E 83 ?? ?? 11 DB 72 ?? B8 01 00 00 00 01 DB 75}
	condition:
		$0 at entrypoint
}
rule _ActiveMARK_5x__Trymedia_SystemsInc_h_
{
	meta:
		description = "ActiveMARK 5.x -> Trymedia Systems,Inc. (h)"
	strings:
		$0 = {20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67}
		$1 = {20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67}
	condition:
		$0 or $1
}
rule _PEProtect_09_by_Cristoph_Gabler_1998_
{
	meta:
		description = "PE-Protect 0.9 by Cristoph Gabler 1998"
	strings:
		$0 = {50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39}
	condition:
		$0
}
rule _Free_Pascal_v106_
{
	meta:
		description = "Free Pascal v1.06"
	strings:
		$0 = {C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00}
	condition:
		$0
}
rule _RSCs_Process_Patcher_v14_
{
	meta:
		description = "R!SC's Process Patcher v1.4"
	strings:
		$0 = {E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92}
	condition:
		$0
}
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Basic_50__60_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual Basic 5.0 / 6.0)"
	strings:
		$0 = {C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77}
	condition:
		$0 at entrypoint
}
rule _Themida_1201_compressed__Oreans_Technologies_h_
{
	meta:
		description = "Themida 1.2.0.1 (compressed) -> Oreans Technologies (h)"
	strings:
		$0 = {B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8}
	condition:
		$0 at entrypoint
}
rule _SoftProtect__SoftProtectbyru_
{
	meta:
		description = "SoftProtect -> SoftProtect.by.ru"
	strings:
		$0 = {EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 59 83 01 01 80 39 5C}
	condition:
		$0 at entrypoint
}
rule _UPXLock_v10__CyberDoom_
{
	meta:
		description = "UPXLock v1.0 -> CyberDoom"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 60 E8 2B 03 00 00}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v220b1_
{
	meta:
		description = "Armadillo v2.20b1"
	strings:
		$0 = {55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPack_v011_
{
	meta:
		description = "UPack v0.11"
	strings:
		$0 = {BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7}
	condition:
		$0
}
rule _FSG_v11_
{
	meta:
		description = "FSG v1.1"
	strings:
		$0 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16}
	condition:
		$0 at entrypoint
}
rule _PECrypter_
{
	meta:
		description = "PE-Crypter"
	strings:
		$0 = {60 E8 00 00 00 00 5D EB 26}
	condition:
		$0 at entrypoint
}
rule _EXE_joiner__Amok_
{
	meta:
		description = "EXE joiner -> Amok"
	strings:
		$0 = {A1 14 A1 40 00 C1 E0 02 A3 18 A1 40}
	condition:
		$0 at entrypoint
}
rule _Name_of_the_Packer_v10_
{
	meta:
		description = "Name of the Packer v1.0"
	strings:
		$0 = {50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v11_MTEb_
{
	meta:
		description = "ASProtect v1.1 MTEb"
	strings:
		$0 = {90 60 E9 ?? 04}
	condition:
		$0 at entrypoint
}
rule _PAKSFX_Archive_
{
	meta:
		description = "PAK-SFX Archive"
	strings:
		$0 = {55 8B EC 83 ?? ?? A1 ?? ?? 2E ?? ?? ?? 2E ?? ?? ?? ?? ?? 8C D7 8E C7 8D ?? ?? BE ?? ?? FC AC 3C 0D}
	condition:
		$0 at entrypoint
}
rule _DevCpp_v4_
{
	meta:
		description = "Dev-C++ v4"
	strings:
		$0 = {55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF}
	condition:
		$0
}
rule _PCrypt_v351_
{
	meta:
		description = "PCrypt v3.51"
	strings:
		$0 = {50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_WATCOM_CCpp_EXE__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [WATCOM C/C++ EXE] --> Anorganix"
	strings:
		$0 = {E9 00 00 00 00 90 90 90 90 57 41}
		$1 = {E9 00 00 00 00 90 90 90 90 57 41}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Grazie883_
{
	meta:
		description = "Vx: Grazie.883"
	strings:
		$0 = {1E 0E 1F 50 06 BF 70 03 B4 1A BA 70 03 CD 21 B4 47 B2 00 BE 32 04 CD 21}
	condition:
		$0 at entrypoint
}
rule _Blade_Joiner_v15_
{
	meta:
		description = "Blade Joiner v1.5"
	strings:
		$0 = {55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85}
	condition:
		$0 at entrypoint
}
rule _PECompact_v2xx_
{
	meta:
		description = "PECompact v2.xx"
	strings:
		$0 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00}
	condition:
		$0
}
rule _EncryptPE_12003518__WFS_
{
	meta:
		description = "EncryptPE 1.2003.5.18 -> WFS"
	strings:
		$0 = {60 9C 64 FF 35 00 00 00 00 E8 79}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_MinGW_GCC_2x__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [MinGW GCC 2.x] --> Anorganix"
	strings:
		$0 = {55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9}
		$1 = {55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PEiDBundle_v100__v101__BoB__BobSoft_
{
	meta:
		description = "PEiD-Bundle v1.00 - v1.01 --> BoB / BobSoft"
	strings:
		$0 = {60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A}
	condition:
		$0 at entrypoint
}
rule _VProtector_V10_Build_20041213_test__vcasm_
{
	meta:
		description = "VProtector V1.0 [Build 2004.12.13] test! -> vcasm"
	strings:
		$0 = {55 8B EC 6A FF 68 1A 89 40 00 68 56 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50}
	condition:
		$0 at entrypoint
}
rule _SEAAXE_v22_
{
	meta:
		description = "SEA-AXE v2.2"
	strings:
		$0 = {FC BC ?? ?? 0E 1F A3 ?? ?? E8 ?? ?? A1 ?? ?? 8B ?? ?? ?? 2B C3 8E C0 B1 03 D3 E3 8B CB BF ?? ?? 8B F7 F3 A5}
	condition:
		$0 at entrypoint
}
rule _Simple_UPX_Cryptor_V3042005__MANtiCORE_
{
	meta:
		description = "Simple UPX Cryptor V30.4.2005 -> MANtiCORE"
	strings:
		$0 = {60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? ?? ?? E2 FA 61 68 ?? ?? ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _Crunch_5_Fusion_4_
{
	meta:
		description = "Crunch 5 Fusion 4"
	strings:
		$0 = {EB 15 03 ?? ?? ?? 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 55 E8}
	condition:
		$0
}
rule _PseudoSigner_01_Microsoft_Visual_Cpp_70_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual C++ 7.0 DLL] --> Anorganix"
	strings:
		$0 = {55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 ?? ?? ?? ?? E9}
		$1 = {55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 ?? ?? ?? ?? E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v190b1_
{
	meta:
		description = "Armadillo v1.90b1"
	strings:
		$0 = {55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Basic_50_
{
	meta:
		description = "Microsoft Visual Basic 5.0"
	strings:
		$0 = {FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00}
	condition:
		$0
}
rule _Pksmart_10b_
{
	meta:
		description = "Pksmart 1.0b"
	strings:
		$0 = {BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3}
	condition:
		$0 at entrypoint
}
rule _RLPack_Full_Edition_117_iBox_aPLib__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 iBox [aPLib] -> Ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 79 29 00 00 8D 9D 2C 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Neolite_20__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Neolite 2.0] --> Anorganix"
	strings:
		$0 = {E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 E9}
		$1 = {E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
		$2 = {E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _ASProtect_v12x_New_Strain_
{
	meta:
		description = "ASProtect v1.2x (New Strain)"
	strings:
		$0 = {68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3}
	condition:
		$0 at entrypoint
}
rule _Vx_SYP_
{
	meta:
		description = "Vx: SYP"
	strings:
		$0 = {47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v305c4_Extractable_p_Password_checking_
{
	meta:
		description = "WWPACK v3.05c4 (Extractable + Password checking)"
	strings:
		$0 = {03 05 80 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _ENIGMA_Protector_V112_Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.12-> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 C5 FA 81 ED ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31}
	condition:
		$0 at entrypoint
}
rule _nPack_v11_150200_Beta__NEOx_
{
	meta:
		description = "nPack v1.1 150-200 Beta -> NEOx"
	strings:
		$0 = {83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_PiMP_Install_System_v1x_
{
	meta:
		description = "Nullsoft PiMP Install System v1.x"
	strings:
		$0 = {83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74}
	condition:
		$0
}
rule _PseudoSigner_01_PENinja_131__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PENinja 1.31] --> Anorganix"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PKLITE_v200b_extra_
{
	meta:
		description = "PKLITE v2.00b [extra]"
	strings:
		$0 = {50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EA ?? ?? ?? ?? F3 A5 C3 59 2D ?? ?? 8E D0 51 2D ?? ?? 50 80}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_Install_System_v20_RC2_
{
	meta:
		description = "Nullsoft Install System v2.0 RC2"
	strings:
		$0 = {83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00}
	condition:
		$0
}
rule _PKLITE_v100c_2_
{
	meta:
		description = "PKLITE v1.00c (2)"
	strings:
		$0 = {BA ?? ?? A1 ?? ?? 2D ?? ?? 8C CB 81 C3 ?? ?? 3B C3 77 ?? 05 ?? ?? 3B C3 77 ?? B4 09 BA ?? ?? CD 21 CD 20 90}
	condition:
		$0 at entrypoint
}
rule _RLPack_Full_Edition_117_DLL_LZMA__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 DLL [LZMA] -> Ap0x"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v182_
{
	meta:
		description = "Armadillo v1.82"
	strings:
		$0 = {55 8B EC 6A FF 68 E0 C1 40 00 68 74 81 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 E0 C1 40 00 68 74 81 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PocketPC_ARM_
{
	meta:
		description = "PocketPC ARM"
	strings:
		$0 = {F0 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 ?? 00 00 EB 07 30 A0 E1 06 20 A0 E1 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB F0 40 BD E8 ?? 00 00 EA ?? 40 2D E9 ?? ?? 9F E5 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 9F E5 00 ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _PLINK86_1984_1985_
{
	meta:
		description = "PLINK86 1984, 1985"
	strings:
		$0 = {FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26}
	condition:
		$0 at entrypoint
}
rule _Software_Compress_v12__BG_Software_Protect_Technologies_
{
	meta:
		description = "Software Compress v1.2 -> BG Software Protect Technologies"
	strings:
		$0 = {E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 1A 0F 41 00 89 44 24 1C 61 C2 04 00 E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24}
	condition:
		$0 at entrypoint
}
rule _Petite_14_
{
	meta:
		description = "Petite 1.4"
	strings:
		$0 = {66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC}
	condition:
		$0
}
rule _Password_protector_my_SMT_
{
	meta:
		description = "Password protector my SMT"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5D 8B FD 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 46 80 ?? ?? 74}
	condition:
		$0 at entrypoint
}
rule _aPack_v098_m_
{
	meta:
		description = "aPack v0.98 -m"
	strings:
		$0 = {1E 06 8C C8 8E D8 05 ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B2 ?? BD ?? ?? 33 C9 50 A4 BB ?? ?? 3B F3 76}
	condition:
		$0
}
rule _Armadillo_v171_
{
	meta:
		description = "Armadillo v1.71"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1}
	condition:
		$0 at entrypoint
}
rule _yodas_Crypter_13__Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Crypter 1.3 -> Ashkbiz Danehkar"
	strings:
		$0 = {55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC}
	condition:
		$0 at entrypoint
}
rule _Vx_TrojanTelefoon_
{
	meta:
		description = "Vx: Trojan.Telefoon"
	strings:
		$0 = {60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05}
	condition:
		$0 at entrypoint
}
rule _PECompact_v0978_
{
	meta:
		description = "PECompact v0.978"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88}
	condition:
		$0 at entrypoint
}
rule _PocketPC_SHA_
{
	meta:
		description = "PocketPC SHA"
	strings:
		$0 = {86 2F 96 2F A6 2F B6 2F 22 4F 43 68 53 6B 63 6A 73 69 F0 7F 0B D0 0B 40 09 00 09 D0 B3 65 A3 66 93 67 0B 40 83 64 03 64 04 D0 0B 40 09 00 10 7F 26 4F F6 6B F6 6A F6 69 0B 00 F6 68 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 22 4F F0 7F 0A D0 06 D4 06 D5 0B 40 09}
	condition:
		$0 at entrypoint
}
rule _Lattice_C_v101_
{
	meta:
		description = "Lattice C v1.01"
	strings:
		$0 = {FA B8 ?? ?? 05 ?? ?? B1 ?? D3 E8 8C CB 03 C3 8E D8 8E D0 26 ?? ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 ?? D3 E3 EB}
	condition:
		$0 at entrypoint
}
rule _WinZip_SelfExtractor_22_personal_edition__WinZip_Computing_h_
{
	meta:
		description = "WinZip Self-Extractor 2.2 personal edition -> WinZip Computing (h)"
	strings:
		$0 = {53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B}
	condition:
		$0 at entrypoint
}
rule _XCR_v012_
{
	meta:
		description = "XCR v0.12"
	strings:
		$0 = {60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D}
	condition:
		$0 at entrypoint
}
rule _EXEPACK_LINK_v360_v364_v365_or_50121_
{
	meta:
		description = "EXEPACK (LINK) v3.60, v3.64, v3.65 or 5.01.21"
	strings:
		$0 = {8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 50 B8 ?? ?? 50 CB}
	condition:
		$0 at entrypoint
}
rule _SCRAM_v08a1_
{
	meta:
		description = "SCRAM! v0.8a1"
	strings:
		$0 = {B4 30 CD 21 3C 02 77 ?? CD 20 BC ?? ?? B9 ?? ?? 8B FC B2 ?? 58 4C}
	condition:
		$0 at entrypoint
}
rule _CERBERUS_v20_
{
	meta:
		description = "CERBERUS v2.0"
	strings:
		$0 = {9C 2B ED 8C ?? ?? 8C ?? ?? FA E4 ?? 88 ?? ?? 16 07 BF ?? ?? 8E DD 9B F5 B9 ?? ?? FC F3 A5}
	condition:
		$0 at entrypoint
}
rule _Gamehouse_Media_Protector_Version_Unknown_
{
	meta:
		description = "Gamehouse Media Protector Version Unknown"
	strings:
		$0 = {68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v301_v305_
{
	meta:
		description = "Armadillo v3.01, v3.05"
	strings:
		$0 = {60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F}
		$1 = {60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_Borland_Delphi_60__70__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Borland Delphi 6.0 - 7.0] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _SoftDefender_1x__Randy_Li_
{
	meta:
		description = "SoftDefender 1.x -> Randy Li"
	strings:
		$0 = {74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00}
	condition:
		$0 at entrypoint
}
rule _with_added_PK_signature_
{
	meta:
		description = "with added 'PK' signature"
	strings:
		$0 = {C7 ?? ?? ?? ?? ?? 8C D8 05}
	condition:
		$0 at entrypoint
}
rule _FSG_v133_Eng__dulekxt_
{
	meta:
		description = "FSG v1.33 (Eng) -> dulek/xt"
	strings:
		$0 = {BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D}
		$1 = {BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D}
		$2 = {BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _by_Central_Point_Software_
{
	meta:
		description = "by Central Point Software"
	strings:
		$0 = {50 51 52 56 57 8B EB 1E 2E}
	condition:
		$0 at entrypoint
}
rule _Vx_August_16th_Iron_Maiden_
{
	meta:
		description = "Vx: August 16th (Iron Maiden)"
	strings:
		$0 = {BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02}
	condition:
		$0 at entrypoint
}
rule _Upack_v02Beta_
{
	meta:
		description = "Upack v0.2Beta"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_v153_
{
	meta:
		description = "EXECryptor v1.5.3"
	strings:
		$0 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3}
		$1 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3}
	condition:
		$0 or $1
}
rule _SOFTWrapper_for_Win9xNT_Evaluation_Version_
{
	meta:
		description = "SOFTWrapper for Win9x/NT (Evaluation Version)"
	strings:
		$0 = {E8 00 00 00 00 5D 8B C5 2D ?? ?? ?? 00 50 81 ED 05 00 00 00 8B C5 2B 85 03 0F 00 00 89 85 03 0F 00 00 8B F0 03 B5 0B 0F 00 00 8B F8 03 BD 07 0F 00 00 83 7F 0C 00 74 2B 56 57 8B 7F 10 03 F8 8B 76 10 03 F0 83 3F 00 74 0C 8B 1E 89 1F 83 C6 04 83 C7 04 EB EF}
	condition:
		$0 at entrypoint
}
rule _Mew_10_v10_Eng__Northfox_
{
	meta:
		description = "Mew 10 v1.0 (Eng) -> Northfox"
	strings:
		$0 = {33 C0 E9 ?? ?? ?? FF}
	condition:
		$0 at entrypoint
}
rule _themida_1005__httpwwworeanscom_
{
	meta:
		description = "themida 1.0.0.5 -> http://www.oreans.com"
	strings:
		$0 = {B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44}
	condition:
		$0 at entrypoint
}
rule _CrypKey_v5__v6_
{
	meta:
		description = "CrypKey v5 - v6"
	strings:
		$0 = {E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06}
	condition:
		$0 at entrypoint
}
rule _PEBundle_v02__v20x_
{
	meta:
		description = "PEBundle v0.2 - v2.0x"
	strings:
		$0 = {9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_v151x_
{
	meta:
		description = "EXECryptor v1.5.1.x"
	strings:
		$0 = {E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3}
		$1 = {E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PESHiELD_v025_
{
	meta:
		description = "PESHiELD v0.25"
	strings:
		$0 = {60 E8 2B 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Vcasm_Protector_V1X__vcasm_
{
	meta:
		description = "Vcasm Protector V1.X -> vcasm"
	strings:
		$0 = {EB ?? 5B 56 50 72 6F 74 65 63 74 5D}
	condition:
		$0 at entrypoint
}
rule _Macromedia_Windows_Flash_ProjectorPlayer_v40_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v4.0"
	strings:
		$0 = {83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C}
	condition:
		$0 at entrypoint
}
rule _PCGuard_v303d_v305d_
{
	meta:
		description = "PC-Guard v3.03d, v3.05d"
	strings:
		$0 = {55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01}
	condition:
		$0 at entrypoint
}
rule _XJ__XPAL__LiNSoN_
{
	meta:
		description = "XJ / XPAL -> LiNSoN"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C}
	condition:
		$0 at entrypoint
}
rule _ExeShield_v37__ExeShield_Team_h_
{
	meta:
		description = "ExeShield v3.7 -> ExeShield Team (h)"
	strings:
		$0 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F}
	condition:
		$0 at entrypoint
}
rule _Microsoft_C_v104_
{
	meta:
		description = "Microsoft C v1.04"
	strings:
		$0 = {FA B8 ?? ?? 8E D8 8E D0 26 8B ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 04 D3 E3 EB}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v172__v173_
{
	meta:
		description = "Armadillo v1.72 - v1.73"
	strings:
		$0 = {55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58}
	condition:
		$0 at entrypoint
}
rule _PECrc32_088__ZhouJinYu_
{
	meta:
		description = "PECrc32 0.88 -> ZhouJinYu"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_FSG_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [FSG 1.0] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _beria_v007_public_WIP__symbiont_h_
{
	meta:
		description = "beria v0.07 public WIP --> symbiont (h)"
	strings:
		$0 = {83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0}
	condition:
		$0 at entrypoint
}
rule _BeRoEXEPacker_v100_DLL_LZBRS__BeRo__Farbrausch_
{
	meta:
		description = "BeRoEXEPacker v1.00 DLL [LZBRS] -> BeRo / Farbrausch"
	strings:
		$0 = {83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_Yodas_Protector_102__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Yoda's Protector 1.02] --> Anorganix"
	strings:
		$0 = {E8 03 00 00 00 EB 01 90 90}
		$1 = {E8 03 00 00 00 EB 01 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Upack_v037__v038_Beta_Strip_base_relocation_table_Option_Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.37 ~ v0.38 Beta (Strip base relocation table Option)-> Sign by hot_UNP"
	strings:
		$0 = {53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33}
	condition:
		$0
}
rule _HACKSTOP_v119_
{
	meta:
		description = "HACKSTOP v1.19"
	strings:
		$0 = {52 BA ?? ?? 5A EB ?? 9A ?? ?? ?? ?? 30 CD 21 ?? ?? ?? D6 02 ?? ?? CD 20 0E 1F 52 BA ?? ?? 5A EB}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v260b2_
{
	meta:
		description = "Armadillo v2.60b2"
	strings:
		$0 = {55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C}
	condition:
		$0 at entrypoint
}
rule _FSG_v130_Eng__dulekxt_
{
	meta:
		description = "FSG v1.30 (Eng) -> dulek/xt"
	strings:
		$0 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00}
	condition:
		$0 at entrypoint
}
rule _JAM_v211_
{
	meta:
		description = "JAM v2.11"
	strings:
		$0 = {50 06 16 07 BE ?? ?? 8B FE B9 ?? ?? FD FA F3 2E A5 FB 06 BD ?? ?? 55 CB}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v305c4_Extr_Passwcheck_Vir_shield_
{
	meta:
		description = "WWPACK v3.05c4 (Extr. Passw.check. Vir. shield)"
	strings:
		$0 = {03 05 C0 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _NsPack_v23__North_Star_h_
{
	meta:
		description = "NsPack v2.3 -> North Star (h)"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD}
	condition:
		$0
}
rule _PECompact_v147__v150_
{
	meta:
		description = "PECompact v1.47 - v1.50"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12}
	condition:
		$0 at entrypoint
}
rule _RLPack_FullEdition_V11X__ap0x____SignByfly_
{
	meta:
		description = "RLPack FullEdition V1.1X -> ap0x   * Sign.By.fly"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 10}
	condition:
		$0
}
rule _CPAV_
{
	meta:
		description = "CPAV"
	strings:
		$0 = {E8 ?? ?? 4D 5A B1 01 93 01 00 00 02}
	condition:
		$0 at entrypoint
}
rule _PassEXE_v20_
{
	meta:
		description = "PassEXE v2.0"
	strings:
		$0 = {06 1E 0E 0E 07 1F BE ?? ?? B9 ?? ?? 87 14 81 ?? ?? ?? EB ?? C7 ?? ?? ?? 84 00 87 ?? ?? ?? FB 1F 58 4A}
	condition:
		$0 at entrypoint
}
rule _EXE_Shield_V05__Smoke_
{
	meta:
		description = "EXE Shield V0.5 -> Smoke"
	strings:
		$0 = {E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40}
	condition:
		$0 at entrypoint
}
rule _tElock_098_Special_Build__forgot__heXer_
{
	meta:
		description = "tElock 0.98 Special Build -> forgot & heXer"
	strings:
		$0 = {E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA}
	condition:
		$0 at entrypoint
}
rule _Shrinker_33_
{
	meta:
		description = "Shrinker 3.3"
	strings:
		$0 = {00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8}
	condition:
		$0
}
rule _Stony_Brook_Pascalp_v70_
{
	meta:
		description = "Stony Brook Pascal+ v7.0"
	strings:
		$0 = {31 ED 9A ?? ?? ?? ?? 55 89 E5 81 EC ?? ?? B8 ?? ?? 0E 50 9A ?? ?? ?? ?? BE ?? ?? 1E 0E BF ?? ?? 1E 07 1F FC}
	condition:
		$0 at entrypoint
}
rule _UPX_v0761_pe_exe_
{
	meta:
		description = "UPX v0.76.1 [pe exe]"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 57 83 ?? ?? 31 DB EB}
	condition:
		$0 at entrypoint
}
rule _Ding_Boys_PElock_Phantasm_v10__v11_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v1.0 / v1.1"
	strings:
		$0 = {55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC}
	condition:
		$0 at entrypoint
}
rule _UPXShit_006_
{
	meta:
		description = "UPXShit 0.06"
	strings:
		$0 = {B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF}
	condition:
		$0 at entrypoint
}
rule _WinUpack_v030_beta__By_Dwing_
{
	meta:
		description = "WinUpack v0.30 beta -> By Dwing"
	strings:
		$0 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02}
	condition:
		$0
}
rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Borland_Cpp_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Borland C++)"
	strings:
		$0 = {2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80}
		$1 = {2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80}
		$2 = {EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02}
		$3 = {2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _Stony_Brook_Pascal_v614_
{
	meta:
		description = "Stony Brook Pascal v6.14"
	strings:
		$0 = {31 ED 9A ?? ?? ?? ?? 55 89 E5 ?? EC ?? ?? 9A}
	condition:
		$0 at entrypoint
}
rule _Launcher_Generator_v103_
{
	meta:
		description = "Launcher Generator v1.03"
	strings:
		$0 = {68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00}
	condition:
		$0
}
rule _Ding_Boys_PElock_v007_
{
	meta:
		description = "Ding Boy's PE-lock v0.07"
	strings:
		$0 = {55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00}
	condition:
		$0 at entrypoint
}
rule _PE_Lock_NT_v203_
{
	meta:
		description = "PE Lock NT v2.03"
	strings:
		$0 = {EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01}
	condition:
		$0 at entrypoint
}
rule _Exact_Audio_Copy__UnknownCompiler_
{
	meta:
		description = "Exact Audio Copy -> (UnknownCompiler)"
	strings:
		$0 = {E8 ?? ?? ?? 00 31 ED 55 89 E5 81 EC ?? 00 00 00 8D BD ?? FF FF FF B9 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _CExe_v10a_
{
	meta:
		description = "CExe v1.0a"
	strings:
		$0 = {55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16}
		$1 = {55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_290_LZMA__Markus_Oberhumer_Laszlo_Molnar__John_Reiser_
{
	meta:
		description = "UPX 2.90 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
		$1 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _CAN2EXE_v001_
{
	meta:
		description = "CAN2EXE v0.01"
	strings:
		$0 = {26 8E 06 ?? ?? B9 ?? ?? 33 C0 8B F8 F2 AE E3 ?? 26 38 05 75 ?? EB ?? E9}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v183_
{
	meta:
		description = "Armadillo v1.83"
	strings:
		$0 = {55 8B EC 6A FF 68 E0 C1 40 00 68 64 84 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 E0 C1 40 00 68 64 84 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PKLITE32_v11_
{
	meta:
		description = "PKLITE32 v1.1"
	strings:
		$0 = {55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 00 00 00 5D C2 0C 00 8B 45 0C 57 56 53 8B 5D 10}
		$1 = {55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10}
		$2 = {68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8}
		$3 = {68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 44 24 0C 50}
	condition:
		$0 at entrypoint or $1 or $2 at entrypoint or $3 at entrypoint
}
rule _Turbo_C_1988_
{
	meta:
		description = "Turbo C 1988"
	strings:
		$0 = {8C D8 BB ?? ?? 8E DB 8C D3 8B CC FA 8E ?? ?? ?? BC}
	condition:
		$0 at entrypoint
}
rule _TopSpeed_v301_1989_
{
	meta:
		description = "TopSpeed v3.01 1989"
	strings:
		$0 = {1E BA ?? ?? 8E DA 8B ?? ?? ?? 8B ?? ?? ?? FF ?? ?? ?? 50 53}
	condition:
		$0 at entrypoint
}
rule _Vx_Haryanto_
{
	meta:
		description = "Vx: Haryanto"
	strings:
		$0 = {81 EB 2A 01 8B 0F 1E 5B 03 CB 0E 51 B9 10 01 51 CB}
	condition:
		$0 at entrypoint
}
rule _Vx_Danish_tiny_
{
	meta:
		description = "Vx: Danish tiny"
	strings:
		$0 = {33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21}
	condition:
		$0 at entrypoint
}
rule _CodeLock_vxx_
{
	meta:
		description = "Code-Lock vx.x"
	strings:
		$0 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00}
	condition:
		$0 at entrypoint
}
rule _RCryptor_v16b__v16c__Vaska_
{
	meta:
		description = "RCryptor v1.6b / v1.6c --> Vaska"
	strings:
		$0 = {8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at entrypoint
}
rule _PKLITE32_11_
{
	meta:
		description = "PKLITE32 1.1"
	strings:
		$0 = {50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_80_Debug_
{
	meta:
		description = "Microsoft Visual C++ 8.0 [Debug]"
	strings:
		$0 = {E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9}
	condition:
		$0 at entrypoint
}
rule _624_Six_to_Four_v10_
{
	meta:
		description = "624 (Six to Four) v1.0"
	strings:
		$0 = {50 55 4C 50 83 ?? ?? FC BF ?? ?? BE ?? ?? B5 ?? 57 F3 A5 C3 33 ED}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Macromedia_Flash_Projector_60__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Macromedia Flash Projector 6.0] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C E9}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _yodas_Protector_10xAshkbiz_Danehkar_
{
	meta:
		description = "yoda's Protector 1.0x-->Ashkbiz Danehkar"
	strings:
		$0 = {55 8B EC 53 56 57 E8 03 00 00 00 EB 01}
	condition:
		$0 at entrypoint
}
rule _FSG_v10_
{
	meta:
		description = "FSG v1.0"
	strings:
		$0 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B}
		$1 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _CrunchPE_v30xx_
{
	meta:
		description = "Crunch/PE v3.0.x.x"
	strings:
		$0 = {EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74}
	condition:
		$0 at entrypoint
}
rule _Virogens_PE_Shrinker_v014_
{
	meta:
		description = "Virogen`s PE Shrinker v0.14"
	strings:
		$0 = {9C 55 E8 ?? ?? ?? ?? 87 D5 5D 60 87 D5 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 57 56 AD 0B C0 74}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v11_MTEc_
{
	meta:
		description = "ASProtect v1.1 MTEc"
	strings:
		$0 = {90 60 E8 1B ?? ?? ?? E9 FC}
	condition:
		$0 at entrypoint
}
rule _Vx_Eddie2100_
{
	meta:
		description = "Vx: Eddie.2100"
	strings:
		$0 = {E8 ?? ?? 4F 4F 0E E8 ?? ?? 47 47 1E FF ?? ?? CB E8 ?? ?? 84 C0 ?? ?? 50 53 56 57 1E 06 B4 51 CD 21 8E C3 ?? ?? ?? ?? ?? ?? ?? 8B F2 B4 2F CD 21 AC}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_ExeSmasher__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [ExeSmasher] --> Anorganix"
	strings:
		$0 = {9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9}
		$1 = {9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _HACKSTOP_v110_v111_
{
	meta:
		description = "HACKSTOP v1.10, v1.11"
	strings:
		$0 = {B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 2F CD 21 B0 ?? B4 4C CD 21 50 B8 ?? ?? 58 EB}
	condition:
		$0 at entrypoint
}
rule _DevCpp_v5_
{
	meta:
		description = "Dev-C++ v5"
	strings:
		$0 = {55 89 E5 83 EC 14 6A ?? FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00}
	condition:
		$0
}
rule _MinGW_v32x_Dll_WinMain_
{
	meta:
		description = "MinGW v3.2.x (Dll_WinMain)"
	strings:
		$0 = {55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00}
	condition:
		$0 at entrypoint
}
rule _PESPin_v13__Cyberbob_h_
{
	meta:
		description = "PESPin v1.3 -> Cyberbob (h)"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF}
	condition:
		$0 at entrypoint
}
rule _LameCrypt__LaZaRus_
{
	meta:
		description = "LameCrypt -> LaZaRus"
	strings:
		$0 = {60 66 9C BB 00 ?? ?? 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 ?? ?? 40 00 FF E0}
	condition:
		$0 at entrypoint
}
rule _CreateInstall_v200335_
{
	meta:
		description = "CreateInstall v2003.3.5"
	strings:
		$0 = {81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40}
		$1 = {81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40}
	condition:
		$0 or $1
}
rule _APatch_GUI_v11_
{
	meta:
		description = "APatch GUI v1.1"
	strings:
		$0 = {52 31 C0 E8 FF FF FF FF}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Borland_Delphi_20_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi 2.0)"
	strings:
		$0 = {EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB}
	condition:
		$0 at entrypoint
}
rule _VProtector_V11__vcasm_
{
	meta:
		description = "VProtector V1.1 -> vcasm"
	strings:
		$0 = {B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00}
	condition:
		$0 at entrypoint
}
rule _HACKSTOP_v111c_
{
	meta:
		description = "HACKSTOP v1.11c"
	strings:
		$0 = {B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB ?? ?? 5B EB}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_NorthStar_PE_Shrinker_13__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [NorthStar PE Shrinker 1.3] --> Anorganix"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00}
		$1 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Involuntary1349_
{
	meta:
		description = "Vx: Involuntary.1349"
	strings:
		$0 = {BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB}
	condition:
		$0 at entrypoint
}
rule _CodeCrypt_v0164_
{
	meta:
		description = "CodeCrypt v0.164"
	strings:
		$0 = {E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34}
	condition:
		$0 at entrypoint
}
rule _Krypton_v03_
{
	meta:
		description = "Krypton v0.3"
	strings:
		$0 = {8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA}
	condition:
		$0 at entrypoint
}
rule _CryptoLock_v202_Eng__Ryan_Thian_
{
	meta:
		description = "Crypto-Lock v2.02 (Eng) -> Ryan Thian"
	strings:
		$0 = {60 BE ?? 90 40 00 8D BE ?? ?? FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0}
		$1 = {60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0}
		$2 = {60 BE ?? 90 40 00 8D BE ?? ?? FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0}
		$3 = {60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0}
		$4 = {60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint
}
rule _CRYPT_Version_17_c_Dismember_COM_
{
	meta:
		description = "CRYPT Version 1.7 (c) Dismember (COM)"
	strings:
		$0 = {0E 17 9C 58 F6 C4 01 ?? ?? ?? ?? ?? B4 01 BE ?? ?? BF ?? ?? B9 ?? ?? 68 ?? ?? 68 ?? ?? 68 ?? ?? 57 F3 A4 C3 B0 02 E6 21 60}
	condition:
		$0 at entrypoint
}
rule _NTkrnl_Secure_Suite__NTkrnl_team_h_
{
	meta:
		description = "NTkrnl Secure Suite -> NTkrnl team (h)"
	strings:
		$0 = {34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73}
	condition:
		$0
}
rule _Nullsoft_Install_System_v20a0_
{
	meta:
		description = "Nullsoft Install System v2.0a0"
	strings:
		$0 = {83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74}
	condition:
		$0
}
rule _PEX_v099_
{
	meta:
		description = "PEX v0.99"
	strings:
		$0 = {60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81}
	condition:
		$0 at entrypoint
}
rule _UPX_v060__v061_
{
	meta:
		description = "UPX v0.60 - v0.61"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8}
	condition:
		$0 at entrypoint
}
rule _PELOCKnt_204_
{
	meta:
		description = "PELOCKnt 2.04"
	strings:
		$0 = {EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60}
	condition:
		$0 at entrypoint
}
rule _nMacro_recorder_10_
{
	meta:
		description = "nMacro recorder 1.0"
	strings:
		$0 = {5C 6E 6D 72 5F 74 65 6D 70 2E 6E 6D 72 00 00 00 72 62 00 00 58 C7 41 00 10 F8 41 00 11 01 00 00 00 00 00 00 46 E1 00 00 46 E1 00 00 35 00 00 00 F6 88 41 00}
	condition:
		$0
}
rule _E__
{
	meta:
		description = "E游地带-> 月黑风高"
	strings:
		$0 = {55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 0F 31 8B D8 0F 31 8B D0 2B D3 C1 EA 10 B8 ?? ?? ?? ?? 0F 6E C0 B8 ?? ?? ?? ?? 0F 6E C8 0F F5 C1 0F 7E C0 0F 77 03 C2 ?? ?? ?? ?? ?? FF E0}
	condition:
		$0 at entrypoint
}
rule _iPB_Protect_013__017__forgot_
{
	meta:
		description = "iPB Protect 0.1.3 - 0.1.7 -> forgot"
	strings:
		$0 = {55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Crunch_4_
{
	meta:
		description = "Crunch 4"
	strings:
		$0 = {EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8}
	condition:
		$0
}
rule _y0das_Crypter_v10_
{
	meta:
		description = "y0da's Crypter v1.0"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85}
	condition:
		$0 at entrypoint
}
rule _Trainer_Creation_Kit_v5_Trainer_
{
	meta:
		description = "Trainer Creation Kit v5 Trainer"
	strings:
		$0 = {6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40}
	condition:
		$0
}
rule _SoftSentry_v30_
{
	meta:
		description = "SoftSentry v3.0"
	strings:
		$0 = {55 8B EC 83 EC ?? 53 56 57 E9 B0 06}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v302_v302a_v304_Relocations_pack_
{
	meta:
		description = "WWPACK v3.02, v3.02a, v3.04 (Relocations pack)"
	strings:
		$0 = {BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC}
	condition:
		$0 at entrypoint
}
rule _Exe_Locker_10__IonIce_
{
	meta:
		description = "Exe Locker 1.0 -> IonIce"
	strings:
		$0 = {E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Pe123__v200644_
{
	meta:
		description = "Pe123  v2006.4.4"
	strings:
		$0 = {8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10}
	condition:
		$0 at entrypoint
}
rule _Vx_Igor_
{
	meta:
		description = "Vx: Igor"
	strings:
		$0 = {1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C}
	condition:
		$0 at entrypoint
}
rule _Crinkler_V01V02__Rune_LHStubbe_and_Aske_Simon_Christensen_
{
	meta:
		description = "Crinkler V0.1-V0.2 -> Rune L.H.Stubbe and Aske Simon Christensen"
	strings:
		$0 = {B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9}
	condition:
		$0 at entrypoint
}
rule _XPack_167_com_
{
	meta:
		description = "XPack 1.67 [com]"
	strings:
		$0 = {E9 53 00 FF FD FF FB FF F9 FF BC 03 00 8B E5 4C 4C C3}
	condition:
		$0 at entrypoint
}
rule _Petite_v_after_v14_
{
	meta:
		description = "Petite v?.? (after v1.4)"
	strings:
		$0 = {B8 ?? ?? ?? ?? 66 9C 60 50 8D ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 83}
	condition:
		$0 at entrypoint
}
rule _Microsoft_C_Library_1985_
{
	meta:
		description = "Microsoft C Library 1985"
	strings:
		$0 = {BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 81 C4 ?? ?? FB 73}
	condition:
		$0 at entrypoint
}
rule _SVK_Protector_v13x_Eng__Pavol_Cerven_
{
	meta:
		description = "SVK Protector v1.3x (Eng) -> Pavol Cerven"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E}
	condition:
		$0 at entrypoint
}
rule _Private_exe_Protector_V18XV19X__SetiSoft_Team_
{
	meta:
		description = "Private exe Protector V1.8X-V1.9X -> SetiSoft Team"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73}
	condition:
		$0
}
rule _Symantec_Visual_Cafe_v30_
{
	meta:
		description = "Symantec Visual Cafe v3.0"
	strings:
		$0 = {64 8B 05 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? 40 ?? 68 ?? ?? 40 ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 08 50 53 56 57 89 65 E8 C7 45 FC}
	condition:
		$0 at entrypoint
}
rule _PassLock_2000_v10_Eng__MoonlightSoftware_
{
	meta:
		description = "PassLock 2000 v1.0 (Eng) -> Moonlight-Software"
	strings:
		$0 = {55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24}
		$1 = {55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _KGB_SFX_
{
	meta:
		description = "KGB SFX"
	strings:
		$0 = {60 BE 00 A0 46 00 8D BE 00 70 F9 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73}
	condition:
		$0 at entrypoint
}
rule _NsPacK_V34V35__LiuXingPing_
{
	meta:
		description = "NsPacK V3.4-V3.5 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84}
	condition:
		$0 at entrypoint
}
rule _Excalibur_103__forgot_
{
	meta:
		description = "Excalibur 1.03 -> forgot"
	strings:
		$0 = {E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _XCR_v013_
{
	meta:
		description = "XCR v0.13"
	strings:
		$0 = {93 71 08 ?? ?? ?? ?? ?? ?? ?? ?? 8B D8 78 E2 ?? ?? ?? ?? 9C 33 C3 ?? ?? ?? ?? 60 79 CE ?? ?? ?? ?? E8 01 ?? ?? ?? ?? 83 C4 04 E8 AB FF FF FF ?? ?? ?? ?? 2B E8 ?? ?? ?? ?? 03 C5 FF 30 ?? ?? ?? ?? C6 ?? EB}
	condition:
		$0 at entrypoint
}
rule _Guardant_Stealth_aka_Novex_Dongle_
{
	meta:
		description = "Guardant Stealth aka Novex Dongle"
	strings:
		$0 = {55 8B EC 83 C4 F0 60 E8 51 FF FF FF}
	condition:
		$0 at entrypoint
}
rule _FSG_v120_Eng__dulekxt__Borland_Cpp_
{
	meta:
		description = "FSG v1.20 (Eng) -> dulek/xt -> (Borland C++)"
	strings:
		$0 = {C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6}
		$1 = {C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Free_Pascal_v1010_win32_console_
{
	meta:
		description = "Free Pascal v1.0.10 (win32 console)"
	strings:
		$0 = {C6 05 ?? ?? ?? 00 01 E8 ?? ?? 00 00 C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 ?? EC}
	condition:
		$0
}
rule _DOS32_v33_DOSExtender_and_Loader_
{
	meta:
		description = "DOS32 v.3.3 DOS-Extender and Loader"
	strings:
		$0 = {0E 1F FC 9C 5B 8B C3 80 F4 ?? 50 9D 9C 58 3A E7 75 ?? BA ?? ?? B4 09 CD 21 B4 4C CD 21}
	condition:
		$0 at entrypoint
}
rule _SVKProtector_v1051_
{
	meta:
		description = "SVK-Protector v1.051"
	strings:
		$0 = {60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v42_
{
	meta:
		description = "Microsoft Visual C++ v4.2"
	strings:
		$0 = {64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? FF}
		$1 = {64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? C7}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _CrunchPE_v50_
{
	meta:
		description = "Crunch/PE v5.0"
	strings:
		$0 = {EB 15 03 ?? ?? ?? 06}
	condition:
		$0
}
rule _MinGW_v32x__mainCRTStartup_
{
	meta:
		description = "MinGW v3.2.x (_mainCRTStartup)"
	strings:
		$0 = {55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 40 00 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _SDProtector_BasicPro_Edition_110__Randy_Li_h_
{
	meta:
		description = "SDProtector Basic/Pro Edition 1.10 -> Randy Li (h)"
	strings:
		$0 = {55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64}
	condition:
		$0 at entrypoint
}
rule _AHPack_01__FEUERRADER_
{
	meta:
		description = "AHPack 0.1 -> FEUERRADER"
	strings:
		$0 = {60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00}
	condition:
		$0 at entrypoint
}
rule _tElock_v071_
{
	meta:
		description = "tElock v0.71"
	strings:
		$0 = {60 E8 ED 10 00 00 C3 83}
	condition:
		$0 at entrypoint
}
rule _Upack_v022__v023Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.22 ~ v0.23Beta -> Sign by hot_UNP"
	strings:
		$0 = {6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5}
	condition:
		$0 at entrypoint
}
rule _Macromedia_Windows_Flash_ProjectorPlayer_v50_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v5.0"
	strings:
		$0 = {83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00}
	condition:
		$0 at entrypoint
}
rule _Trilobytes_JPEG_graphics_Library_
{
	meta:
		description = "Trilobyte's JPEG graphics Library"
	strings:
		$0 = {84 10 FF FF FF FF 1E 00 01 10 08 00 00 00 00 00}
	condition:
		$0
}
rule _eXPressor_v12__CGSoftLabs_
{
	meta:
		description = "eXPressor v1.2 -> CGSoftLabs"
	strings:
		$0 = {45 78 50 72 2D 76 2E 31 2E 32 2E}
	condition:
		$0
}
rule _Shrink_Wrap_v14_
{
	meta:
		description = "Shrink Wrap v1.4"
	strings:
		$0 = {58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_CrunchPE_Heuristic__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Crunch/PE Heuristic] --> Anorganix"
	strings:
		$0 = {55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00}
		$1 = {55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Eddie1028_
{
	meta:
		description = "Vx: Eddie.1028"
	strings:
		$0 = {E8 ?? ?? 5E FC 83 ?? ?? 81 ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E B8 FE 4B CD 21 81 FF BB 55 ?? ?? 07 ?? ?? ?? 07 B4 49 CD 21 BB FF FF B4 48 CD 21}
	condition:
		$0 at entrypoint
}
rule _Vx_GRUNT4Family_
{
	meta:
		description = "Vx: GRUNT.4.Family"
	strings:
		$0 = {E8 1C 00 8D 9E 41 01 40 3E 8B 96 14 03 B9 EA 00 87 DB F7 D0 31 17 83 C3 02 E2 F7 C3}
	condition:
		$0 at entrypoint
}
rule _PECompact_v098_
{
	meta:
		description = "PECompact v0.98"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_CDCops_II__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [CD-Cops II] --> Anorganix"
	strings:
		$0 = {53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01}
		$1 = {53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Zortech_C_v200_1988_1989_
{
	meta:
		description = "Zortech C v2.00 1988, 1989"
	strings:
		$0 = {FA B8 ?? ?? 8E D8 8C ?? ?? ?? 26 8B ?? ?? ?? 89 1E ?? ?? 8B D8 2B 1E ?? ?? 89 1E}
	condition:
		$0 at entrypoint
}
rule _ActiveMARKTM_R5311140__Trymedia_
{
	meta:
		description = "ActiveMARK[TM] R5.31.1140 -> Trymedia"
	strings:
		$0 = {79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25}
	condition:
		$0 at entrypoint
}
rule _Vx_Number_One_
{
	meta:
		description = "Vx: Number One"
	strings:
		$0 = {F9 07 3C 53 6D 69 6C 65 3E E8}
	condition:
		$0 at entrypoint
}
rule _MS_RunTime_Library_1990_07_
{
	meta:
		description = "MS Run-Time Library 1990 (07)"
	strings:
		$0 = {2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F 8B 1E ?? ?? 0B DB 74 ?? 8C D1 8B D4 FA 8E D3 BC ?? ?? FB}
	condition:
		$0 at entrypoint
}
rule _PECompact_v0971__v0976_
{
	meta:
		description = "PECompact v0.971 - v0.976"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85}
	condition:
		$0 at entrypoint
}
rule _ExeTools_COM2EXE_
{
	meta:
		description = "ExeTools COM2EXE"
	strings:
		$0 = {E8 ?? ?? 5D 83 ED ?? 8C DA 2E 89 96 ?? ?? 83 C2 ?? 8E DA 8E C2 2E 01 96 ?? ?? 60}
	condition:
		$0 at entrypoint
}
rule _ASProtect_SKE_21x_dll__Alexey_Solodovnikov_h_
{
	meta:
		description = "ASProtect SKE 2.1x (dll) -> Alexey Solodovnikov (h)"
	strings:
		$0 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$1 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FixupPak_v120_
{
	meta:
		description = "FixupPak v1.20"
	strings:
		$0 = {55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8}
		$1 = {55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Exe_Guarder_v18__Exeiconcom_h_
{
	meta:
		description = "Exe Guarder v1.8 -> Exeicon.com (h)"
	strings:
		$0 = {55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89}
		$1 = {55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_MEW_11_SE_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [MEW 11 SE 1.0] --> Anorganix"
	strings:
		$0 = {E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9}
		$1 = {E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_C_20_
{
	meta:
		description = "Microsoft Visual C 2.0"
	strings:
		$0 = {64 A1 00 00 00 00 55 8B EC 6A FF 68}
	condition:
		$0 at entrypoint
}
rule _UPX_p_ECLiPSE_layer_
{
	meta:
		description = "UPX + ECLiPSE layer"
	strings:
		$0 = {B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01}
	condition:
		$0 at entrypoint
}
rule _NET_executable_
{
	meta:
		description = ".NET executable"
	strings:
		$0 = {FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _yodas_Crypter_13Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Crypter 1.3-->Ashkbiz Danehkar"
	strings:
		$0 = {55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_Install_System_v1xx_
{
	meta:
		description = "Nullsoft Install System v1.xx"
	strings:
		$0 = {55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00}
		$1 = {83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_SPx_
{
	meta:
		description = "Microsoft Visual C++ v6.0 SPx"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15}
		$1 = {55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _TXT2COM_v206_
{
	meta:
		description = "TXT2COM v2.06"
	strings:
		$0 = {8D 26 ?? ?? E8 ?? ?? B8 ?? ?? CD 21 CD 20 54 58 54 32 43 4F 4D 20}
	condition:
		$0 at entrypoint
}
rule _DIET_v100d_
{
	meta:
		description = "DIET v1.00d"
	strings:
		$0 = {FC 06 1E 0E 8C C8 01 ?? ?? ?? BA ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PEShit_
{
	meta:
		description = "PEShit"
	strings:
		$0 = {B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF}
	condition:
		$0 at entrypoint
}
rule _BeRoEXEPacker_v100_LZMA__BeRo__Farbrausch_
{
	meta:
		description = "BeRoEXEPacker v1.00 [LZMA] -> BeRo / Farbrausch"
	strings:
		$0 = {60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8}
	condition:
		$0 at entrypoint
}
rule _AcidCrypt_
{
	meta:
		description = "AcidCrypt"
	strings:
		$0 = {BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB}
		$1 = {60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v13_
{
	meta:
		description = "FSG v1.3"
	strings:
		$0 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00}
		$1 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_Modified_Stub_b__Farbrausch_Consumer_Consulting_
{
	meta:
		description = "UPX Modified Stub b -> Farb-rausch Consumer Consulting"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC}
	condition:
		$0 at entrypoint
}
rule _Unknown_packer_07_
{
	meta:
		description = "Unknown packer (07)"
	strings:
		$0 = {8C C8 05 ?? ?? 50 B8 ?? ?? 50 B0 ?? 06 8C D2 06 83}
	condition:
		$0 at entrypoint
}
rule _HACKSTOP_v118_
{
	meta:
		description = "HACKSTOP v1.18"
	strings:
		$0 = {52 BA ?? ?? 5A EB ?? 9A ?? ?? ?? ?? 30 CD 21 ?? ?? ?? FD 02 ?? ?? CD 20 0E 1F 52 BA ?? ?? 5A EB}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v260b1_
{
	meta:
		description = "Armadillo v2.60b1"
	strings:
		$0 = {55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC}
	condition:
		$0 at entrypoint
}
rule _AdFlt2_
{
	meta:
		description = "AdFlt2"
	strings:
		$0 = {68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_Dll_mainCRTStartup_
{
	meta:
		description = "MinGW v3.2.x (Dll_mainCRTStartup)"
	strings:
		$0 = {55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 00 10 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _SimplePack_V11XV12X_Method2__bagie_
{
	meta:
		description = "SimplePack V1.1X-V1.2X (Method2) -> bagie"
	strings:
		$0 = {4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_vxxxx_
{
	meta:
		description = "EXECryptor vx.x.x.x"
	strings:
		$0 = {E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41}
	condition:
		$0 at entrypoint
}
rule _SoftSentry_v211_
{
	meta:
		description = "SoftSentry v2.11"
	strings:
		$0 = {55 8B EC 83 EC ?? 53 56 57 E9 50}
	condition:
		$0 at entrypoint
}
rule _RECrypt_v07x__Crudd_RET_h2_
{
	meta:
		description = "RE-Crypt v0.7x -> Crudd [RET] (h2)"
	strings:
		$0 = {60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_JDPack_1x__JDProtect_09__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [JDPack 1.x / JDProtect 0.9] --> Anorganix"
	strings:
		$0 = {60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9}
		$1 = {60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASPack_v1061b_
{
	meta:
		description = "ASPack v1.061b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _SEAAXE_
{
	meta:
		description = "SEA-AXE"
	strings:
		$0 = {FC BC ?? ?? 0E 1F E8 ?? ?? 26 A1 ?? ?? 8B 1E ?? ?? 2B C3 8E C0 B1 ?? D3 E3}
	condition:
		$0 at entrypoint
}
rule _Microsoft_C_19881989_
{
	meta:
		description = "Microsoft C (1988/1989)"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? CD 20 BF ?? ?? 8B ?? ?? ?? 2B F7 81 ?? ?? ?? 72}
	condition:
		$0 at entrypoint
}
rule _Aluwain_v809_
{
	meta:
		description = "Aluwain v8.09"
	strings:
		$0 = {8B EC 1E E8 ?? ?? 9D 5E}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Lockless_Intro_Pack__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Lockless Intro Pack] --> Anorganix"
	strings:
		$0 = {2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD E9}
		$1 = {2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_02_Borland_Delphi_Setup_Module__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Borland Delphi Setup Module] --> Anorganix"
	strings:
		$0 = {55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00}
		$1 = {55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _EXE2COM_Encrypted_without_selfcheck_
{
	meta:
		description = "EXE2COM (Encrypted without selfcheck)"
	strings:
		$0 = {B3 ?? B9 ?? ?? BE ?? ?? BF ?? ?? EB ?? 54 69 ?? ?? ?? ?? 03 ?? ?? 32 C3 AA 43 49 E3 ?? EB ?? BE ?? ?? 8B C6}
	condition:
		$0 at entrypoint
}
rule _Obsidium_v1304__Obsidium_Software_h_
{
	meta:
		description = "Obsidium v1.3.0.4 -> Obsidium Software (h)"
	strings:
		$0 = {EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01}
	condition:
		$0 at entrypoint
}
rule _PrivateEXE_v20a_
{
	meta:
		description = "PrivateEXE v2.0a"
	strings:
		$0 = {06 60 C8 ?? ?? ?? 0E 68 ?? ?? 9A ?? ?? ?? ?? 3D ?? ?? 0F ?? ?? ?? 50 50 0E 68 ?? ?? 9A ?? ?? ?? ?? 0E}
		$1 = {53 E8 ?? ?? ?? ?? 5B 8B C3 2D ?? ?? ?? ?? 50 81 ?? ?? ?? ?? ?? 8B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Obsiduim_1304__Obsiduim_Software_
{
	meta:
		description = "Obsiduim 1.3.0.4 -> Obsiduim Software"
	strings:
		$0 = {EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64}
	condition:
		$0 at entrypoint
}
rule _tElock_v085f_
{
	meta:
		description = "tElock v0.85f"
	strings:
		$0 = {60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v190b3_
{
	meta:
		description = "Armadillo v1.90b3"
	strings:
		$0 = {55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_C_v70__Basic_NET_
{
	meta:
		description = "Microsoft Visual C# v7.0 / Basic .NET"
	strings:
		$0 = {FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0
}
rule _EXEJoiner_v10_
{
	meta:
		description = "EXEJoiner v1.0"
	strings:
		$0 = {68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8}
		$1 = {68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ORiEN_v211__212__Fisun_Alexander_
{
	meta:
		description = "ORiEN v2.11 - 2.12 -> Fisun Alexander"
	strings:
		$0 = {E9 5D 01 00 00 CE D1 CE ?? 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F}
	condition:
		$0 at entrypoint
}
rule _Upack_Patch__Sign_by_hot_UNP_
{
	meta:
		description = "Upack_Patch -> Sign by hot_UNP"
	strings:
		$0 = {81 3A 00 00 00 02 00 00 00 00}
		$1 = {2A A3 F2 54 CE}
	condition:
		$0 at entrypoint or $1
}
rule _RLPack_10_beta__ap0x_
{
	meta:
		description = "RLPack 1.0 beta -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 48 02 00 00 56 FF D3 83 C4 08 8B B5 48 02 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 83 C0 04 89 85 44 02 00 00 EB 7A 56 FF 95 F1 01 00 00 89 85 40 02 00 00 8B C6 EB 4F 8B 85 44 02 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 44 02 00 00 C7 00 20 20 20 00 EB 06 FF B5 44 02 00 00 FF B5 40 02 00 00 FF 95 F5 01 00 00 89 07 83 C7 04 8B 85 44 02 00 00 EB 01 40 80 38 00 75 FA 40 89 85 44 02 00 00 80 38 00 75 AC EB 01 46 80 3E 00 75 FA 46 40 8B 38 83 C0 04 89 85 44 02 00 00 80 3E 01 75 81 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 48 02 00 00 FF 95 FD 01 00 00 61 68 ?? ?? ?? ?? C3 60 8B 74 24 24 8B 7C}
	condition:
		$0 at entrypoint
}
rule _RLPack_117p_
{
	meta:
		description = "RLPack 1.17+"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? 00 00 8D 9D ?? ?? 00 00 33 FF E8 ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 37 FF D3}
	condition:
		$0 at entrypoint
}
rule _y0das_Crypter_v11_
{
	meta:
		description = "y0da's Crypter v1.1"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33}
	condition:
		$0 at entrypoint
}
rule _Adys_Glue_v010_
{
	meta:
		description = "Ady`s Glue v0.10"
	strings:
		$0 = {2E 8C 06 ?? ?? 0E 07 33 C0 8E D8 BE ?? ?? BF ?? ?? FC B9 ?? ?? 56 F3 A5 1E 07 5F}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_CrunchPE_Heuristic__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Crunch/PE Heuristic] --> Anorganix"
	strings:
		$0 = {55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 E9}
		$1 = {55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _eXPressor_120_Beta_PE_Packer_
{
	meta:
		description = "eXPressor 1.2.0 Beta PE Packer"
	strings:
		$0 = {55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 EB ?? 45 78 50 72 2D 76 2E 31 2E 32 2E 2E}
	condition:
		$0 at entrypoint
}
rule _W32Jeefo_PE_File_Infector_
{
	meta:
		description = "W32.Jeefo (PE File Infector)"
	strings:
		$0 = {55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 ?? ?? ?? FF D0 E8 ?? ?? ?? ?? C9 C3}
	condition:
		$0 at entrypoint
}
rule _EXE2COM_Limited_
{
	meta:
		description = "EXE2COM (Limited)"
	strings:
		$0 = {BE ?? ?? 8B 04 3D ?? ?? 74 ?? BA ?? ?? B4 09 CD 21 CD 20}
	condition:
		$0 at entrypoint
}
rule _StarForce_Protection_Driver__Protection_Technology_
{
	meta:
		description = "StarForce Protection Driver -> Protection Technology"
	strings:
		$0 = {57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _PolyEnE_V001p__Lennart_Hedlund_
{
	meta:
		description = "PolyEnE V0.01+ -> Lennart Hedlund"
	strings:
		$0 = {50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C}
	condition:
		$0
}
rule _PeX_v099_Eng__bartCrackPl_
{
	meta:
		description = "PeX v0.99 (Eng) -> bart/CrackPl"
	strings:
		$0 = {E9 F5 00 00 00 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4}
	condition:
		$0 at entrypoint
}
rule _WATCOM_CCpp_32_RunTime_System_1989_1994_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1989, 1994"
	strings:
		$0 = {0E 1F 8C C6 B4 ?? 50 BB ?? ?? CD 21 73 ?? 58 CD 21 72}
	condition:
		$0 at entrypoint
}
rule _CDCops_II_
{
	meta:
		description = "CD-Cops II"
	strings:
		$0 = {53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D}
	condition:
		$0 at entrypoint
}
rule _SmartE__Microsoft_
{
	meta:
		description = "SmartE -> Microsoft"
	strings:
		$0 = {EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06}
	condition:
		$0 at entrypoint
}
rule _aPack_v098b_DSES_not_saved_
{
	meta:
		description = "aPack v0.98b (DS&ES not saved)"
	strings:
		$0 = {8C CB BA ?? ?? 03 DA FC 33 F6 33 FF 4B 8E DB 8D ?? ?? ?? 8E C0 B9 ?? ?? F3 A5 4A 75}
	condition:
		$0
}
rule _NsPack_14_by_North_Star_Liu_Xing_Ping_
{
	meta:
		description = "NsPack 1.4 by North Star (Liu Xing Ping)"
	strings:
		$0 = {8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53}
	condition:
		$0
}
rule _PEArmor_049__Hying_
{
	meta:
		description = "PE-Armor 0.49 -> Hying"
	strings:
		$0 = {56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Stones_PE_Encryptor_v20_
{
	meta:
		description = "Stone's PE Encryptor v2.0"
	strings:
		$0 = {53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_DLL_
{
	meta:
		description = "Microsoft Visual C++ v6.0 DLL"
	strings:
		$0 = {83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? ?? 00 10 E8 8B FF FF FF}
		$1 = {55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84}
		$2 = {55 8B EC 53 8B 5D 08 56 8B 75 0C}
		$3 = {55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3
}
rule _UCEXE_v23_v24_
{
	meta:
		description = "UCEXE v2.3, v2.4"
	strings:
		$0 = {50 1E 0E 1F FC 33 F6 E8 ?? ?? 16 07 33 F6 33 FF B9 ?? ?? F3 A5 06 B8 ?? ?? 50 CB}
	condition:
		$0 at entrypoint
}
rule _UPX_Alternative_stub_
{
	meta:
		description = "UPX Alternative stub"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B}
	condition:
		$0 at entrypoint
}
rule _EXERefactor_V01__random_
{
	meta:
		description = "EXERefactor V0.1 -> random"
	strings:
		$0 = {55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E}
	condition:
		$0 at entrypoint
}
rule _WinRAR_32bit_SFX_Module_
{
	meta:
		description = "WinRAR 32-bit SFX Module"
	strings:
		$0 = {E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF}
	condition:
		$0 at entrypoint
}
rule _Microsoft_FORTRAN_
{
	meta:
		description = "Microsoft FORTRAN"
	strings:
		$0 = {FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC 8C DB 8E C3 BB ?? ?? B9 ?? ?? 9A ?? ?? ?? ?? 80 ?? ?? ?? ?? 74 ?? E9}
	condition:
		$0 at entrypoint
}
rule _Vx_MTE_nonencrypted_
{
	meta:
		description = "Vx: MTE (non-encrypted)"
	strings:
		$0 = {F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48}
	condition:
		$0 at entrypoint
}
rule _Goats_PE_Mutilator_16_
{
	meta:
		description = "Goat's PE Mutilator 1.6"
	strings:
		$0 = {E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v123_RC1_
{
	meta:
		description = "ASProtect v1.23 RC1"
	strings:
		$0 = {68 01 ?? ?? 00 E8 01 00 00 00 C3 C3}
	condition:
		$0 at entrypoint
}
rule _PCShrink_v040b_
{
	meta:
		description = "PCShrink v0.40b"
	strings:
		$0 = {9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D}
	condition:
		$0 at entrypoint
}
rule _CopyControl_v303_
{
	meta:
		description = "CopyControl v3.03"
	strings:
		$0 = {CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C}
	condition:
		$0 at entrypoint
}
rule _DJoin_v07_public_xor_encryption__drmist_
{
	meta:
		description = "DJoin v0.7 public (xor encryption) -> drmist"
	strings:
		$0 = {C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _Com4mail_v10_
{
	meta:
		description = "Com4mail v1.0"
	strings:
		$0 = {42 45 47 49 4E 3D 3D 3D 74 66 75 64 23 6F 66 5F 43 6F 6D 34 4D 61 69 6C 5F 66 69 6C 65 23 0D 0A}
	condition:
		$0 at entrypoint
}
rule _ASPack_v106b_
{
	meta:
		description = "ASPack v1.06b"
	strings:
		$0 = {90 90 90 75 00 E9}
		$1 = {90 75 00 E9}
		$2 = {90 90 75 00 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _EXE32Pack_v138_
{
	meta:
		description = "EXE32Pack v1.38"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D 40}
	condition:
		$0 at entrypoint
}
rule _Turbo_C_1987_or_Borland_Cpp_1991_
{
	meta:
		description = "Turbo C 1987 or Borland C++ 1991"
	strings:
		$0 = {FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21}
	condition:
		$0 at entrypoint
}
rule _ExeSmasher_vxx_
{
	meta:
		description = "ExeSmasher vx.x"
	strings:
		$0 = {9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10}
	condition:
		$0 at entrypoint
}
rule _Krypton_v02_
{
	meta:
		description = "Krypton v0.2"
	strings:
		$0 = {8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_60_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0)"
	strings:
		$0 = {03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE}
		$1 = {03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE}
		$2 = {F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? ?? BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68}
		$3 = {91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00}
		$4 = {03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3}
		$5 = {E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8}
		$6 = {EB 02 AB 35 EB 02 B5 C6 8D 05 80 ?? ?? 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8}
		$7 = {D1 E9 03 C0 68 80 ?? ?? 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E}
		$8 = {C1 CE 10 C1 F6 0F 68 00 ?? ?? 00 2B FA 5B 23 F9 8D 15 80 ?? ?? 00 E8 01 00 00 00 B6 5E 0B}
		$9 = {EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38}
		$10 = {EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint or $5 at entrypoint or $6 at entrypoint or $7 at entrypoint or $8 at entrypoint or $9 at entrypoint or $10 at entrypoint
}
rule _kryptor_5_
{
	meta:
		description = "kryptor 5"
	strings:
		$0 = {E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0}
	condition:
		$0 at entrypoint
}
rule _JDPack_V200__JDPack_
{
	meta:
		description = "JDPack V2.00 -> JDPack"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? 05 00 00 00 00 83 C4 0C 5D 60 E8 00 00 00 00 5D 8B D5 64 FF 35 00 00 00 00 EB}
	condition:
		$0 at entrypoint
}
rule _SVKProtector_v132_
{
	meta:
		description = "SVK-Protector v1.32"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23}
	condition:
		$0 at entrypoint
}
rule _Upack_020_beta__Dwing_
{
	meta:
		description = "Upack 0.20 beta -> Dwing"
	strings:
		$0 = {BE 88 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_VOB_ProtectCD_5__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [VOB ProtectCD 5] --> Anorganix"
	strings:
		$0 = {36 3E 26 8A C0 60 E8 00 00 00 00}
		$1 = {36 3E 26 8A C0 60 E8 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ThemidaWinLicense_V1000V1800_Oreans_Technologies_
{
	meta:
		description = "Themida/WinLicense V1.0.0.0-V1.8.0.0-> Oreans Technologies"
	strings:
		$0 = {B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _EmbedPE_113__cyclotron_
{
	meta:
		description = "EmbedPE 1.13 -> cyclotron"
	strings:
		$0 = {83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33}
		$1 = {83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _EXE_Stealth_v271_
{
	meta:
		description = "EXE Stealth v2.71"
	strings:
		$0 = {EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v42_DLL_
{
	meta:
		description = "Microsoft Visual C++ v4.2 DLL"
	strings:
		$0 = {53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75}
	condition:
		$0 at entrypoint
}
rule _RLPack_Full_Edition_117_aPLib__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 [aPLib] -> Ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 74 1F 00 00 8D 9D 1E 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Basic__MASM32_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual Basic / MASM32)"
	strings:
		$0 = {EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47}
	condition:
		$0 at entrypoint
}
rule _MoleBox_V2X__MoleStudiocom_
{
	meta:
		description = "MoleBox V2.X -> MoleStudio.com"
	strings:
		$0 = {E8 00 00 00 00 60 E8 4F 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Reflexive_Arcade_Wrapper_
{
	meta:
		description = "Reflexive Arcade Wrapper"
	strings:
		$0 = {55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8}
	condition:
		$0 at entrypoint
}
rule _PC_PE_Encryptor_Alpha_preview_
{
	meta:
		description = "PC PE Encryptor Alpha preview"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 00 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84}
	condition:
		$0 at entrypoint
}
rule _yodas_Protector_v101__Ashkbiz_Danehkar_h_
{
	meta:
		description = "yoda's Protector v1.01 -> Ashkbiz Danehkar (h)"
	strings:
		$0 = {55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Crunch_v40_
{
	meta:
		description = "Crunch v4.0"
	strings:
		$0 = {EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24}
		$1 = {EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Copy_Protector_v20_
{
	meta:
		description = "Copy Protector v2.0"
	strings:
		$0 = {2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F}
	condition:
		$0 at entrypoint
}
rule _North_Star_PE_Shrinker_13__Liuxingping_
{
	meta:
		description = "North Star PE Shrinker 1.3 -> Liuxingping"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5}
	condition:
		$0 at entrypoint
}
rule _dUP_2x_Patcher__wwwdiablo2oo2cjbnet_
{
	meta:
		description = "dUP 2.x Patcher --> www.diablo2oo2.cjb.net"
	strings:
		$0 = {8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9}
	condition:
		$0
}
rule _ASProtect_SKE_21x_exe__Alexey_Solodovnikov_h_
{
	meta:
		description = "ASProtect SKE 2.1x (exe) -> Alexey Solodovnikov (h)"
	strings:
		$0 = {90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$1 = {90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 or $1
}
rule _WinUpack_v039_final__By_Dwing_c2005_h1_
{
	meta:
		description = "WinUpack v0.39 final -> By Dwing (c)2005 (h1)"
	strings:
		$0 = {BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_DxPack_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [DxPack 1.0] --> Anorganix"
	strings:
		$0 = {60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00}
		$1 = {60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Upack_Patch_or_any_Version__Sign_by_hot_UNP_
{
	meta:
		description = "Upack_Patch or any Version -> Sign by hot_UNP"
	strings:
		$0 = {60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02}
	condition:
		$0 at entrypoint
}
rule _CrunchPE_v40_
{
	meta:
		description = "Crunch/PE v4.0"
	strings:
		$0 = {EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 E9 06 ?? ?? 89 85 E1 06 ?? ?? FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24}
	condition:
		$0
}
rule _Wise_Installer_Stub_v11010291_
{
	meta:
		description = "Wise Installer Stub v1.10.1029.1"
	strings:
		$0 = {55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45}
	condition:
		$0 at entrypoint
}
rule _PKTINY_v10_with_TINYPROG_v38_
{
	meta:
		description = "PKTINY v1.0 with TINYPROG v3.8"
	strings:
		$0 = {2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? E9 ?? ?? E8 ?? ?? 83}
	condition:
		$0 at entrypoint
}
rule _nBinder_v40_
{
	meta:
		description = "nBinder v4.0"
	strings:
		$0 = {5C 6E 62 34 5F 74 6D 70 5F 30 31 33 32 34 35 34 33 35 30 5C 00 00 00 00 00 00 00 00 00 E9 55 43 4C FF 01 1A 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E 32 88 DB 0E A4 B8 DC 79}
	condition:
		$0
}
rule _Unknown_packer_08_
{
	meta:
		description = "Unknown packer (08)"
	strings:
		$0 = {8B C4 2D ?? ?? 24 00 8B F8 57 B9 ?? ?? BE ?? ?? F3 A5 FD C3 97 4F 4F}
	condition:
		$0 at entrypoint
}
rule _ESO_Eclipse_Operating_System_v208_p_DOS_Extender_
{
	meta:
		description = "E.S.O. Eclipse Operating System v.2.08 + DOS Extender"
	strings:
		$0 = {8C C8 8E D8 BA ?? ?? E8 ?? ?? BB ?? ?? 8C C0 2B D8 B4 4A CD 21 BA ?? ?? 73 ?? E9}
	condition:
		$0 at entrypoint
}
rule _WARNING__TROJAN__ADinjector_
{
	meta:
		description = "WARNING -> TROJAN -> ADinjector"
	strings:
		$0 = {90 61 BE 00 20 44 00 8D BE 00 F0 FB FF C7 87 9C E0 04 00 6A F0 8A 5E 57 83 CD FF EB 0E}
	condition:
		$0 at entrypoint
}
rule _PESpin_v01__Cyberbob_
{
	meta:
		description = "PESpin v0.1 -> Cyberbob"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF}
	condition:
		$0 at entrypoint
}
rule _UPX_v0896__v102__v105__v122_Modified_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 Modified"
	strings:
		$0 = {01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75}
	condition:
		$0 at entrypoint
}
rule _EXE2COM_Method_1_
{
	meta:
		description = "EXE2COM (Method 1)"
	strings:
		$0 = {8C DB BE ?? ?? 8B C6 B1 ?? D3 E8 03 C3 03 ?? ?? A3 ?? ?? 8C C8 05 ?? ?? A3}
	condition:
		$0 at entrypoint
}
rule _PKLITE32_11__PKWARE_Inc_
{
	meta:
		description = "PKLITE32 1.1 -> PKWARE Inc."
	strings:
		$0 = {68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 00 00 00 00 E8 ?? ?? ?? ?? E9}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v310_
{
	meta:
		description = "Armadillo v3.10"
	strings:
		$0 = {55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1}
		$1 = {55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _RCryptor_v16x__Vaska_
{
	meta:
		description = "RCryptor v1.6x --> Vaska"
	strings:
		$0 = {60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _VcasmProtector_11__12__vcasm_
{
	meta:
		description = "Vcasm-Protector 1.1 - 1.2 -> vcasm"
	strings:
		$0 = {EB 0B 5B 56 50 72 6F 74 65 63 74 5D}
	condition:
		$0 at entrypoint
}
rule _UPXSCRAMBLER_306__OnToL_
{
	meta:
		description = "UPX-SCRAMBLER 3.06 -> ㎡nT畂L"
	strings:
		$0 = {E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6}
	condition:
		$0 at entrypoint
}
rule _Petite_22__c199899_Ian_Luck_h_
{
	meta:
		description = "Petite 2.2 -> (c)1998-99 Ian Luck (h)"
	strings:
		$0 = {68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66}
	condition:
		$0 at entrypoint
}
rule _Simple_UPX_Cryptor_v3042005_One_layer_encryption__MANtiCORE_
{
	meta:
		description = "Simple UPX Cryptor v30.4.2005 [One layer encryption] --> MANtiCORE"
	strings:
		$0 = {60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3}
	condition:
		$0 at entrypoint
}
rule _VBOX_v43__v46_
{
	meta:
		description = "VBOX v4.3 - v4.6"
	strings:
		$0 = {8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5}
		$1 = {90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 ?? ?? 2B C5 48 ?? ?? 0B C0 86 E0 8C E0 ?? ?? 8C E0 86 E0 03 C4 40}
	condition:
		$0 or $1
}
rule _PseudoSigner_01_PECompact_14p__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PECompact 1.4+] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Exe_Locker_v10__IonIce_
{
	meta:
		description = "Exe Locker v1.0 --> IonIce"
	strings:
		$0 = {E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00}
		$1 = {E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _tElock_v070_
{
	meta:
		description = "tElock v0.70"
	strings:
		$0 = {60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Microsoft_Visual_Cpp_620__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual C++ 6.20] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 55 8B EC 83 EC 50 53 56 57 BE 90 90 90 90 8D 7D F4 A5 A5 66 A5 8B}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 55 8B EC 83 EC 50 53 56 57 BE 90 90 90 90 8D 7D F4 A5 A5 66 A5 8B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v120__v1201_
{
	meta:
		description = "PECompact v1.20 - v1.20.1"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40}
	condition:
		$0 at entrypoint
}
rule _XPack_167_
{
	meta:
		description = "XPack 1.67"
	strings:
		$0 = {B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB}
	condition:
		$0 at entrypoint
}
rule _Native_UD_Packer_11_Modded_Poison_Ivy_Shellcode__okkixot_
{
	meta:
		description = "Native UD Packer 1.1 (Modded Poison Ivy Shellcode) -> okkixot"
	strings:
		$0 = {31 C0 31 DB 31 C9 EB 0E 6A 00 6A 00 6A 00 6A 00 FF 15 28 41 40 00 FF 15 94 40 40 00 89 C7 68 88 13 00 00 FF 15 98 40 40 00 FF 15 94 40 40 00 81 C7 88 13 00 00 39 F8 73 05 E9 84 00 00 00 6A 40 68 00 10 00 00 FF 35 04 30 40 00 6A 00 FF 15 A4 40 40 00 89 C7 FF 35 04 30 40 00 68 CA 10 40 00 50 FF 15 A8 40 40 00 6A 40 68 00 10 00 00 FF 35 08 30 40 00 6A 00 FF 15 A4 40 40 00 89 C6 68 00 30 40 00 FF 35 04 30 40 00 57 FF 35 08 30 40 00 50 6A 02 FF 15 4E 41 40 00 6A 00 6A 00 6A 00 56 6A 00 6A 00 FF 15 9C 40 40 00 50 6A 00 6A 00 6A 11 50 FF 15 4A 41 40 00 58 6A FF 50 FF 15 AC 40 40 00 6A 00 FF 15 A0 40}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v71_EXE_
{
	meta:
		description = "Microsoft Visual C++ v7.1 EXE"
	strings:
		$0 = {6A ?? 68 ?? ?? ?? 01 E8 ?? ?? 00 00 66 81 3D 00 00 00 01 4D 5A 75 ?? A1 3C 00 00 01 ?? ?? 00 00 00 01}
		$1 = {6A ?? 68 ?? ?? ?? ?? E8}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_PE_Intro_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PE Intro 1.0] --> Anorganix"
	strings:
		$0 = {8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9}
		$1 = {8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _HASP_HL_Protection_V1X__Aladdin_
{
	meta:
		description = "HASP HL Protection V1.X -> Aladdin"
	strings:
		$0 = {55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15}
	condition:
		$0 at entrypoint
}
rule _Go32Stub_v200_DOSExtender_
{
	meta:
		description = "Go32Stub v.2.00 DOS-Extender"
	strings:
		$0 = {0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 80}
	condition:
		$0 at entrypoint
}
rule _NTkrnl_Secure_Suite__NTkrnl_Team_Blue_
{
	meta:
		description = "NTkrnl Secure Suite -> NTkrnl Team (Blue)"
	strings:
		$0 = {68 29 19 43 00 E8 01 00 00 00 C3 C3 A2 A9 61 4E A5 0E C7 A6 59 90 6E 4D 4C DB 36 46 FB 6E C4 45 A3 C2 2E 0E 41 59 1A 50 17 39 62 4D B8 61 24 8E CF D1 0E 9E 7A 66 C0 8D 6B 9C 52 7E 96 46 80 AF}
	condition:
		$0
}
rule _PKLITE_v120_
{
	meta:
		description = "PKLITE v1.20"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 B4 4C CD 21}
	condition:
		$0 at entrypoint
}
rule _PCGuard_v405d_v410d_v415d_
{
	meta:
		description = "PC-Guard v4.05d, v4.10d, v4.15d"
	strings:
		$0 = {FC 55 50 E8 00 00 00 00 5D EB 01}
	condition:
		$0 at entrypoint
}
rule _MEW_11_SE_v11___Northfox_HCC_
{
	meta:
		description = "MEW 11 SE v1.1  -> Northfox [HCC]"
	strings:
		$0 = {E9 ?? ?? ?? FF 0C}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_FSG_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [FSG 1.0] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_Yodas_Protector_102__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Yoda's Protector 1.02] --> Anorganix"
	strings:
		$0 = {E8 03 00 00 00 EB 01 90 90 E9}
		$1 = {E8 03 00 00 00 EB 01 90 90 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ExeLock_v100_
{
	meta:
		description = "ExeLock v1.00"
	strings:
		$0 = {06 8C C8 8E C0 BE ?? ?? 26 ?? ?? 34 ?? 26 ?? ?? 46 81 ?? ?? ?? 75 ?? 40 B3 ?? B3 ?? F3}
	condition:
		$0 at entrypoint
}
rule _Themida__Oreans_Technologies_2004_
{
	meta:
		description = "Themida -> Oreans Technologies 2004"
	strings:
		$0 = {B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8}
	condition:
		$0 at entrypoint
}
rule _Turbo_or_Borland_Pascal_v70_
{
	meta:
		description = "Turbo or Borland Pascal v7.0"
	strings:
		$0 = {9A ?? ?? ?? ?? C8 ?? ?? ?? 9A ?? ?? ?? ?? 09 C0 75 ?? EB ?? 8D ?? ?? ?? 16 57 6A ?? 9A ?? ?? ?? ?? BF ?? ?? 1E 57 68}
	condition:
		$0 at entrypoint
}
rule _Mew_10_execoder_10__Northfox_HCC_
{
	meta:
		description = "Mew 10 exe-coder 1.0 -> Northfox [HCC]"
	strings:
		$0 = {33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70}
	condition:
		$0 at entrypoint
}
rule _TASM__MASM_
{
	meta:
		description = "TASM / MASM"
	strings:
		$0 = {6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00}
	condition:
		$0 at entrypoint
}
rule _BeRoEXEPacker_v100_LZBRS__BeRo__Farbrausch_
{
	meta:
		description = "BeRoEXEPacker v1.00 [LZBRS] -> BeRo / Farbrausch"
	strings:
		$0 = {60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33}
	condition:
		$0 at entrypoint
}
rule _KGCrypt_vxx_
{
	meta:
		description = "KGCrypt vx.x"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 64 A1 30 ?? ?? ?? 84 C0 74 ?? 64 A1 20 ?? ?? ?? 0B C0 74}
	condition:
		$0 at entrypoint
}
rule _Apex_c_beta__500mhz_
{
	meta:
		description = "Apex_c beta -> 500mhz"
	strings:
		$0 = {68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$1 = {68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v12_
{
	meta:
		description = "FSG v1.2"
	strings:
		$0 = {4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00}
		$1 = {4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _nSpack_V13__LiuXingPing_
{
	meta:
		description = "nSpack V1.3 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00}
	condition:
		$0 at entrypoint
}
rule _ORiEN_v211_DEMO_
{
	meta:
		description = "ORiEN v2.11 (DEMO)"
	strings:
		$0 = {E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F}
	condition:
		$0 at entrypoint
}
rule _Unknown_packer_06_
{
	meta:
		description = "Unknown packer (06)"
	strings:
		$0 = {FA B8 ?? ?? BE ?? ?? 33 F0 0E 17 2E ?? ?? ?? BA ?? ?? 87 E6 5B 33 DC}
	condition:
		$0 at entrypoint
}
rule _Private_EXE_Protector_20__SetiSoft_
{
	meta:
		description = "Private EXE Protector 2.0 -> SetiSoft"
	strings:
		$0 = {89 ?? ?? 38 00 00 00 8B ?? 00 00 00 00 81 ?? ?? ?? ?? ?? 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF}
	condition:
		$0
}
rule _Turbo_Pascal_v20_1984_
{
	meta:
		description = "Turbo Pascal v2.0 1984"
	strings:
		$0 = {90 90 CD AB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 34}
	condition:
		$0 at entrypoint
}
rule _COP_v10_c_1988_
{
	meta:
		description = "COP v1.0 (c) 1988"
	strings:
		$0 = {BF ?? ?? BE ?? ?? B9 ?? ?? AC 32 ?? ?? ?? AA E2 ?? 8B ?? ?? ?? EB ?? 90}
	condition:
		$0 at entrypoint
}
rule _y0das_Crypter_v12_
{
	meta:
		description = "y0da's Crypter v1.2"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC}
	condition:
		$0 at entrypoint
}
rule _TXT2COM_ReadAMatic_v10_
{
	meta:
		description = "TXT2COM (Read-A-Matic v1.0)"
	strings:
		$0 = {B8 ?? ?? 8E D8 8C 06 ?? ?? FA 8E D0 BC ?? ?? FB B4 ?? CD 21 A3 ?? ?? 06 50 B4 34 CD 21}
	condition:
		$0 at entrypoint
}
rule _Cruncher_v10_
{
	meta:
		description = "Cruncher v1.0"
	strings:
		$0 = {2E ?? ?? ?? ?? 2E ?? ?? ?? B4 30 CD 21 3C 03 73 ?? BB ?? ?? 8E DB 8D ?? ?? ?? B4 09 CD 21 06 33 C0 50 CB}
	condition:
		$0 at entrypoint
}
rule _Vx_Doom666_
{
	meta:
		description = "Vx: Doom.666"
	strings:
		$0 = {E8 ?? ?? ?? 5E 83 EE ?? B8 CF 7B CD 21 3D CF 7B ?? ?? 0E 1F 81 C6 ?? ?? BF ?? ?? B9 ?? ?? FC F3 A4 06 1F 06 B8 ?? ?? 50 CB B4 48 BB 2C 00 CD 21}
	condition:
		$0 at entrypoint
}
rule _Free_Pascal_v09910_
{
	meta:
		description = "Free Pascal v0.99.10"
	strings:
		$0 = {E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt32_v102_
{
	meta:
		description = "PE Crypt32 v1.02"
	strings:
		$0 = {E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21}
	condition:
		$0 at entrypoint
}
rule _EXE32Pack_v139_
{
	meta:
		description = "EXE32Pack v1.39"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40}
	condition:
		$0 at entrypoint
}
rule _MEW_5_10__Northfox_
{
	meta:
		description = "MEW 5 1.0 -> Northfox"
	strings:
		$0 = {BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0}
	condition:
		$0 at entrypoint
}
rule _Krypton_v05_
{
	meta:
		description = "Krypton v0.5"
	strings:
		$0 = {54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF}
	condition:
		$0 at entrypoint
}
rule _EP_v20_
{
	meta:
		description = "EP v2.0"
	strings:
		$0 = {6A ?? 60 E9 01 01}
	condition:
		$0 at entrypoint
}
rule _PEMangle_
{
	meta:
		description = "PEMangle"
	strings:
		$0 = {60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3}
	condition:
		$0 at entrypoint
}
rule _NFO_v1x_modified_
{
	meta:
		description = "NFO v1.x modified"
	strings:
		$0 = {60 9C 8D 50}
	condition:
		$0 at entrypoint
}
rule _Obsidium_V1304__Obsidium_Software_
{
	meta:
		description = "Obsidium V1.3.0.4 -> Obsidium Software"
	strings:
		$0 = {EB 02 ?? ?? E8 ?? 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_PE_Pack_099__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PE Pack 0.99] --> Anorganix"
	strings:
		$0 = {60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A}
		$1 = {60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Exe_Shield_v27_
{
	meta:
		description = "Exe Shield v2.7"
	strings:
		$0 = {EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00}
	condition:
		$0 at entrypoint
}
rule _WWPack32_v1x_
{
	meta:
		description = "WWPack32 v1.x"
	strings:
		$0 = {53 55 8B E8 33 DB EB 60}
	condition:
		$0 at entrypoint
}
rule _Morphine_v33__Silent_Software__Silent_Shield_c2005_
{
	meta:
		description = "Morphine v3.3 -> Silent Software & Silent Shield (c)2005"
	strings:
		$0 = {28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41}
	condition:
		$0
}
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_50__60_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 5.0 / 6.0)"
	strings:
		$0 = {33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB}
	condition:
		$0 at entrypoint
}
rule _Themida_1201__Oreans_Technologies_h_
{
	meta:
		description = "Themida 1.2.0.1 -> Oreans Technologies (h)"
	strings:
		$0 = {8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25}
	condition:
		$0
}
rule _SPLayer_v008_
{
	meta:
		description = "SPLayer v0.08"
	strings:
		$0 = {8D 40 00 B9 ?? ?? ?? ?? 6A ?? 58 C0 0C ?? ?? 48 ?? ?? 66 13 F0 91 3B D9 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00}
	condition:
		$0
}
rule _PKLITE_v100c_1_
{
	meta:
		description = "PKLITE v1.00c (1)"
	strings:
		$0 = {2E 8C 1E ?? ?? 8B 1E ?? ?? 8C DA 81 C2 ?? ?? 3B DA 72 ?? 81 EB ?? ?? 83 EB ?? FA 8E D3 BC ?? ?? FB FD BE ?? ?? 8B FE}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_60__70_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)"
	strings:
		$0 = {0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27}
		$1 = {0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27}
		$2 = {0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00}
		$3 = {F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80}
		$4 = {87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3}
		$5 = {F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68}
		$6 = {87 FE ?? 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00}
		$7 = {EB 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint or $5 at entrypoint or $6 at entrypoint or $7 at entrypoint
}
rule _SDProtect__Randy_Li_
{
	meta:
		description = "SDProtect -> Randy Li"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v190b2_
{
	meta:
		description = "Armadillo v1.90b2"
	strings:
		$0 = {55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASPack_v211_
{
	meta:
		description = "ASPack v2.11"
	strings:
		$0 = {60 E9 3D 04 00 00}
	condition:
		$0 at entrypoint
}
rule _tElock_v099_
{
	meta:
		description = "tElock v0.99"
	strings:
		$0 = {E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 02 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? 02 00 00}
	condition:
		$0 at entrypoint
}
rule _UPX_v071_DLL_
{
	meta:
		description = "UPX v0.71 [DLL]"
	strings:
		$0 = {80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83}
	condition:
		$0 at entrypoint
}
rule _DBPE_v233_
{
	meta:
		description = "DBPE v2.33"
	strings:
		$0 = {EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71}
	condition:
		$0 at entrypoint
}
rule _FASM_v15x_
{
	meta:
		description = "FASM v1.5x"
	strings:
		$0 = {6A 00 FF 15 ?? ?? 40 00 A3 ?? ?? 40 00}
	condition:
		$0
}
rule _PseudoSigner_02_PEX_099__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PEX 0.99] --> Anorganix"
	strings:
		$0 = {60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01}
		$1 = {60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _InstallAnywhere_61_Zero_G_Software_Inc_
{
	meta:
		description = "InstallAnywhere 6.1 ->Zero G Software Inc"
	strings:
		$0 = {60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07}
	condition:
		$0 at entrypoint
}
rule _PeCompact_2xx__BitSum_Technologies_
{
	meta:
		description = "PeCompact 2.xx --> BitSum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00}
	condition:
		$0 at entrypoint
}
rule _PESHiELD_v01b_MTE_
{
	meta:
		description = "PESHiELD v0.1b MTE"
	strings:
		$0 = {E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B9 1B 01 ?? ?? D1}
	condition:
		$0 at entrypoint
}
rule _CC_v261_Beta_
{
	meta:
		description = "CC v2.61 Beta"
	strings:
		$0 = {BA ?? ?? B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB}
	condition:
		$0 at entrypoint
}
rule _eXpressor_v12__CGSoftLabs_
{
	meta:
		description = "eXpressor v1.2 -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76}
	condition:
		$0 at entrypoint
}
rule _Safe_20_
{
	meta:
		description = "Safe 2.0"
	strings:
		$0 = {83 EC 10 53 56 57 E8 C4 01 00}
	condition:
		$0
}
rule _Microsoft_Visual_Cpp_60_DLL_
{
	meta:
		description = "Microsoft Visual C++ 6.0 DLL"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 75 09 83 3D ?? ?? ?? ?? ?? EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 15 FF FF FF 85 C0 75 04 33 C0 EB 4E}
	condition:
		$0
}
rule _EPW_v130_
{
	meta:
		description = "EPW v1.30"
	strings:
		$0 = {06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E}
	condition:
		$0 at entrypoint
}
rule _PEQuake_V006__forgat_
{
	meta:
		description = "PEQuake V0.06 -> forgat"
	strings:
		$0 = {E8 A5 00 00 00}
	condition:
		$0 at entrypoint
}
rule _DEF_v10_
{
	meta:
		description = "DEF v1.0"
	strings:
		$0 = {BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? 10 40 00 C3}
		$1 = {BE ?? 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46}
	condition:
		$0 or $1 at entrypoint
}
rule _MSLRH_v032a__emadicius_
{
	meta:
		description = "[MSLRH] v0.32a -> emadicius"
	strings:
		$0 = {EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03}
	condition:
		$0
}
rule _ASProtect_v11_MTE_
{
	meta:
		description = "ASProtect v1.1 MTE"
	strings:
		$0 = {60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9}
	condition:
		$0 at entrypoint
}
rule _BlackEnergy_DDoS_Bot_Crypter_
{
	meta:
		description = "BlackEnergy DDoS Bot Crypter"
	strings:
		$0 = {55 ?? ?? 81 EC 1C 01 00 00 53 56 57 6A 04 BE 00 30 00 00 56 FF 35 00 20 11 13 6A 00 E8 ?? 03 00 00 ?? ?? 83 C4 10 ?? FF 89 7D F4 0F}
	condition:
		$0 at entrypoint
}
rule _PKLITE_v112_v115_v120_1_
{
	meta:
		description = "PKLITE v1.12, v1.15, v1.20 (1)"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 73 ?? 2D ?? ?? FA 8E D0 FB 2D ?? ?? 8E C0 50 B9 ?? ?? 33 FF 57 BE ?? ?? FC F3 A5 CB B4 09 BA ?? ?? CD 21 CD 20}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v302_v302a_Extractable_
{
	meta:
		description = "WWPACK v3.02, v3.02a (Extractable)"
	strings:
		$0 = {B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Borland_Cpp_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland C++)"
	strings:
		$0 = {23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA}
		$1 = {23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA}
		$2 = {23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _MEGALITE_v120a_
{
	meta:
		description = "MEGALITE v1.20a"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 2D 73 ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 90}
	condition:
		$0 at entrypoint
}
rule _ZipWorxSecureEXE_v25__ZipWORX_Technologies_LLC_h_
{
	meta:
		description = "ZipWorxSecureEXE v2.5 -> ZipWORX Technologies LLC (h)"
	strings:
		$0 = {E9 B8 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v71_DLL_Debug_
{
	meta:
		description = "Microsoft Visual C++ v7.1 DLL (Debug)"
	strings:
		$0 = {55 8B EC ?? ?? 0C 83 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 8B}
	condition:
		$0 at entrypoint
}
rule _Freshbind_v20__gFresh_
{
	meta:
		description = "Freshbind v2.0 -> gFresh"
	strings:
		$0 = {64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00}
	condition:
		$0 at entrypoint
}
rule _Shrinker_34_
{
	meta:
		description = "Shrinker 3.4"
	strings:
		$0 = {55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04}
	condition:
		$0
}
rule _DJoin_v07_public_RC4_encryption__drmist_
{
	meta:
		description = "DJoin v0.7 public (RC4 encryption) -> drmist"
	strings:
		$0 = {C6 05 ?? ?? 40 00 00 C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _EncryptPE_22004810__22005314__WFS_
{
	meta:
		description = "EncryptPE 2.2004.8.10 - 2.2005.3.14 -> WFS"
	strings:
		$0 = {60 9C 64 FF 35 00 00 00 00 E8 7A}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b2_
{
	meta:
		description = "PECompact v1.10b2"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60}
	condition:
		$0 at entrypoint
}
rule _Embed_PE_v113__cyclotron_
{
	meta:
		description = "Embed PE v1.13 -> cyclotron"
	strings:
		$0 = {83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68}
	condition:
		$0 at entrypoint
}
rule _Unknown_encryptor_1_
{
	meta:
		description = "Unknown encryptor (1)"
	strings:
		$0 = {EB ?? 2E 90 ?? ?? 8C DB 8C CA 8E DA FA 8B EC BE ?? ?? BC ?? ?? BF}
	condition:
		$0 at entrypoint
}
rule _Watcom_CCpp_
{
	meta:
		description = "Watcom C/C++"
	strings:
		$0 = {E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20}
	condition:
		$0
}
rule _DEF_10__bartxt_
{
	meta:
		description = "DEF 1.0 -> bart/xt"
	strings:
		$0 = {BE ?? ?? 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$1 = {BE ?? ?? 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _bambam_V001__bedrock_
{
	meta:
		description = "bambam V0.01 -> bedrock"
	strings:
		$0 = {6A 14 E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF}
	condition:
		$0 at entrypoint
}
rule _Unknown_Protected_Mode_compiler_2_
{
	meta:
		description = "Unknown Protected Mode compiler (2)"
	strings:
		$0 = {FA FC 0E 1F E8 ?? ?? 8C C0 66 0F B7 C0 66 C1 E0 ?? 66 67 A3}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_ASProtect__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [ASProtect] --> Anorganix"
	strings:
		$0 = {60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9}
		$1 = {60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _SafeDiscSafeCast_2xx__3xx__Macrovision_
{
	meta:
		description = "SafeDisc/SafeCast 2.xx - 3.xx -> Macrovision"
	strings:
		$0 = {55 8B EC 60 BB ?? ?? ?? ?? 33 C9 8A 0D 3D ?? ?? ?? 85 C9 74 0C B8 ?? ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 ?? ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 09 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 76 00 00 00 83 C4 08 59 83 F8 00 74 1C C6 03 C2 C6 43 01 0C 85 C9 74 09 61 5D B8 00 00 00 00 EB 97 50 A1 29 ?? ?? ?? ?? D0 61 5D EB 46 80 7C 24 08 00 75 3F 51 8B 4C 24 04 89 0D ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 4C 24 04 59 EB 28 50 B8 2D ?? ?? ?? ?? 70 08 8B 40 0C FF D0 B8 2D ?? ?? ?? ?? 30 8B 40 04 FF D0 58 FF 35 ?? ?? ?? ?? C3 72 16 61 13 60 0D E9 ?? ?? ?? ?? CC CC 81 EC E8 02 00 00 53 55 56 57}
	condition:
		$0 at entrypoint
}
rule _COMPACK_v51_
{
	meta:
		description = "COMPACK v5.1"
	strings:
		$0 = {BD ?? ?? 50 06 8C CB 03 DD 8C D2 4B 8E DB BE ?? ?? BF ?? ?? 8E C2 B9 ?? ?? F3 A5 4A 4D 75 ?? 8B F7 8E DA 0E 07 06 16}
	condition:
		$0 at entrypoint
}
rule _PEncrypt_v30_
{
	meta:
		description = "PEncrypt v3.0"
	strings:
		$0 = {E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB ?? ?? ?? ?? AD 33 C3 E2 FA}
	condition:
		$0 at entrypoint
}
rule _WATCOM_CCpp_32_RunTime_System_19881994_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1994"
	strings:
		$0 = {FB 83 ?? ?? 89 E3 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 29 C0 B4 30 CD 21}
	condition:
		$0 at entrypoint
}
rule _Silicon_Realms_Install_Stub_
{
	meta:
		description = "Silicon Realms Install Stub"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3}
	condition:
		$0
}
rule _Microsoft_CAB_SFX_
{
	meta:
		description = "Microsoft CAB SFX"
	strings:
		$0 = {E8 0A 00 00 00 E9 7A FF FF FF CC CC CC CC CC}
	condition:
		$0 at entrypoint
}
rule _MicroJoiner_15__coban2k_
{
	meta:
		description = "MicroJoiner 1.5 -> coban2k"
	strings:
		$0 = {BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_30_old_crap_
{
	meta:
		description = "Microsoft Visual C++ (3.0 old crap)"
	strings:
		$0 = {64 A1 00 00 00 00 55 ?? ?? 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00 00 83 EC 10}
	condition:
		$0 at entrypoint
}
rule _tElock_v051_
{
	meta:
		description = "tElock v0.51"
	strings:
		$0 = {C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08}
	condition:
		$0 at entrypoint
}
rule _UPXFreak_v01_Borland_Delphi__HMX0101_
{
	meta:
		description = "UPXFreak v0.1 (Borland Delphi) -> HMX0101"
	strings:
		$0 = {BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_224__StrongbitSoftComplete_Development_h3_
{
	meta:
		description = "EXECryptor 2.2.4 -> Strongbit/SoftComplete Development (h3)"
	strings:
		$0 = {6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73}
		$1 = {6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73}
	condition:
		$0 or $1
}
rule _Unknown_packer_05_
{
	meta:
		description = "Unknown packer (05)"
	strings:
		$0 = {FA BB ?? ?? B9 ?? ?? 87 E5 87 27 03 E3 91 8A CB 80 E1 ?? D3 C4 91 33 E3 87 27}
	condition:
		$0 at entrypoint
}
rule _Setup_Factory_v6003_Setup_Launcher_
{
	meta:
		description = "Setup Factory v6.0.0.3 Setup Launcher"
	strings:
		$0 = {55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89}
	condition:
		$0
}
rule _Enigma_protector_110_unregistered_
{
	meta:
		description = "Enigma protector 1.10 (unregistered)"
	strings:
		$0 = {60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89}
		$1 = {60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89}
	condition:
		$0 or $1
}
rule _InstallShield_Custom_
{
	meta:
		description = "InstallShield Custom"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 ?? ?? 41 00 8B F0 85 F6 75 08 6A FF FF 15 ?? ?? 41 00 8A 06 57 8B 3D ?? ?? 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B}
	condition:
		$0 at entrypoint
}
rule _CrunchPE_
{
	meta:
		description = "Crunch/PE"
	strings:
		$0 = {55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85}
	condition:
		$0 at entrypoint
}
rule _SCRAM_vC5_
{
	meta:
		description = "SCRAM! vC5"
	strings:
		$0 = {B8 ?? ?? 50 9D 9C 58 25 ?? ?? 75 ?? BA ?? ?? B4 09 CD 21 CD 20}
	condition:
		$0 at entrypoint
}
rule _Inno_Setup_Module_v129_
{
	meta:
		description = "Inno Setup Module v1.2.9"
	strings:
		$0 = {55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0}
	condition:
		$0 at entrypoint
}
rule _tElock_v071b7_
{
	meta:
		description = "tElock v0.71b7"
	strings:
		$0 = {60 E8 48 11 00 00 C3 83}
	condition:
		$0 at entrypoint
}
rule _Exe_Shield_v27b_
{
	meta:
		description = "Exe Shield v2.7b"
	strings:
		$0 = {EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40}
		$1 = {EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_UPX_06__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [UPX 0.6] --> Anorganix"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9}
		$1 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Shrinker_v34_
{
	meta:
		description = "Shrinker v3.4"
	strings:
		$0 = {83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF}
		$1 = {BB ?? ?? BA ?? ?? 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Enigma_protector_110111__Vladimir_Sukhov_
{
	meta:
		description = "Enigma protector 1.10/1.11 -> Vladimir Sukhov"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31}
	condition:
		$0
}
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_60__ASM_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / ASM)"
	strings:
		$0 = {F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68}
	condition:
		$0 at entrypoint
}
rule _PE_Protector_093__CRYPToCRACk_
{
	meta:
		description = "PE Protector 0.9.3 --> CRYPToCRACk"
	strings:
		$0 = {5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00}
	condition:
		$0 at entrypoint
}
rule _Vx_Phoenix927_
{
	meta:
		description = "Vx: Phoenix.927"
	strings:
		$0 = {E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8}
	condition:
		$0 at entrypoint
}
rule _LamerStop_v10c_c_Stefan_Esser_
{
	meta:
		description = "LamerStop v1.0c (c) Stefan Esser"
	strings:
		$0 = {E8 ?? ?? 05 ?? ?? CD 21 33 C0 8E C0 26 ?? ?? ?? 2E ?? ?? ?? 26 ?? ?? ?? 2E ?? ?? ?? BA ?? ?? FA}
	condition:
		$0 at entrypoint
}
rule _unknown__jac_
{
	meta:
		description = "unknown -> jac"
	strings:
		$0 = {55 89 E5 B9 00 80 00 00 BA ?? ?? ?? ?? B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 31 C2 66 01 C2 C1 C2 07 E2 F1 50 E8 91 FF FF FF C9 C3}
	condition:
		$0 at entrypoint
}
rule _tElock_v060_
{
	meta:
		description = "tElock v0.60"
	strings:
		$0 = {E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08}
	condition:
		$0 at entrypoint
}
rule _Goats_Mutilator_v16__Goat_e0f_
{
	meta:
		description = "Goats Mutilator v1.6 -> Goat/_e0f"
	strings:
		$0 = {E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D}
		$1 = {E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Packanoid_v1__Arkanoid_
{
	meta:
		description = "Packanoid v1 -> Arkanoid"
	strings:
		$0 = {BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 9D 00 00 00 B8 ?? ?? ?? ?? 8B 30 8B 78 04 BB ?? ?? ?? ?? 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08}
	condition:
		$0 at entrypoint
}
rule _Software_Compress_v14_LITE__BG_Software_Protect_Technologies_h_
{
	meta:
		description = "Software Compress v1.4 LITE -> BG Software Protect Technologies (h)"
	strings:
		$0 = {E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A 41 00 8B 4A 64 89 8D 51 1A 41 00 8B 4A 74 89 8D 59 1A 41 00 68 00 20 00 00 E8 D2 00 00 00 50 8D 8D 00 1C 41 00 50 51 E8 1B 00 00 00 83 C4 08 58 8D 78 74 8D B5 49 1A 41 00 B9 18 00 00 00 F3 A4 05 A4 00 00 00 50 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 4D 1A 41 00 89 44 24 1C 61 C2 04}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_CodeSafe_20__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [CodeSafe 2.0] --> Anorganix"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _VideoLanClient_
{
	meta:
		description = "Video-Lan-Client"
	strings:
		$0 = {55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF}
	condition:
		$0 at entrypoint
}
rule _eXPressor_v120b_
{
	meta:
		description = "eXPressor v1.2.0b"
	strings:
		$0 = {55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? 00 2B 05 84 ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 16 A1 ?? ?? ?? 00 03 05 80 ?? ?? 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 68 04}
	condition:
		$0
}
rule _Packman_V0001__Bubbasoft_
{
	meta:
		description = "Packman V0.0.0.1 -> Bubbasoft"
	strings:
		$0 = {60 E8 00 00 00 00 58 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? 48}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_MEW_11_SE_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [MEW 11 SE 1.0] --> Anorganix"
	strings:
		$0 = {E9 09 00 00 00 00 00 00 02 00 00 00 0C 90}
		$1 = {E9 09 00 00 00 00 00 00 02 00 00 00 0C 90}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PGMPACK_v013_
{
	meta:
		description = "PGMPACK v0.13"
	strings:
		$0 = {FA 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3}
	condition:
		$0 at entrypoint
}
rule _diPacker_V1X__diProtector_Software_
{
	meta:
		description = "diPacker V1.X -> diProtector Software"
	strings:
		$0 = {0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5}
	condition:
		$0 at entrypoint
}
rule _Vx_Explosion1000_
{
	meta:
		description = "Vx: Explosion.1000"
	strings:
		$0 = {E8 ?? ?? 5E 1E 06 50 81 ?? ?? ?? 56 FC B8 21 35 CD 21 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 26 ?? ?? ?? ?? ?? ?? 74 ?? 8C D8 48 8E D8}
	condition:
		$0 at entrypoint
}
rule _Protection_Plus_vxx_
{
	meta:
		description = "Protection Plus vx.x"
	strings:
		$0 = {50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 ?? ?? E8 DD ?? ?? ?? 89 85 1F 03 ?? ?? 6A 40 68 ?? 10 ?? ?? 8B 85}
	condition:
		$0 at entrypoint
}
rule _Microsoft_C_for_Windows_1_
{
	meta:
		description = "Microsoft C for Windows (1)"
	strings:
		$0 = {33 ED 55 9A ?? ?? ?? ?? 0B C0 74}
	condition:
		$0 at entrypoint
}
rule _CrunchPE_v10xx_
{
	meta:
		description = "Crunch/PE v1.0.x.x"
	strings:
		$0 = {55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 09 C6 85}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_PE_Protect_09__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PE Protect 0.9] --> Anorganix"
	strings:
		$0 = {52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9}
		$1 = {52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Exe_Shield_vxx_
{
	meta:
		description = "Exe Shield vx.x"
	strings:
		$0 = {65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00}
	condition:
		$0 at entrypoint
}
rule _VMProtect_v125__PolyTech_
{
	meta:
		description = "VMProtect v1.25 --> PolyTech"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 56 52 56 51 9C 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 A7 72 45 00 C3}
		$1 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 9C 52 56 53 56 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 21 71 45 00 C3}
		$2 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 56 52 56 51 9C 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 A7 72 45 00 C3}
		$3 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 9C 52 56 53 56 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 21 71 45 00 C3}
		$4 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 57 51 9C 50 52 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$5 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 53 9C 57 52 51 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$6 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 53 50 57 53 9C 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$7 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 9C 50 55 51 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$8 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 55 53 52 51 9C 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$9 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 55 52 9C 50 51 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$10 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 55 52 51 55 57 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$11 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 52 50 9C 51 55 54 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$12 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 9C 51 50 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$13 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 51 57 54 53 9C 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$14 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 50 51 57 50 52 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$15 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 57 52 50 51 51 9C 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$16 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 50 57 55 51 52 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$17 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 50 52 54 9C 53 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$18 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 56 53 51 55 9C 55 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9}
		$19 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 9C 56 53 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$20 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 53 56 55 50 9C 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$21 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 53 55 50 55 56 52 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$22 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 52 53 56 9C 55 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$23 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 53 52 50 51 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$24 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 52 53 55 52 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$25 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 51 55 52 51 57 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$26 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 52 55 51 53 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$27 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 53 54 51 55 56 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$28 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 52 53 56 57 9C 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9}
		$29 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 52 9C 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8A 06 8A 04 07 46 83 ED 02 66 89 45 00 E9}
		$30 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 53 50 51 51 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$31 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 51 57 53 56 54 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 8D 76 04 89 45 00 E9}
		$32 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 51 50 53 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$33 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 57 56 50 52 53 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$34 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 57 51 50 52 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$35 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 53 50 54 57 51 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$36 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 51 9C 56 53 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$37 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 50 56 51 52 53 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$38 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 50 52 53 52 51 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$39 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 51 55 56 53 52 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$40 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 9C 53 51 50 52 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$41 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 9C 51 56 53 52 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$42 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 51 53 57 52 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$43 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 57 53 57 55 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$44 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 55 50 57 51 53 9C 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9}
		$45 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 50 53 51 57 9C 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$46 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 52 9C 55 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$47 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 50 53 9C 57 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$48 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 9C 55 53 51 50 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$49 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 55 50 52 51 57 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$50 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 53 9C 51 57 52 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$51 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 52 9C 52 51 57 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9}
		$52 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 9C 57 52 50 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$53 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 53 54 57 55 50 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$54 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 55 51 53 50 52 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$55 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 51 56 52 50 9C 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$56 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 56 57 55 53 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$57 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 56 50 9C 53 50 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$58 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 54 53 9C 55 52 50 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$59 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 56 55 55 9C 50 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$60 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 52 51 57 55 9C 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 83 EE FC 83 ED 04 89 45 00 E9}
		$61 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 50 53 51 56 55 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$62 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 56 9C 56 53 55 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 06 8D 76 02 83 ED 02 66 89 45 00 E9}
		$63 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 56 57 55 52 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8A 06 83 ED 02 66 89 45 00 46 E9}
		$64 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 56 50 55 51 9C 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$65 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 54 55 51 50 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$66 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 50 9C 56 53 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$67 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 52 50 56 9C 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5A 5B 59 9D 5E 58 5F 5D 5F C3}
		$68 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 52 50 51 56 55 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$69 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 57 55 52 50 53 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$70 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 56 56 50 55 51 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$71 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E8 89 45 04 9C 8F 45 00 E9 01 7D 00 00}
		$72 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 55 52 54 50 51 53 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$73 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 57 53 55 56 50 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$74 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 52 9C 51 56 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$75 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 51 57 53 9C 52 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$76 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 56 52 53 55 53 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$77 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 53 56 52 51 50 9C 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9}
		$78 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 53 55 50 9C 55 56 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$79 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 9C 56 53 55 52 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$80 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 53 53 9C 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$81 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 57 56 55 56 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$82 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 57 56 52 55 50 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$83 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 50 53 53 52 57 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$84 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 51 56 52 56 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$85 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 52 57 50 57 51 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9}
		$86 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 51 9C 52 50 53 57 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$87 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 55 50 9C 51 57 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$88 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 57 53 52 9C 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$89 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 9C 57 50 53 55 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$90 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 55 9C 56 57 50 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$91 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 51 50 52 55 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$92 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 50 56 52 57 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$93 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 9C 56 50 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$94 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 55 9C 56 52 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8A 45 00 83 ED 02 00 45 04 9C 8F 45 00 E9}
		$95 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 51 56 57 50 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$96 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 53 50 52 56 55 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$97 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 56 57 53 55 51 52 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$98 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 53 51 57 9C 56 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$99 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 54 53 56 57 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$100 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 52 53 51 55 50 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 80 E0 3C 8B 14 07 83 ED 04 89 55 00 E9}
		$101 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 55 51 57 52 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$102 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 50 52 51 57 53 55 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 C6 04 89 45 00 E9}
		$103 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 55 52 51 56 57 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$104 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 57 55 53 51 52 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$105 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 55 56 52 56 51 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$106 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 51 9C 57 55 52 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$107 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 52 50 56 53 57 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$108 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 50 52 57 53 9C 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$109 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 51 9C 50 57 53 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9}
		$110 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 50 55 57 56 57 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$111 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 9C 51 56 51 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$112 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 50 55 52 56 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$113 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 50 52 57 56 51 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$114 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 52 51 9C 52 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$115 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 53 9C 54 55 51 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$116 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 52 50 56 56 9C 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$117 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 9C 57 51 55 55 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$118 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 57 9C 51 53 52 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$119 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 52 51 9C 53 53 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$120 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 9C 55 53 56 52 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 59 5B 5A 5E 58 5D 9D 58 5F C3}
		$121 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 9C 55 50 54 51 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$122 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 51 53 50 9C 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$123 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 52 53 56 50 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$124 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 51 53 55 51 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$125 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 51 52 55 51 50 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$126 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 51 53 55 56 50 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 8D 76 04 E9}
		$127 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 57 51 50 55 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$128 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 51 55 52 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$129 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 50 52 56 51 50 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5F 5B 5A 59 5E 5A 58 5D 9D C3}
		$130 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 55 56 56 57 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$131 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 51 52 55 52 50 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$132 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 57 53 52 55 51 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$133 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 56 53 57 52 51 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8A 06 46 83 ED 02 66 89 45 00 E9}
		$134 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 52 56 53 57 51 54 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$135 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 52 55 56 51 50 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$136 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 52 56 57 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$137 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 51 56 57 52 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$138 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 53 56 51 55 9C 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$139 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 53 50 56 53 51 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$140 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 56 55 56 9C 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$141 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 9C 52 50 57 56 53 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$142 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 51 50 55 53 56 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$143 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 9C 54 56 53 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$144 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 52 57 51 9C 53 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$145 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 55 52 9C 57 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$146 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 50 55 56 51 57 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$147 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 55 51 53 53 57 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$148 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 53 51 55 57 56 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$149 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 56 55 52 50 55 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$150 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 50 52 51 55 56 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$151 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 56 53 55 53 51 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$152 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 56 51 57 53 50 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$153 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 56 57 51 52 53 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9}
		$154 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 52 53 52 56 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$155 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 51 53 57 56 52 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$156 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 56 53 52 50 55 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 36 8A 02 66 89 45 00 E9}
		$157 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 55 57 53 56 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$158 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 57 53 51 52 55 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 5E 59 5D 5A 59 5B 5F 58 9D C3}
		$159 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 57 53 52 50 51 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$160 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 8A 4D 08 83 C5 02 0F A5 D0 89 45 04 9C 8F 45 00 E9}
		$161 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 8A 4D 08 83 C5 02 0F AD D0 89 45 04 9C 8F 45 00 E9}
		$162 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 47 50 39 C5 0F 87 ?? ?? ?? ?? 8D 4F 40 29 E1 8D 45 80 29 C8 89 C4 9C 56 89 FE 8D BD 40 FF FF FF 57 FC F3 A4 5F 5E 9D E9}
		$163 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 57 52 51 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$164 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 57 50 55 56 57 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$165 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 52 56 50 53 56 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 8D 76 04 89 45 00 E9}
		$166 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 57 55 56 51 50 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$167 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 55 50 52 9C 56 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$168 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 53 53 50 9C 52 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$169 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 52 53 50 9C 57 56 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$170 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 51 9C 56 50 57 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$171 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 9C 50 56 51 55 57 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$172 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 52 51 55 55 56 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$173 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 57 9C 56 50 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$174 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 52 53 51 55 9C 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9}
		$175 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 52 53 51 52 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$176 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 66 8B 55 02 F6 D0 F6 D2 83 ED 02 20 D0 66 89 45 04 9C 8F 45 00 E9}
		$177 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 8A 4D 02 83 ED 02 66 D3 E8 66 89 45 04 9C 8F 45 00 E9}
		$178 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 8A 4D 02 83 ED 02 66 D3 E0 66 89 45 04 9C 8F 45 00 E9}
		$179 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 52 53 55 55 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$180 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 51 9C 55 52 53 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$181 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 52 53 57 51 55 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$182 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 55 54 52 51 9C 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$183 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 51 52 55 57 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$184 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 56 50 51 53 52 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$185 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 56 53 57 51 52 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$186 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 55 51 9C 52 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9}
		$187 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 52 51 55 9C 50 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 0F B6 06 83 ED 02 46 66 89 45 00 E9}
		$188 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 53 9C 57 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 0F B6 06 66 98 98 46 83 ED 04 89 45 00 E9}
		$189 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 53 57 51 55 56 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$190 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 9C 50 56 51 55 54 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$191 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 55 50 9C 56 54 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$192 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 50 57 53 56 9C 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$193 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 50 53 56 51 9C 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$194 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 56 50 9C 55 53 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$195 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 52 50 56 57 51 9C 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$196 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 56 9C 56 53 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$197 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 56 53 55 57 9C 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 83 EE FC 89 45 00 E9}
		$198 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 53 9C 57 55 51 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$199 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 50 56 53 57 9C 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 59 5D 9D 5F 5A 5E 58 5B 5A C3}
		$200 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 50 55 51 56 9C 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$201 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 51 9C 53 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 C6 04 83 ED 04 89 45 00 E9}
		$202 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 56 51 50 9C 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$203 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 53 9C 50 50 56 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$204 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 50 53 51 56 55 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$205 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 51 53 52 57 55 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$206 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 51 51 9C 52 57 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9}
		$207 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 9C 56 53 55 57 54 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$208 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 9C 55 56 57 51 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$209 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 9C 50 51 57 53 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$210 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 9C 57 51 50 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$211 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 56 57 55 53 9C 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$212 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 53 51 50 9C 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$213 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 53 50 55 9C 57 51 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$214 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 55 57 53 9C 50 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$215 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 56 52 9C 50 53 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5F 5D 5B 58 9D 5A 5E 59 59 C3}
		$216 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 52 56 53 50 55 9C 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9}
		$217 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 50 55 56 53 9C 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$218 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 52 57 50 53 55 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$219 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 52 53 50 56 57 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$220 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 9C 50 53 56 51 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$221 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 52 9C 57 54 55 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$222 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 57 50 9C 56 52 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$223 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 53 57 50 52 50 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$224 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 9C 50 55 53 54 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$225 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 52 55 50 9C 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$226 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 56 53 55 57 9C 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$227 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 50 57 53 56 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$228 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 56 57 53 9C 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$229 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 56 9C 57 53 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$230 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 53 9C 55 51 54 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$231 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 53 50 57 9C 55 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 EC 5B 5E 5D 5D 9D 5F 58 5B 59 5A C3}
		$232 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 50 56 55 53 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$233 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 9C 55 53 51 56 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$234 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 56 50 52 57 57 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9}
		$235 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 53 53 56 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9}
		$236 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 53 50 52 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$237 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 53 51 9C 55 54 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$238 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 53 50 55 51 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$239 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 50 50 56 53 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$240 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 52 50 51 57 56 55 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$241 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 9C 56 50 51 55 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$242 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 56 51 50 9C 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$243 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 52 51 9C 57 53 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$244 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 56 51 52 50 55 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$245 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 53 56 51 57 55 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$246 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 9C 52 52 51 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$247 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 51 55 50 57 9C 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$248 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 9C 56 57 51 50 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$249 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 52 55 56 55 50 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$250 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 52 55 50 51 57 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$251 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 51 52 50 51 9C 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 36 88 10 E9}
		$252 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 57 52 51 9C 53 56 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9}
		$253 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 51 51 56 50 52 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$254 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 57 51 56 53 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$255 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 57 50 9C 53 56 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$256 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 57 51 52 53 53 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$257 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 52 57 50 55 53 9C 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8A 06 46 83 ED 02 66 89 45 00 E9}
		$258 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 52 9C 57 56 50 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$259 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 53 57 52 57 56 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$260 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 53 51 56 52 9C 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$261 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 9C 56 52 51 53 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$262 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 57 56 52 50 56 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$263 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 53 56 50 56 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$264 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 53 51 52 50 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$265 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 9C 50 57 57 51 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$266 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 55 56 54 57 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$267 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 54 51 57 52 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$268 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 50 56 57 51 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$269 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 52 55 56 55 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$270 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 50 9C 55 52 50 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9}
		$271 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 50 52 52 57 55 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$272 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 53 9C 52 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$273 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 50 51 9C 52 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$274 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 54 9C 51 56 55 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$275 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 9C 56 51 52 55 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$276 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 56 9C 55 52 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$277 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 56 55 51 9C 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$278 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 52 55 56 56 9C 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$279 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 55 56 51 55 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$280 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 55 51 9C 56 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$281 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 50 55 51 9C 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$282 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 55 57 51 56 50 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 83 C6 04 89 45 00 E9}
		$283 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 52 57 57 50 9C 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$284 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 9C 55 57 50 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$285 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 9C 52 57 55 50 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$286 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 56 50 57 55 52 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$287 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 55 56 52 9C 57 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9}
		$288 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 56 9C 57 50 51 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$289 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 55 9C 57 56 51 50 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 EC 5A 5E 58 59 5E 5F 9D 5D 5A 5B C3}
		$290 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 50 56 51 57 56 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 46 E9}
		$291 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 9C 53 56 57 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 89 EC 5A 5B 58 5F 5E 5A 9D 5A 5D 59 C3}
		$292 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 52 53 57 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$293 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 55 51 55 9C 56 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$294 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 53 57 52 56 51 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$295 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 56 56 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$296 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 53 55 51 56 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9}
		$297 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 53 51 55 51 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$298 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 51 51 9C 52 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$299 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 56 57 57 51 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 8D 76 02 89 45 00 E9}
		$300 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 53 57 51 52 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$301 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 53 51 55 57 52 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$302 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 53 50 55 9C 51 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$303 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 52 53 55 57 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$304 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 53 56 53 52 55 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$305 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 9C 56 53 57 55 52 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$306 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 9C 56 53 57 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$307 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 57 9C 53 53 55 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$308 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 55 9C 56 53 52 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 5A 58 5F 5A 5B 5E 9D 5D 59 59 C3}
		$309 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 53 55 9C 55 56 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9}
		$310 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 50 53 56 55 57 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$311 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 55 54 56 52 57 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$312 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 54 55 56 52 53 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$313 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 53 57 52 57 56 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$314 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 55 56 50 53 9C 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 0F B6 06 46 83 ED 02 66 89 45 00 E9}
		$315 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 52 9C 53 57 50 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$316 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 56 53 53 55 57 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$317 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 53 56 52 57 56 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$318 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 55 53 56 51 57 52 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$319 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 9C 52 56 55 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 EE FC E9}
		$320 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 54 57 56 52 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$321 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 9C 53 57 55 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$322 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 53 55 57 52 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5D 9D 5A 5F 5D 5B 5E 59 58 C3}
		$323 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 55 9C 57 57 56 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$324 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 53 9C 56 57 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$325 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 50 9C 53 55 57 52 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 C6 02 E9}
		$326 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 50 57 9C 55 52 56 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$327 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 52 55 9C 52 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$328 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 9C 50 53 57 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$329 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 57 56 55 53 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$330 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 53 9C 55 56 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$331 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 50 9C 51 57 52 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 EE FC 83 ED 04 89 45 00 E9}
		$332 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 9C 55 53 57 51 53 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$333 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 9C 50 55 53 51 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$334 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 52 52 9C 56 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$335 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 56 57 52 55 51 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$336 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 54 52 57 51 55 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$337 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 56 53 57 51 9C 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$338 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 53 53 55 9C 57 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$339 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 9C 56 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$340 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 57 9C 54 53 55 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$341 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 57 56 57 9C 51 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$342 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 56 9C 53 54 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$343 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 57 51 9C 50 52 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$344 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 53 9C 57 52 51 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$345 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 53 50 57 53 9C 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$346 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 9C 50 55 51 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$347 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 55 53 52 51 9C 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$348 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 55 52 9C 50 51 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$349 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 55 52 51 55 57 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$350 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 52 50 9C 51 55 54 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$351 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 9C 51 50 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$352 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 51 57 54 53 9C 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$353 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 50 51 57 50 52 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$354 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 57 52 50 51 51 9C 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$355 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 50 57 55 51 52 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$356 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 50 52 54 9C 53 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$357 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 56 53 51 55 9C 55 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9}
		$358 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 9C 56 53 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$359 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 53 56 55 50 9C 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$360 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 53 55 50 55 56 52 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$361 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 52 53 56 9C 55 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$362 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 53 52 50 51 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$363 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 52 53 55 52 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$364 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 51 55 52 51 57 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$365 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 52 55 51 53 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$366 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 53 54 51 55 56 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$367 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 52 53 56 57 9C 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9}
		$368 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 52 9C 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8A 06 8A 04 07 46 83 ED 02 66 89 45 00 E9}
		$369 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 53 50 51 51 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$370 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 51 57 53 56 54 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 8D 76 04 89 45 00 E9}
		$371 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 51 50 53 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$372 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 57 56 50 52 53 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$373 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 57 51 50 52 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$374 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 53 50 54 57 51 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$375 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 51 9C 56 53 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$376 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 50 56 51 52 53 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$377 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 50 52 53 52 51 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$378 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 51 55 56 53 52 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$379 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 9C 53 51 50 52 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$380 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 9C 51 56 53 52 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$381 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 51 53 57 52 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$382 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 57 53 57 55 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$383 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 55 50 57 51 53 9C 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9}
		$384 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 50 53 51 57 9C 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$385 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 52 9C 55 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$386 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 50 53 9C 57 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$387 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 9C 55 53 51 50 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$388 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 55 50 52 51 57 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$389 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 53 9C 51 57 52 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$390 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 52 9C 52 51 57 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9}
		$391 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 9C 57 52 50 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$392 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 53 54 57 55 50 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$393 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 55 51 53 50 52 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$394 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 51 56 52 50 9C 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$395 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 56 57 55 53 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$396 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 56 50 9C 53 50 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$397 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 54 53 9C 55 52 50 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$398 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 56 55 55 9C 50 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$399 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 52 51 57 55 9C 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 83 EE FC 83 ED 04 89 45 00 E9}
		$400 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 50 53 51 56 55 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$401 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 56 9C 56 53 55 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 06 8D 76 02 83 ED 02 66 89 45 00 E9}
		$402 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 56 57 55 52 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8A 06 83 ED 02 66 89 45 00 46 E9}
		$403 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 56 50 55 51 9C 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$404 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 54 55 51 50 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$405 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 50 9C 56 53 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$406 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 52 50 56 9C 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5A 5B 59 9D 5E 58 5F 5D 5F C3}
		$407 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 52 50 51 56 55 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$408 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 57 55 52 50 53 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$409 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 56 56 50 55 51 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$410 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E8 89 45 04 9C 8F 45 00 E9 01 7D 00 00}
		$411 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 55 52 54 50 51 53 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$412 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 57 53 55 56 50 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$413 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 52 9C 51 56 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$414 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 51 57 53 9C 52 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$415 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 56 52 53 55 53 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$416 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 53 56 52 51 50 9C 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9}
		$417 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 53 55 50 9C 55 56 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$418 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 9C 56 53 55 52 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$419 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 53 53 9C 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$420 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 57 56 55 56 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$421 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 57 56 52 55 50 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$422 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 50 53 53 52 57 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$423 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 51 56 52 56 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$424 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 52 57 50 57 51 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9}
		$425 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 51 9C 52 50 53 57 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$426 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 55 50 9C 51 57 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$427 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 57 53 52 9C 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$428 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 9C 57 50 53 55 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$429 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 55 9C 56 57 50 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$430 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 51 50 52 55 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$431 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 50 56 52 57 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$432 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 9C 56 50 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$433 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 55 9C 56 52 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8A 45 00 83 ED 02 00 45 04 9C 8F 45 00 E9}
		$434 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 51 56 57 50 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$435 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 53 50 52 56 55 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$436 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 56 57 53 55 51 52 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$437 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 53 51 57 9C 56 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$438 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 54 53 56 57 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$439 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 52 53 51 55 50 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 80 E0 3C 8B 14 07 83 ED 04 89 55 00 E9}
		$440 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 55 51 57 52 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$441 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 50 52 51 57 53 55 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 C6 04 89 45 00 E9}
		$442 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 55 52 51 56 57 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$443 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 57 55 53 51 52 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$444 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 55 56 52 56 51 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$445 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 51 9C 57 55 52 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$446 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 52 50 56 53 57 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$447 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 50 52 57 53 9C 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$448 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 51 9C 50 57 53 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9}
		$449 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 50 55 57 56 57 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$450 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 9C 51 56 51 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$451 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 50 55 52 56 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$452 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 50 52 57 56 51 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$453 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 52 51 9C 52 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$454 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 53 9C 54 55 51 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$455 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 52 50 56 56 9C 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$456 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 9C 57 51 55 55 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$457 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 57 9C 51 53 52 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$458 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 52 51 9C 53 53 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$459 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 9C 55 53 56 52 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 59 5B 5A 5E 58 5D 9D 58 5F C3}
		$460 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 9C 55 50 54 51 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$461 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 51 53 50 9C 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$462 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 52 53 56 50 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$463 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 51 53 55 51 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$464 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 51 52 55 51 50 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$465 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 51 53 55 56 50 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 8D 76 04 E9}
		$466 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 57 51 50 55 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$467 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 51 55 52 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$468 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 50 52 56 51 50 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5F 5B 5A 59 5E 5A 58 5D 9D C3}
		$469 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 55 56 56 57 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$470 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 51 52 55 52 50 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$471 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 57 53 52 55 51 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$472 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 56 53 57 52 51 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8A 06 46 83 ED 02 66 89 45 00 E9}
		$473 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 52 56 53 57 51 54 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$474 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 52 55 56 51 50 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$475 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 52 56 57 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$476 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 51 56 57 52 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$477 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 53 56 51 55 9C 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$478 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 53 50 56 53 51 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$479 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 56 55 56 9C 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$480 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 9C 52 50 57 56 53 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$481 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 51 50 55 53 56 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$482 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 9C 54 56 53 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$483 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 52 57 51 9C 53 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$484 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 55 52 9C 57 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$485 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 50 55 56 51 57 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$486 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 55 51 53 53 57 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$487 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 53 51 55 57 56 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$488 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 56 55 52 50 55 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$489 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 50 52 51 55 56 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$490 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 56 53 55 53 51 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$491 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 56 51 57 53 50 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$492 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 56 57 51 52 53 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9}
		$493 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 52 53 52 56 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$494 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 51 53 57 56 52 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$495 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 56 53 52 50 55 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 36 8A 02 66 89 45 00 E9}
		$496 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 55 57 53 56 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$497 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 57 53 51 52 55 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 5E 59 5D 5A 59 5B 5F 58 9D C3}
		$498 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 57 53 52 50 51 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$499 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 8A 4D 08 83 C5 02 0F A5 D0 89 45 04 9C 8F 45 00 E9}
		$500 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 8A 4D 08 83 C5 02 0F AD D0 89 45 04 9C 8F 45 00 E9}
		$501 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 47 50 39 C5 0F 87 ?? ?? ?? ?? 8D 4F 40 29 E1 8D 45 80 29 C8 89 C4 9C 56 89 FE 8D BD 40 FF FF FF 57 FC F3 A4 5F 5E 9D E9}
		$502 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 57 52 51 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$503 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 57 50 55 56 57 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$504 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 52 56 50 53 56 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 8D 76 04 89 45 00 E9}
		$505 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 57 55 56 51 50 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$506 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 55 50 52 9C 56 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$507 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 53 53 50 9C 52 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$508 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 52 53 50 9C 57 56 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$509 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 51 9C 56 50 57 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$510 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 9C 50 56 51 55 57 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$511 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 52 51 55 55 56 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$512 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 57 9C 56 50 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$513 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 52 53 51 55 9C 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9}
		$514 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 52 53 51 52 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$515 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 66 8B 55 02 F6 D0 F6 D2 83 ED 02 20 D0 66 89 45 04 9C 8F 45 00 E9}
		$516 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 8A 4D 02 83 ED 02 66 D3 E8 66 89 45 04 9C 8F 45 00 E9}
		$517 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 8A 4D 02 83 ED 02 66 D3 E0 66 89 45 04 9C 8F 45 00 E9}
		$518 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 52 53 55 55 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$519 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 51 9C 55 52 53 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$520 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 52 53 57 51 55 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$521 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 55 54 52 51 9C 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$522 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 51 52 55 57 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$523 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 56 50 51 53 52 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$524 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 56 53 57 51 52 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$525 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 55 51 9C 52 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9}
		$526 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 52 51 55 9C 50 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 0F B6 06 83 ED 02 46 66 89 45 00 E9}
		$527 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 53 9C 57 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 0F B6 06 66 98 98 46 83 ED 04 89 45 00 E9}
		$528 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 53 57 51 55 56 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$529 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 9C 50 56 51 55 54 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$530 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 55 50 9C 56 54 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$531 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 50 57 53 56 9C 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$532 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 50 53 56 51 9C 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$533 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 56 50 9C 55 53 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$534 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 52 50 56 57 51 9C 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$535 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 56 9C 56 53 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$536 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 56 53 55 57 9C 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 83 EE FC 89 45 00 E9}
		$537 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 53 9C 57 55 51 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$538 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 50 56 53 57 9C 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 59 5D 9D 5F 5A 5E 58 5B 5A C3}
		$539 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 50 55 51 56 9C 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$540 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 51 9C 53 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 C6 04 83 ED 04 89 45 00 E9}
		$541 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 56 51 50 9C 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$542 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 53 9C 50 50 56 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$543 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 50 53 51 56 55 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$544 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 51 53 52 57 55 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$545 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 51 51 9C 52 57 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9}
		$546 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 9C 56 53 55 57 54 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$547 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 9C 55 56 57 51 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$548 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 9C 50 51 57 53 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$549 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 9C 57 51 50 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$550 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 56 57 55 53 9C 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$551 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 53 51 50 9C 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$552 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 53 50 55 9C 57 51 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$553 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 55 57 53 9C 50 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$554 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 56 52 9C 50 53 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5F 5D 5B 58 9D 5A 5E 59 59 C3}
		$555 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 52 56 53 50 55 9C 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9}
		$556 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 50 55 56 53 9C 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$557 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 52 57 50 53 55 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$558 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 52 53 50 56 57 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$559 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 9C 50 53 56 51 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$560 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 52 9C 57 54 55 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$561 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 57 50 9C 56 52 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$562 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 53 57 50 52 50 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$563 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 9C 50 55 53 54 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$564 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 52 55 50 9C 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$565 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 56 53 55 57 9C 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$566 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 50 57 53 56 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$567 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 56 57 53 9C 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$568 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 56 9C 57 53 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$569 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 53 9C 55 51 54 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$570 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 53 50 57 9C 55 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 EC 5B 5E 5D 5D 9D 5F 58 5B 59 5A C3}
		$571 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 50 56 55 53 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$572 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 9C 55 53 51 56 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$573 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 56 50 52 57 57 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9}
		$574 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 53 53 56 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9}
		$575 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 53 50 52 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$576 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 53 51 9C 55 54 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$577 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 53 50 55 51 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$578 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 50 50 56 53 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$579 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 52 50 51 57 56 55 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$580 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 9C 56 50 51 55 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$581 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 56 51 50 9C 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$582 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 52 51 9C 57 53 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$583 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 56 51 52 50 55 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$584 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 53 56 51 57 55 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$585 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 9C 52 52 51 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$586 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 51 55 50 57 9C 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$587 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 9C 56 57 51 50 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$588 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 52 55 56 55 50 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$589 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 52 55 50 51 57 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$590 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 51 52 50 51 9C 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 36 88 10 E9}
		$591 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 57 52 51 9C 53 56 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9}
		$592 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 51 51 56 50 52 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$593 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 57 51 56 53 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$594 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 57 50 9C 53 56 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$595 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 57 51 52 53 53 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$596 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 52 57 50 55 53 9C 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8A 06 46 83 ED 02 66 89 45 00 E9}
		$597 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 52 9C 57 56 50 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$598 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 53 57 52 57 56 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$599 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 53 51 56 52 9C 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$600 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 9C 56 52 51 53 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$601 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 57 56 52 50 56 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9}
		$602 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 53 56 50 56 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$603 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 53 51 52 50 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$604 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 9C 50 57 57 51 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$605 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 55 56 54 57 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$606 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 54 51 57 52 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$607 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 50 56 57 51 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$608 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 52 55 56 55 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$609 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 50 9C 55 52 50 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9}
		$610 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 50 52 52 57 55 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$611 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 53 9C 52 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$612 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 50 51 9C 52 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$613 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 54 9C 51 56 55 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$614 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 9C 56 51 52 55 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$615 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 56 9C 55 52 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$616 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 56 55 51 9C 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$617 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 52 55 56 56 9C 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$618 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 55 56 51 55 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$619 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 55 51 9C 56 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$620 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 50 55 51 9C 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$621 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 55 57 51 56 50 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 83 C6 04 89 45 00 E9}
		$622 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 52 57 57 50 9C 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$623 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 9C 55 57 50 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$624 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 9C 52 57 55 50 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$625 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 56 50 57 55 52 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$626 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 55 56 52 9C 57 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9}
		$627 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 56 9C 57 50 51 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$628 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 55 9C 57 56 51 50 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 EC 5A 5E 58 59 5E 5F 9D 5D 5A 5B C3}
		$629 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 50 56 51 57 56 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 46 E9}
		$630 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 9C 53 56 57 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 89 EC 5A 5B 58 5F 5E 5A 9D 5A 5D 59 C3}
		$631 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 52 53 57 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$632 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 55 51 55 9C 56 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$633 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 53 57 52 56 51 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9}
		$634 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 56 56 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$635 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 53 55 51 56 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9}
		$636 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 53 51 55 51 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$637 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 51 51 9C 52 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9}
		$638 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 56 57 57 51 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 8D 76 02 89 45 00 E9}
		$639 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 53 57 51 52 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$640 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 53 51 55 57 52 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$641 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 53 50 55 9C 51 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$642 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 52 53 55 57 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$643 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 53 56 53 52 55 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$644 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 9C 56 53 57 55 52 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$645 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 9C 56 53 57 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$646 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 57 9C 53 53 55 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$647 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 55 9C 56 53 52 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 5A 58 5F 5A 5B 5E 9D 5D 59 59 C3}
		$648 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 53 55 9C 55 56 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9}
		$649 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 50 53 56 55 57 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9}
		$650 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 55 54 56 52 57 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9}
		$651 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 54 55 56 52 53 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$652 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 53 57 52 57 56 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$653 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 55 56 50 53 9C 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 0F B6 06 46 83 ED 02 66 89 45 00 E9}
		$654 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 52 9C 53 57 50 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$655 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 56 53 53 55 57 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$656 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 53 56 52 57 56 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$657 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 55 53 56 51 57 52 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$658 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 9C 52 56 55 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 EE FC E9}
		$659 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 54 57 56 52 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$660 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 9C 53 57 55 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$661 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 53 55 57 52 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5D 9D 5A 5F 5D 5B 5E 59 58 C3}
		$662 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 55 9C 57 57 56 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$663 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 53 9C 56 57 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$664 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 50 9C 53 55 57 52 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 C6 02 E9}
		$665 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 50 57 9C 55 52 56 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$666 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 52 55 9C 52 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$667 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 9C 50 53 57 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$668 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 57 56 55 53 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3}
		$669 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 53 9C 55 56 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$670 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 50 9C 51 57 52 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 EE FC 83 ED 04 89 45 00 E9}
		$671 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 9C 55 53 57 51 53 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9}
		$672 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 9C 50 55 53 51 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$673 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 52 52 9C 56 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$674 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 56 57 52 55 51 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9}
		$675 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 54 52 57 51 55 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$676 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 56 53 57 51 9C 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$677 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 53 53 55 9C 57 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3}
		$678 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 9C 56 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3}
		$679 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 57 9C 54 53 55 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9}
		$680 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 57 56 57 9C 51 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3}
		$681 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 56 9C 53 54 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3}
		$682 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 58 5A 5D 5F 5B 5A 59 9D C3}
		$683 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 5E 5B 9D 58 5B 59 5A C3}
		$684 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 5A 5E 5D 5B 58 9D 59 C3}
		$685 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 59 5F 5B 5D 58 5A 9D 5E C3}
		$686 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 59 58 5F 5D 58 5B 9D 5A C3}
		$687 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 58 5F 5D 5B 5A 59 9D 5F C3}
		$688 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 59 5A 58 9D 5D 5B 5F C3}
		$689 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 58 5D 5F 9D 5A 59 5F C3}
		$690 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 9D 5E 5D 58 5F 5A 59 5B C3}
		$691 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 59 59 5A 5E 5B 9D 58 C3}
		$692 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5F 5B 9D 59 5A 5D 58 5E C3}
		$693 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5F 58 5A 5E 9D 5D 59 59 C3}
		$694 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 59 5B 5A 58 5F 9D 58 C3}
		$695 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 59 5A 5F 5E 5D 5D 58 5B C3}
		$696 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5F 5B 5A 9D 5E 5D 59 58 C3}
		$697 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5E 9D 59 5A 5A 5B 58 5D C3}
		$698 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5D 5A 5B 58 5F 5E 5E 59 C3}
		$699 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 5F 5D 58 5B 58 59 5E C3}
		$700 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 58 5B 5F 59 5D 5E 59 C3}
		$701 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 59 5E 5F 5D 5A 9D C3}
		$702 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5F 9D 5D 5B 58 5E 5A 59 C3}
		$703 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 5A 58 59 5B 5A 5F 9D C3}
		$704 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5D 5E 58 5B 9D 59 5A 5B C3}
		$705 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5A 5B 59 5D 9D 59 5E 58 C3}
		$706 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 9D 5A 5D 5F 5E 59 C3}
		$707 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 5F 5F 58 5E 5D 9D 59 5B C3}
		$708 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5B 5E 5B 5D 59 5A 9D 58 C3}
		$709 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5A 5E 5E 59 9D 5D 5B 58 C3}
		$710 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5F 5F 9D 59 5D 5A 5B 58 C3}
		$711 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 9D 5D 58 5B 5A 5A 59 C3}
		$712 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 5D 59 9D 5B 58 5A 5A C3}
		$713 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 58 5D 5B 59 9D 5A 5D C3}
		$714 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5A 5F 58 58 5D 59 5B 9D C3}
		$715 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5A 59 5D 5B 58 5F 9D 5F C3}
		$716 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 59 5D 9D 58 5B 5A 5F 5A C3}
		$717 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5F 5B 59 5D 58 9D 5A 5D C3}
		$718 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 5D 5A 5F 58 59 58 9D C3}
		$719 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 5A 59 5D 58 5F 9D 5D C3}
		$720 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 58 5F 5F 5B 5A 59 5D 5E C3}
		$721 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 58 5B 5D 5F 5E 5A 5F 9D C3}
		$722 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 5B 5D 5E 5B 5A 59 9D C3}
		$723 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 59 5A 59 5E 5D 5B 9D C3}
		$724 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 5F 5B 58 59 5D 9D 5D 5E C3}
		$725 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5A 9D 5F 5B 5B 5D 58 5E C3}
		$726 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5A 9D 5E 58 5F 5D 59 5B C3}
		$727 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 59 59 5E 5D 5F 5A 9D C3}
		$728 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5F 5D 5E 5B 58 59 5A 59 C3}
		$729 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5D 5E 58 59 5B 5F 5A 5F C3}
		$730 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 9D 5A 5F 5D 5A 5E 59 C3}
		$731 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 5A 5F 59 5D 5D 5E 9D C3}
		$732 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 59 5F 5A 5E 5D 9D 5A C3}
		$733 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5A 5B 5E 5F 9D 5D 5F 59 C3}
		$734 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5E 5F 5B 5D 58 5A 59 59 C3}
		$735 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5E 5A 58 5F 5D 5B 59 5F C3}
		$736 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5F 5E 5B 59 5D 5A 9D 59 C3}
		$737 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5F 5E 59 9D 5D 5B 59 5A C3}
		$738 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5A 5E 5F 5B 5B 5D 59 9D C3}
		$739 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 59 59 5A 5B 9D 5E 58 5D C3}
		$740 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 9D 5A 5D 5F 58 5B 59 5B C3}
		$741 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5F 58 5B 5A 59 5D 9D 5D C3}
		$742 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5A 59 5E 5D 5F 5B 5A 58 C3}
		$743 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5B 9D 5D 5A 5E 58 5A 59 C3}
		$744 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5A 59 5D 9D 5E 58 5B 5A C3}
		$745 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5D 5A 58 9D 5B 5E 5F 58 C3}
		$746 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 5D 5E 5F 58 9D 5A 58 59 C3}
		$747 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 59 5E 5F 5D 5A 9D 58 58 C3}
		$748 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 9D 5B 5F 5E 5D 58 59 59 C3}
		$749 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5A 5F 58 9D 5E 5B 59 58 C3}
		$750 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 59 9D 5A 5E 58 5B 5F 58 C3}
		$751 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 9D 58 59 58 5E 5D 5A 5F C3}
		$752 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5F 5B 58 5A 9D 58 5E 5D C3}
		$753 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5E 5F 5D 5A 5B 58 5A 9D C3}
		$754 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5E 5A 5F 5B 9D 5B 58 5D C3}
		$755 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5D 59 5D 5F 58 5E 5B 9D C3}
		$756 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 59 5E 5D 5F 9D 5E 5B 58 C3}
		$757 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 58 5B 59 5E 5D 5F 5F 9D C3}
		$758 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5E 5B 58 9D 59 5D 5F 5A C3}
		$759 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 59 58 5D 5E 5D 5F 5B 9D C3}
		$760 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5F 5F 5E 5D 5A 5B 9D 58 C3}
		$761 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5F 5D 9D 5E 5B 5A 5A 58 C3}
		$762 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5F 5E 58 5D 59 5D 5B 9D C3}
		$763 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5B 5F 58 5D 5E 5D 59 9D C3}
		$764 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5B 5D 5E 58 5F 59 5D 9D C3}
		$765 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5B 5D 5E 5A 5E 59 9D 5F C3}
		$766 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 9D 5F 59 5A 5B 5D C3}
		$767 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5F 58 5A 5E 5D 5E 5B 59 C3}
		$768 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5D 5D 5A 5F 5E 58 9D 5B C3}
		$769 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5A 5B 9D 58 5E 5F 58 5D C3}
		$770 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 9D 5B 5E 5A 5D 5F 5F 59 C3}
		$771 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5A 59 5E 9D 5E 5D 5F C3}
		$772 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 9D 5A 5B 59 58 5E 58 5F C3}
		$773 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5F 5B 5D 58 5E 5A 59 9D C3}
		$774 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5E 58 5F 5A 59 5B 5B 9D C3}
		$775 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5D 5B 5F 5E 59 58 9D 5A C3}
		$776 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5B 5A 58 5D 59 5F 9D 5F C3}
		$777 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5A 5F 5B 9D 58 5E 59 5D C3}
		$778 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5A 9D 58 5F 5E 5E 59 5D C3}
		$779 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 59 9D 5D 5A 5E 58 5F 5F C3}
		$780 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5D 58 9D 59 5A 5F 5E C3}
		$781 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5E 58 5A 9D 5F 59 5B 59 C3}
		$782 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 9D 5F 5D 58 5A 5E 59 58 C3}
		$783 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5E 59 5F 5D 5D 9D 58 5A C3}
		$784 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5F 5E 58 9D 59 5A 5B 5A C3}
		$785 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 58 5D 5F 9D 5A 5E 5E C3}
		$786 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5A 5E 58 9D 5D 58 5B 5F C3}
		$787 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 9D 5B 5D 5E 5F 5A 59 5E C3}
		$788 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5E 58 5D 5B 9D 5F 5A 5A C3}
		$789 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5D 5F 5E 5A 5B 9D 5B 58 C3}
		$790 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 9D 5E 5F 5A 58 5D 5D C3}
		$791 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5B 5E 5D 58 5F 9D 59 5A C3}
		$792 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5A 5D 5B 5E 59 5A 9D 5F C3}
		$793 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 59 5E 5D 5B 9D 5F 5A 5E C3}
		$794 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5F 5B 5F 5D 59 5E 9D 5A C3}
		$795 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5E 5A 59 5D 59 9D 5F 5B C3}
		$796 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5B 5E 5D 9D 5B 59 5A 5F C3}
		$797 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 59 5B 5D 5A 5E 9D 5F 58 C3}
		$798 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 59 5E 5D 5D 5F 5A 58 C3}
		$799 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5E 5A 58 5F 58 59 9D 5D C3}
		$800 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 59 5F 5E 58 9D 5A 5E C3}
		$801 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 59 9D 5D 58 5B 5E 5A 5F C3}
		$802 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 58 5A 5B 5D 9D 5F 5E 59 C3}
		$803 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 5E 5A 5E 59 5F 5D 58 C3}
		$804 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5E 5D 9D 5B 58 5F 59 59 C3}
		$805 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5B 59 5D 5E 58 5F 9D 5D C3}
		$806 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5B 58 9D 5E 5F 5D 59 5F C3}
		$807 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 58 9D 59 5F 5E 59 5A C3}
		$808 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 5D 58 5F 5B 59 58 C3}
		$809 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 5B 5F 5B 58 5D 59 C3}
		$810 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 8D 76 02 89 45 00 E9}
		$811 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 83 EE FE E9}
		$812 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 83 C6 02 E9}
		$813 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 C6 02 98 83 ED 04 89 45 00 E9}
		$814 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 8D 76 02 98 83 ED 04 89 45 00 E9}
		$815 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 EE FE 83 ED 02 66 89 45 00 E9}
		$816 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 8D 76 02 E9}
		$817 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 EE FE 98 83 ED 04 89 45 00 E9}
		$818 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 83 EE FE E9}
		$819 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 8D 76 02 83 ED 04 89 45 00 E9}
		$820 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 C6 02 83 ED 04 89 45 00 E9}
		$821 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 8D 76 02 83 ED 02 66 89 45 00 E9}
		$822 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 5D 5A 5A 5F 5B 9D 59 C3}
		$823 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 59 5B 59 5A 5D 9D 5F C3}
		$824 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 59 5E 5A 58 5B 5F 59 9D C3}
		$825 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5D 5F 5E 9D 58 5A 59 58 C3}
		$826 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5D 5F 5B 5E 9D 58 5A 5B C3}
		$827 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 59 5D 9D 5E 5F 5A 5D 58 C3}
		$828 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5E 5D 5B 9D 59 58 58 5F C3}
		$829 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5E 9D 5F 59 5A 5D 58 5B C3}
		$830 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 9D 5B 59 5E 5B 5D 58 5A C3}
		$831 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5D 5E 5F 9D 5A 59 5A C3}
		$832 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 9D 5F 5D 5E 5B 59 5A 5A C3}
		$833 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 5F 58 5B 59 5B 5D 5E C3}
		$834 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 58 5A 5F 5B 5E 5D 5D 9D C3}
		$835 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 5E 59 5E 5D 5B 5A 9D C3}
		$836 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5A 9D 5D 59 5B 59 5E 5F C3}
		$837 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 5F 5A 59 5D 9D 5E C3}
		$838 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5E 9D 58 5B 5F 59 58 5A C3}
		$839 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5D 58 59 9D 5E 5A 5B 5F C3}
		$840 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 59 5D 5D 58 5B 5F C3}
		$841 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5A 5D 5B 9D 59 5F 5F 5E C3}
		$842 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5D 59 5F 5E 58 58 5A 5B C3}
		$843 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 5F 58 5B 5A 5A 59 9D C3}
		$844 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5F 5A 59 58 5D 9D 5E 5A C3}
		$845 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5A 5F 59 5B 5D 58 5B 9D C3}
		$846 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5F 5E 5E 5A 5D 5B 59 9D C3}
		$847 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 5F 5D 5B 5A 5A 9D C3}
		$848 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 59 5A 5B 58 5B 5F 5E 5D C3}
		$849 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 59 58 5B 5E 5F 5A 9D 5D C3}
		$850 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5E 5A 58 5D 9D 59 5F 5B C3}
		$851 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 5F 5E 58 9D 5D 5A 5E C3}
		$852 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5A 5B 5E 58 5D 5F 9D 5B C3}
		$853 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 9D 58 5D 5F 5A 5D 59 C3}
		$854 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 5E 5A 5F 58 5D 9D 58 C3}
		$855 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5F 5A 5B 5E 58 9D 59 5F C3}
		$856 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5F 58 59 5B 5D 5E 9D 58 C3}
		$857 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 59 5D 5F 9D 5A 58 5F C3}
		$858 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5A 5F 5E 5D 58 58 59 9D C3}
		$859 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 58 5B 5E 59 5D 9D 5F 59 C3}
		$860 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 59 5D 5B 5F 58 5E 5A 5A C3}
		$861 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 9D 5A 5F 59 58 5D 5E 5E C3}
		$862 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5A 5B 5E 5D 5B 9D 59 58 C3}
		$863 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 58 5F 5E 59 5D 5D 5A C3}
		$864 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5D 58 59 9D 5E 5B 5A 5E C3}
		$865 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 5A 5F 59 58 9D 5B 5B C3}
		$866 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5D 58 5F 59 5B 9D 5E 5A C3}
		$867 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 59 5F 59 58 9D 5E 5D 5B C3}
		$868 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 83 C6 01 89 45 00 E9}
		$869 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 46 89 45 00 E9}
		$870 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 C6 01 83 ED 04 89 45 00 E9}
		$871 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 8D 76 01 E9}
		$872 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 83 C6 01 E9}
		$873 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 83 EE FF 89 45 00 E9}
		$874 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 EE FF 83 C5 02 88 14 07 E9}
		$875 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 EE FF 83 C5 02 66 89 14 07 E9}
		$876 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C6 01 83 C5 02 66 89 14 07 E9}
		$877 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 83 EE FF 98 83 ED 04 89 45 00 E9}
		$878 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 83 C6 01 98 83 ED 04 89 45 00 E9}
		$879 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 8D 76 01 83 C5 02 66 89 14 07 E9}
		$880 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 8D 76 01 89 45 00 E9}
		$881 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$882 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 83 EE FF 66 89 45 00 E9}
		$883 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 8D 76 01 E9}
		$884 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 46 83 ED 02 66 89 45 00 E9}
		$885 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 98 98 83 ED 04 89 45 00 E9}
		$886 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 55 00 83 C5 02 88 14 07 E9}
		$887 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$888 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$889 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 EE FF 83 ED 04 89 45 00 E9}
		$890 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 83 EE FF E9}
		$891 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 8A 04 07 83 ED 02 66 89 45 00 E9}
		$892 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 55 00 83 C5 02 88 14 07 E9}
		$893 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 8D 76 01 88 14 07 E9}
		$894 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 9D 5F 5D 5B 58 5D 59 5A C3}
		$895 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 9D 5D 5B 59 5A 58 5F 5A C3}
		$896 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5F 58 59 9D 5F 5B 5D 5A C3}
		$897 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5D 59 58 5F 5A 5E 5B 5B C3}
		$898 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 9D 58 5B 5D 5A 5A 5E 59 C3}
		$899 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 5A 58 5E 5D 5B 9D 59 5D C3}
		$900 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 59 58 5F 5B 5D 5D 5A 9D C3}
		$901 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 5F 5D 5A 59 9D 5A 5B C3}
		$902 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5B 58 5A 59 5F 9D 5E 58 C3}
		$903 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5D 5B 5A 9D 58 5A 59 5F C3}
		$904 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5D 58 59 58 9D 5A 5B 5F C3}
		$905 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5A 59 9D 5F 5D 5B 58 5B C3}
		$906 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5D 5E 59 5B 58 5B 5F 5A C3}
		$907 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 8D 76 01 E9}
		$908 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 8D 76 01 83 ED 02 66 89 45 00 E9}
		$909 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 8D 76 01 66 89 45 00 E9}
		$910 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 8D 76 01 E9}
		$911 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 EE FF 66 89 14 07 E9}
		$912 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 C6 01 66 89 14 07 E9}
		$913 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$914 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5F 59 5D 5A 5B 5B 5E 58 C3}
		$915 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5F 58 5E 5A 5B 59 5D 59 C3}
		$916 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 8D 76 01 E9}
		$917 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 83 C6 01 E9}
		$918 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 C6 01 83 ED 02 66 89 45 00 E9}
		$919 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 5E 59 5F 58 9D 58 5A C3}
		$920 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5B 59 5D 5F 58 5E 5E C3}
		$921 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 98 98 83 ED 04 89 45 00 E9}
		$922 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 55 00 83 C5 02 88 14 07 E9}
		$923 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$924 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 8D 76 04 E9}
		$925 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 8A 04 07 83 ED 02 66 89 45 00 E9}
		$926 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 83 ED 02 66 89 45 00 E9}
		$927 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 83 EE FF E9}
		$928 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 83 C6 01 E9}
		$929 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 C6 01 83 ED 02 66 89 45 00 E9}
		$930 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 8D 76 01 83 ED 02 66 89 45 00 E9}
		$931 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 83 EE FF 66 89 45 00 E9}
		$932 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 83 C6 01 66 89 45 00 E9}
		$933 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 8D 76 04 89 45 00 E9}
		$934 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 46 E9}
		$935 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 EE FF 88 14 07 E9}
		$936 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 C6 01 88 14 07 E9}
		$937 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 8D 76 01 66 89 14 07 E9}
		$938 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 83 EE FF E9}
		$939 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 83 C6 01 E9}
		$940 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 46 88 14 07 E9}
		$941 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 46 66 89 14 07 E9}
		$942 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 46 83 C5 02 88 14 07 E9}
		$943 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 83 EE FF E9}
		$944 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 83 C6 01 E9}
		$945 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 46 E9}
		$946 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C6 01 83 C5 02 88 14 07 E9}
		$947 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 83 ED 02 66 89 45 00 E9}
		$948 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 98 98 83 ED 04 89 45 00 E9}
		$949 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 8D 76 01 83 ED 04 89 45 00 E9}
		$950 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 83 C6 01 E9}
		$951 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 46 E9}
		$952 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 46 66 89 45 00 E9}
		$953 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 8D 76 01 98 83 ED 04 89 45 00 E9}
		$954 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 46 98 83 ED 04 89 45 00 E9}
		$955 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 8D 76 01 83 C5 02 88 14 07 E9}
		$956 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 83 EE FF E9}
		$957 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 46 E9}
		$958 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 46 83 ED 04 89 45 00 E9}
		$959 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 46 83 C5 02 66 89 14 07 E9}
		$960 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5F 5D 9D 58 59 59 5B 5E C3}
		$961 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5B 5F 5E 9D 58 5D 59 5A C3}
		$962 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 59 5F 58 5E 9D 5D 5F 5B C3}
		$963 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 59 5A 5B 9D 5F 58 58 5D C3}
		$964 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 9D 59 5F 5D 58 5E 5A 5B C3}
		$965 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5B 59 5F 5E 9D 5D 5A 58 C3}
		$966 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5B 58 5A 5B 5F 5E 9D 5D C3}
		$967 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 9D 5F 5B 5A 5B 58 59 C3}
		$968 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 5B 5F 58 5E 59 5A 9D C3}
		$969 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5E 5F 5D 5A 58 5B 9D 59 C3}
		$970 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 5D 5F 5B 9D 5A 5F C3}
		$971 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5B 5D 5A 5F 59 5E 58 59 C3}
		$972 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 5F 5B 58 59 5D 5A 5E 9D C3}
		$973 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 83 EE FF E9}
		$974 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 46 E9}
		$975 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 46 66 89 45 00 E9}
		$976 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 EE FF 83 ED 02 66 89 45 00 E9}
		$977 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 83 EE FF 66 89 45 00 E9}
		$978 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 83 C6 01 66 89 45 00 E9}
		$979 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 98 98 83 ED 04 89 45 00 E9}
		$980 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 55 00 83 C5 02 88 14 07 E9}
		$981 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$982 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 46 83 ED 02 66 89 45 00 E9}
		$983 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 8A 04 07 83 ED 02 66 89 45 00 E9}
		$984 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 83 ED 02 66 89 45 00 E9}
		$985 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$986 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9}
		$987 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 83 C5 02 36 8A 02 66 89 45 00 E9}
		$988 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 F7 D0 F7 D2 21 D0 89 45 04 9C 8F 45 00 E9}
		$989 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E8 89 45 04 9C 8F 45 00 E9}
		$990 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E0 89 45 04 9C 8F 45 00 E9}
		$991 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$992 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$993 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 36 88 10 E9}
		$994 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9}
		$995 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 8D 76 01 E9}
		$996 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 C6 01 83 ED 02 66 89 45 00 E9}
		$997 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F7 55 00 66 8B 45 00 83 ED 02 66 21 45 04 9C 8F 45 00 E9}
		$998 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 8D 76 01 66 89 45 00 E9}
		$999 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1000 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1001 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 36 8B 00 66 89 45 00 E9}
		$1002 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1003 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1004 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 46 E9}
		$1005 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 83 ED 02 00 45 04 9C 8F 45 00 E9}
		$1006 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1007 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1008 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1009 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1010 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1011 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 46 66 89 45 00 E9}
		$1012 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1013 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1014 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 8A 4D 02 83 ED 02 D2 E0 66 89 45 04 9C 8F 45 00 E9}
		$1015 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$1016 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9}
		$1017 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 EE FC 83 ED 04 89 45 00 E9}
		$1018 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9}
		$1019 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 36 89 10 E9}
		$1020 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 83 C6 04 89 45 00 E9}
		$1021 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 C6 04 83 ED 04 89 45 00 E9}
		$1022 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 8A 4D 02 83 ED 02 D2 E8 66 89 45 04 9C 8F 45 00 E9}
		$1023 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 EE FC E9}
		$1024 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9}
		$1025 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9}
		$1026 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 58 5E 5D 5B 5B 9D 59 5F C3}
		$1027 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1028 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 46 E9}
		$1029 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 46 66 89 45 00 E9}
		$1030 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1031 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1032 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1033 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 46 E9}
		$1034 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 46 66 89 45 00 E9}
		$1035 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 83 ED 02 66 89 45 00 E9}
		$1036 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1037 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1038 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1039 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1040 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1041 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1042 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1043 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 46 66 89 45 00 E9}
		$1044 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 46 83 ED 02 66 89 45 00 E9}
		$1045 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1046 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 83 EE FF E9}
		$1047 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1048 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 46 E9}
		$1049 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1050 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1051 = {8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9}
		$1052 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 83 ED 02 66 89 45 00 E9}
		$1053 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 98 98 83 ED 04 89 45 00 E9}
		$1054 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1055 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1056 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 EE FF 83 C5 02 66 89 14 07 E9}
		$1057 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 83 C6 01 E9}
		$1058 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 46 E9}
		$1059 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 46 E9}
		$1060 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 46 89 45 00 E9}
		$1061 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 C6 01 83 ED 04 89 45 00 E9}
		$1062 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 46 88 14 07 E9}
		$1063 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 46 83 C5 02 88 14 07 E9}
		$1064 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 46 83 C5 02 66 89 14 07 E9}
		$1065 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 C6 01 66 89 14 07 E9}
		$1066 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 83 C6 01 E9}
		$1067 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 46 E9}
		$1068 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 83 EE FE 89 45 00 E9}
		$1069 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 83 C6 02 89 45 00 E9}
		$1070 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 C6 02 83 ED 04 89 45 00 E9}
		$1071 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 8D 76 02 E9}
		$1072 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 EE FE E9}
		$1073 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 C6 02 E9}
		$1074 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 83 EE FE 66 89 45 00 E9}
		$1075 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 83 C6 02 66 89 45 00 E9}
		$1076 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 C6 02 83 ED 02 66 89 45 00 E9}
		$1077 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 8D 76 02 83 ED 02 66 89 45 00 E9}
		$1078 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 EE FE 98 83 ED 04 89 45 00 E9}
		$1079 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 8D 76 02 66 89 45 00 E9}
		$1080 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 EE FE 83 ED 04 89 45 00 E9}
		$1081 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 E0 3C 8B 55 00 83 C5 04 89 14 07 E9}
		$1082 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 E0 3C 8B 14 07 83 ED 04 89 55 00 E9}
		$1083 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5F 58 5A 9D 5D 5E 5E 5B C3}
		$1084 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5E 5B 5F 5B 9D 58 5D 5A C3}
		$1085 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 83 ED 02 66 01 45 04 9C 8F 45 00 E9}
		$1086 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 8D 76 02 83 ED 04 89 45 00 E9}
		$1087 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 EE FE 83 ED 04 89 45 00 E9}
		$1088 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 C6 02 98 83 ED 04 89 45 00 E9}
		$1089 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 C6 02 83 ED 02 66 89 45 00 E9}
		$1090 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 83 C6 02 E9}
		$1091 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 83 C6 02 E9}
		$1092 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 83 EE FE 89 45 00 E9}
		$1093 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 83 C6 02 89 45 00 E9}
		$1094 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 8D 76 02 89 45 00 E9}
		$1095 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 8D 76 02 E9}
		$1096 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 83 EE FE E9}
		$1097 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 83 EE FE 66 89 45 00 E9}
		$1098 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 83 C6 02 66 89 45 00 E9}
		$1099 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 8D 76 02 E9}
		$1100 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 8D 76 02 98 83 ED 04 89 45 00 E9}
		$1101 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 EE FE 83 ED 02 66 89 45 00 E9}
		$1102 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 8D 76 02 66 89 45 00 E9}
		$1103 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 83 EE FF E9}
		$1104 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1105 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1106 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1107 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1108 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1109 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 8D 76 01 83 ED 04 89 45 00 E9}
		$1110 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 EE FF 83 ED 04 89 45 00 E9}
		$1111 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 8D 76 01 89 45 00 E9}
		$1112 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 98 98 83 ED 04 89 45 00 E9}
		$1113 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1114 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1115 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1116 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1117 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1118 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 83 EE FF E9}
		$1119 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 98 98 83 ED 04 89 45 00 E9}
		$1120 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1121 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1122 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1123 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1124 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 98 98 83 ED 04 89 45 00 E9}
		$1125 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1126 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 C6 01 83 ED 02 66 89 45 00 E9}
		$1127 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 46 83 ED 02 66 89 45 00 E9}
		$1128 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 8D 76 01 E9}
		$1129 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 8D 76 01 E9}
		$1130 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 83 EE FF E9}
		$1131 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 EE FF 88 14 07 E9}
		$1132 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C6 01 83 C5 02 66 89 14 07 E9}
		$1133 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 8D 76 01 88 14 07 E9}
		$1134 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 8D 76 01 66 89 14 07 E9}
		$1135 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 83 EE FF E9}
		$1136 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 46 66 89 14 07 E9}
		$1137 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1138 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 EE FF 66 89 14 07 E9}
		$1139 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 C6 01 88 14 07 E9}
		$1140 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 8D 76 01 E9}
		$1141 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C6 01 83 C5 02 88 14 07 E9}
		$1142 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 83 C6 01 89 45 00 E9}
		$1143 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 46 83 ED 04 89 45 00 E9}
		$1144 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 8D 76 01 98 83 ED 04 89 45 00 E9}
		$1145 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 83 EE FF E9}
		$1146 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 83 C6 01 E9}
		$1147 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 83 EE FF 89 45 00 E9}
		$1148 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 8D 76 01 83 C5 02 88 14 07 E9}
		$1149 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 8D 76 01 83 C5 02 66 89 14 07 E9}
		$1150 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 EE FF 83 C5 02 88 14 07 E9}
		$1151 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 83 EE FF 98 83 ED 04 89 45 00 E9}
		$1152 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 83 C6 01 98 83 ED 04 89 45 00 E9}
		$1153 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 46 98 83 ED 04 89 45 00 E9}
		$1154 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 58 5A 5D 5F 5B 5A 59 9D C3}
		$1155 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 5E 5B 9D 58 5B 59 5A C3}
		$1156 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 5A 5E 5D 5B 58 9D 59 C3}
		$1157 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 59 5F 5B 5D 58 5A 9D 5E C3}
		$1158 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 59 58 5F 5D 58 5B 9D 5A C3}
		$1159 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 58 5F 5D 5B 5A 59 9D 5F C3}
		$1160 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 59 5A 58 9D 5D 5B 5F C3}
		$1161 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 58 5D 5F 9D 5A 59 5F C3}
		$1162 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 9D 5E 5D 58 5F 5A 59 5B C3}
		$1163 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 59 59 5A 5E 5B 9D 58 C3}
		$1164 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5F 5B 9D 59 5A 5D 58 5E C3}
		$1165 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5F 58 5A 5E 9D 5D 59 59 C3}
		$1166 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 59 5B 5A 58 5F 9D 58 C3}
		$1167 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 59 5A 5F 5E 5D 5D 58 5B C3}
		$1168 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5F 5B 5A 9D 5E 5D 59 58 C3}
		$1169 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5E 9D 59 5A 5A 5B 58 5D C3}
		$1170 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5D 5A 5B 58 5F 5E 5E 59 C3}
		$1171 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 5F 5D 58 5B 58 59 5E C3}
		$1172 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 58 5B 5F 59 5D 5E 59 C3}
		$1173 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 59 5E 5F 5D 5A 9D C3}
		$1174 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5F 9D 5D 5B 58 5E 5A 59 C3}
		$1175 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 5A 58 59 5B 5A 5F 9D C3}
		$1176 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5D 5E 58 5B 9D 59 5A 5B C3}
		$1177 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5A 5B 59 5D 9D 59 5E 58 C3}
		$1178 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 9D 5A 5D 5F 5E 59 C3}
		$1179 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 5F 5F 58 5E 5D 9D 59 5B C3}
		$1180 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5B 5E 5B 5D 59 5A 9D 58 C3}
		$1181 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5A 5E 5E 59 9D 5D 5B 58 C3}
		$1182 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5F 5F 9D 59 5D 5A 5B 58 C3}
		$1183 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 9D 5D 58 5B 5A 5A 59 C3}
		$1184 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 5D 59 9D 5B 58 5A 5A C3}
		$1185 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 58 5D 5B 59 9D 5A 5D C3}
		$1186 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5A 5F 58 58 5D 59 5B 9D C3}
		$1187 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5A 59 5D 5B 58 5F 9D 5F C3}
		$1188 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 59 5D 9D 58 5B 5A 5F 5A C3}
		$1189 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5F 5B 59 5D 58 9D 5A 5D C3}
		$1190 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 5D 5A 5F 58 59 58 9D C3}
		$1191 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 5A 59 5D 58 5F 9D 5D C3}
		$1192 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 58 5F 5F 5B 5A 59 5D 5E C3}
		$1193 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 58 5B 5D 5F 5E 5A 5F 9D C3}
		$1194 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 5B 5D 5E 5B 5A 59 9D C3}
		$1195 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 59 5A 59 5E 5D 5B 9D C3}
		$1196 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 5F 5B 58 59 5D 9D 5D 5E C3}
		$1197 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5A 9D 5F 5B 5B 5D 58 5E C3}
		$1198 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5A 9D 5E 58 5F 5D 59 5B C3}
		$1199 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 59 59 5E 5D 5F 5A 9D C3}
		$1200 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5F 5D 5E 5B 58 59 5A 59 C3}
		$1201 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5D 5E 58 59 5B 5F 5A 5F C3}
		$1202 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 9D 5A 5F 5D 5A 5E 59 C3}
		$1203 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 5A 5F 59 5D 5D 5E 9D C3}
		$1204 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 59 5F 5A 5E 5D 9D 5A C3}
		$1205 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5A 5B 5E 5F 9D 5D 5F 59 C3}
		$1206 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5E 5F 5B 5D 58 5A 59 59 C3}
		$1207 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5E 5A 58 5F 5D 5B 59 5F C3}
		$1208 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5F 5E 5B 59 5D 5A 9D 59 C3}
		$1209 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5F 5E 59 9D 5D 5B 59 5A C3}
		$1210 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5A 5E 5F 5B 5B 5D 59 9D C3}
		$1211 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 59 59 5A 5B 9D 5E 58 5D C3}
		$1212 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 9D 5A 5D 5F 58 5B 59 5B C3}
		$1213 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5F 58 5B 5A 59 5D 9D 5D C3}
		$1214 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5A 59 5E 5D 5F 5B 5A 58 C3}
		$1215 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5B 9D 5D 5A 5E 58 5A 59 C3}
		$1216 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5A 59 5D 9D 5E 58 5B 5A C3}
		$1217 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5D 5A 58 9D 5B 5E 5F 58 C3}
		$1218 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 5D 5E 5F 58 9D 5A 58 59 C3}
		$1219 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 59 5E 5F 5D 5A 9D 58 58 C3}
		$1220 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 9D 5B 5F 5E 5D 58 59 59 C3}
		$1221 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5A 5F 58 9D 5E 5B 59 58 C3}
		$1222 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 59 9D 5A 5E 58 5B 5F 58 C3}
		$1223 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 9D 58 59 58 5E 5D 5A 5F C3}
		$1224 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5F 5B 58 5A 9D 58 5E 5D C3}
		$1225 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5E 5F 5D 5A 5B 58 5A 9D C3}
		$1226 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5E 5A 5F 5B 9D 5B 58 5D C3}
		$1227 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5D 59 5D 5F 58 5E 5B 9D C3}
		$1228 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 59 5E 5D 5F 9D 5E 5B 58 C3}
		$1229 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 58 5B 59 5E 5D 5F 5F 9D C3}
		$1230 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5E 5B 58 9D 59 5D 5F 5A C3}
		$1231 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 59 58 5D 5E 5D 5F 5B 9D C3}
		$1232 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5F 5F 5E 5D 5A 5B 9D 58 C3}
		$1233 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5F 5D 9D 5E 5B 5A 5A 58 C3}
		$1234 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5F 5E 58 5D 59 5D 5B 9D C3}
		$1235 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5B 5F 58 5D 5E 5D 59 9D C3}
		$1236 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5B 5D 5E 58 5F 59 5D 9D C3}
		$1237 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5B 5D 5E 5A 5E 59 9D 5F C3}
		$1238 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 9D 5F 59 5A 5B 5D C3}
		$1239 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5F 58 5A 5E 5D 5E 5B 59 C3}
		$1240 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5D 5D 5A 5F 5E 58 9D 5B C3}
		$1241 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5A 5B 9D 58 5E 5F 58 5D C3}
		$1242 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 9D 5B 5E 5A 5D 5F 5F 59 C3}
		$1243 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5A 59 5E 9D 5E 5D 5F C3}
		$1244 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 9D 5A 5B 59 58 5E 58 5F C3}
		$1245 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5F 5B 5D 58 5E 5A 59 9D C3}
		$1246 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5E 58 5F 5A 59 5B 5B 9D C3}
		$1247 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5D 5B 5F 5E 59 58 9D 5A C3}
		$1248 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5B 5A 58 5D 59 5F 9D 5F C3}
		$1249 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5A 5F 5B 9D 58 5E 59 5D C3}
		$1250 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5A 9D 58 5F 5E 5E 59 5D C3}
		$1251 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 59 9D 5D 5A 5E 58 5F 5F C3}
		$1252 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5D 58 9D 59 5A 5F 5E C3}
		$1253 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5E 58 5A 9D 5F 59 5B 59 C3}
		$1254 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 9D 5F 5D 58 5A 5E 59 58 C3}
		$1255 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5E 59 5F 5D 5D 9D 58 5A C3}
		$1256 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5F 5E 58 9D 59 5A 5B 5A C3}
		$1257 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 58 5D 5F 9D 5A 5E 5E C3}
		$1258 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5A 5E 58 9D 5D 58 5B 5F C3}
		$1259 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 9D 5B 5D 5E 5F 5A 59 5E C3}
		$1260 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5E 58 5D 5B 9D 5F 5A 5A C3}
		$1261 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5D 5F 5E 5A 5B 9D 5B 58 C3}
		$1262 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 9D 5E 5F 5A 58 5D 5D C3}
		$1263 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5B 5E 5D 58 5F 9D 59 5A C3}
		$1264 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5A 5D 5B 5E 59 5A 9D 5F C3}
		$1265 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 59 5E 5D 5B 9D 5F 5A 5E C3}
		$1266 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5F 5B 5F 5D 59 5E 9D 5A C3}
		$1267 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5E 5A 59 5D 59 9D 5F 5B C3}
		$1268 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5B 5E 5D 9D 5B 59 5A 5F C3}
		$1269 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 59 5B 5D 5A 5E 9D 5F 58 C3}
		$1270 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 59 5E 5D 5D 5F 5A 58 C3}
		$1271 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5E 5A 58 5F 58 59 9D 5D C3}
		$1272 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 59 5F 5E 58 9D 5A 5E C3}
		$1273 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 59 9D 5D 58 5B 5E 5A 5F C3}
		$1274 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 58 5A 5B 5D 9D 5F 5E 59 C3}
		$1275 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 5E 5A 5E 59 5F 5D 58 C3}
		$1276 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5E 5D 9D 5B 58 5F 59 59 C3}
		$1277 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5B 59 5D 5E 58 5F 9D 5D C3}
		$1278 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5B 58 9D 5E 5F 5D 59 5F C3}
		$1279 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 58 9D 59 5F 5E 59 5A C3}
		$1280 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 5D 58 5F 5B 59 58 C3}
		$1281 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 5B 5F 5B 58 5D 59 C3}
		$1282 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 8D 76 02 89 45 00 E9}
		$1283 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 83 EE FE E9}
		$1284 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 83 C6 02 E9}
		$1285 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 C6 02 98 83 ED 04 89 45 00 E9}
		$1286 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 8D 76 02 98 83 ED 04 89 45 00 E9}
		$1287 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 EE FE 83 ED 02 66 89 45 00 E9}
		$1288 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 8D 76 02 E9}
		$1289 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 EE FE 98 83 ED 04 89 45 00 E9}
		$1290 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 83 EE FE E9}
		$1291 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 8D 76 02 83 ED 04 89 45 00 E9}
		$1292 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 C6 02 83 ED 04 89 45 00 E9}
		$1293 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 8D 76 02 83 ED 02 66 89 45 00 E9}
		$1294 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 5D 5A 5A 5F 5B 9D 59 C3}
		$1295 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 59 5B 59 5A 5D 9D 5F C3}
		$1296 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 59 5E 5A 58 5B 5F 59 9D C3}
		$1297 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5D 5F 5E 9D 58 5A 59 58 C3}
		$1298 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5D 5F 5B 5E 9D 58 5A 5B C3}
		$1299 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 59 5D 9D 5E 5F 5A 5D 58 C3}
		$1300 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5E 5D 5B 9D 59 58 58 5F C3}
		$1301 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5E 9D 5F 59 5A 5D 58 5B C3}
		$1302 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 9D 5B 59 5E 5B 5D 58 5A C3}
		$1303 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5D 5E 5F 9D 5A 59 5A C3}
		$1304 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 9D 5F 5D 5E 5B 59 5A 5A C3}
		$1305 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 5F 58 5B 59 5B 5D 5E C3}
		$1306 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 58 5A 5F 5B 5E 5D 5D 9D C3}
		$1307 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 5E 59 5E 5D 5B 5A 9D C3}
		$1308 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5A 9D 5D 59 5B 59 5E 5F C3}
		$1309 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 5F 5A 59 5D 9D 5E C3}
		$1310 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5E 9D 58 5B 5F 59 58 5A C3}
		$1311 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5D 58 59 9D 5E 5A 5B 5F C3}
		$1312 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 59 5D 5D 58 5B 5F C3}
		$1313 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5A 5D 5B 9D 59 5F 5F 5E C3}
		$1314 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5D 59 5F 5E 58 58 5A 5B C3}
		$1315 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 5F 58 5B 5A 5A 59 9D C3}
		$1316 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5F 5A 59 58 5D 9D 5E 5A C3}
		$1317 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5A 5F 59 5B 5D 58 5B 9D C3}
		$1318 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5F 5E 5E 5A 5D 5B 59 9D C3}
		$1319 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 5F 5D 5B 5A 5A 9D C3}
		$1320 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 59 5A 5B 58 5B 5F 5E 5D C3}
		$1321 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 59 58 5B 5E 5F 5A 9D 5D C3}
		$1322 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5E 5A 58 5D 9D 59 5F 5B C3}
		$1323 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 5F 5E 58 9D 5D 5A 5E C3}
		$1324 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5A 5B 5E 58 5D 5F 9D 5B C3}
		$1325 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 9D 58 5D 5F 5A 5D 59 C3}
		$1326 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 5E 5A 5F 58 5D 9D 58 C3}
		$1327 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5F 5A 5B 5E 58 9D 59 5F C3}
		$1328 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5F 58 59 5B 5D 5E 9D 58 C3}
		$1329 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 59 5D 5F 9D 5A 58 5F C3}
		$1330 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5A 5F 5E 5D 58 58 59 9D C3}
		$1331 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 58 5B 5E 59 5D 9D 5F 59 C3}
		$1332 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 59 5D 5B 5F 58 5E 5A 5A C3}
		$1333 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 9D 5A 5F 59 58 5D 5E 5E C3}
		$1334 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5A 5B 5E 5D 5B 9D 59 58 C3}
		$1335 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 58 5F 5E 59 5D 5D 5A C3}
		$1336 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5D 58 59 9D 5E 5B 5A 5E C3}
		$1337 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 5A 5F 59 58 9D 5B 5B C3}
		$1338 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5D 58 5F 59 5B 9D 5E 5A C3}
		$1339 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 59 5F 59 58 9D 5E 5D 5B C3}
		$1340 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 83 C6 01 89 45 00 E9}
		$1341 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 46 89 45 00 E9}
		$1342 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 C6 01 83 ED 04 89 45 00 E9}
		$1343 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 8D 76 01 E9}
		$1344 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 83 C6 01 E9}
		$1345 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 83 EE FF 89 45 00 E9}
		$1346 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 EE FF 83 C5 02 88 14 07 E9}
		$1347 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 EE FF 83 C5 02 66 89 14 07 E9}
		$1348 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C6 01 83 C5 02 66 89 14 07 E9}
		$1349 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 83 EE FF 98 83 ED 04 89 45 00 E9}
		$1350 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 83 C6 01 98 83 ED 04 89 45 00 E9}
		$1351 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 8D 76 01 83 C5 02 66 89 14 07 E9}
		$1352 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 8D 76 01 89 45 00 E9}
		$1353 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1354 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1355 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1356 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 46 83 ED 02 66 89 45 00 E9}
		$1357 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 98 98 83 ED 04 89 45 00 E9}
		$1358 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1359 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1360 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1361 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 EE FF 83 ED 04 89 45 00 E9}
		$1362 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 83 EE FF E9}
		$1363 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1364 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1365 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 8D 76 01 88 14 07 E9}
		$1366 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 9D 5F 5D 5B 58 5D 59 5A C3}
		$1367 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 9D 5D 5B 59 5A 58 5F 5A C3}
		$1368 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5F 58 59 9D 5F 5B 5D 5A C3}
		$1369 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5D 59 58 5F 5A 5E 5B 5B C3}
		$1370 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 9D 58 5B 5D 5A 5A 5E 59 C3}
		$1371 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 5A 58 5E 5D 5B 9D 59 5D C3}
		$1372 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 59 58 5F 5B 5D 5D 5A 9D C3}
		$1373 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 5F 5D 5A 59 9D 5A 5B C3}
		$1374 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5B 58 5A 59 5F 9D 5E 58 C3}
		$1375 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5D 5B 5A 9D 58 5A 59 5F C3}
		$1376 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5D 58 59 58 9D 5A 5B 5F C3}
		$1377 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5A 59 9D 5F 5D 5B 58 5B C3}
		$1378 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5D 5E 59 5B 58 5B 5F 5A C3}
		$1379 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 8D 76 01 E9}
		$1380 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1381 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1382 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 8D 76 01 E9}
		$1383 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 EE FF 66 89 14 07 E9}
		$1384 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 C6 01 66 89 14 07 E9}
		$1385 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1386 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5F 59 5D 5A 5B 5B 5E 58 C3}
		$1387 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5F 58 5E 5A 5B 59 5D 59 C3}
		$1388 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1389 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1390 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 C6 01 83 ED 02 66 89 45 00 E9}
		$1391 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 5E 59 5F 58 9D 58 5A C3}
		$1392 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5B 59 5D 5F 58 5E 5E C3}
		$1393 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 98 98 83 ED 04 89 45 00 E9}
		$1394 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1395 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1396 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 8D 76 04 E9}
		$1397 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1398 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1399 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 83 EE FF E9}
		$1400 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1401 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 C6 01 83 ED 02 66 89 45 00 E9}
		$1402 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1403 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1404 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1405 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 8D 76 04 89 45 00 E9}
		$1406 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 46 E9}
		$1407 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 EE FF 88 14 07 E9}
		$1408 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 C6 01 88 14 07 E9}
		$1409 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 8D 76 01 66 89 14 07 E9}
		$1410 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 83 EE FF E9}
		$1411 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 83 C6 01 E9}
		$1412 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 46 88 14 07 E9}
		$1413 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 46 66 89 14 07 E9}
		$1414 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 46 83 C5 02 88 14 07 E9}
		$1415 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 83 EE FF E9}
		$1416 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 83 C6 01 E9}
		$1417 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 46 E9}
		$1418 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C6 01 83 C5 02 88 14 07 E9}
		$1419 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 83 ED 02 66 89 45 00 E9}
		$1420 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 98 98 83 ED 04 89 45 00 E9}
		$1421 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 8D 76 01 83 ED 04 89 45 00 E9}
		$1422 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1423 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 46 E9}
		$1424 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 46 66 89 45 00 E9}
		$1425 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 8D 76 01 98 83 ED 04 89 45 00 E9}
		$1426 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 46 98 83 ED 04 89 45 00 E9}
		$1427 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 8D 76 01 83 C5 02 88 14 07 E9}
		$1428 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 83 EE FF E9}
		$1429 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 46 E9}
		$1430 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 46 83 ED 04 89 45 00 E9}
		$1431 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 46 83 C5 02 66 89 14 07 E9}
		$1432 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5F 5D 9D 58 59 59 5B 5E C3}
		$1433 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5B 5F 5E 9D 58 5D 59 5A C3}
		$1434 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 59 5F 58 5E 9D 5D 5F 5B C3}
		$1435 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 59 5A 5B 9D 5F 58 58 5D C3}
		$1436 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 9D 59 5F 5D 58 5E 5A 5B C3}
		$1437 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5B 59 5F 5E 9D 5D 5A 58 C3}
		$1438 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5B 58 5A 5B 5F 5E 9D 5D C3}
		$1439 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 9D 5F 5B 5A 5B 58 59 C3}
		$1440 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 5B 5F 58 5E 59 5A 9D C3}
		$1441 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5E 5F 5D 5A 58 5B 9D 59 C3}
		$1442 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 5D 5F 5B 9D 5A 5F C3}
		$1443 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5B 5D 5A 5F 59 5E 58 59 C3}
		$1444 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 5F 5B 58 59 5D 5A 5E 9D C3}
		$1445 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 83 EE FF E9}
		$1446 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 46 E9}
		$1447 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 46 66 89 45 00 E9}
		$1448 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1449 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1450 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1451 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 98 98 83 ED 04 89 45 00 E9}
		$1452 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1453 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1454 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 46 83 ED 02 66 89 45 00 E9}
		$1455 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1456 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 83 ED 02 66 89 45 00 E9}
		$1457 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9}
		$1458 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9}
		$1459 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 83 C5 02 36 8A 02 66 89 45 00 E9}
		$1460 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 F7 D0 F7 D2 21 D0 89 45 04 9C 8F 45 00 E9}
		$1461 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E8 89 45 04 9C 8F 45 00 E9}
		$1462 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E0 89 45 04 9C 8F 45 00 E9}
		$1463 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9}
		$1464 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9}
		$1465 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 36 88 10 E9}
		$1466 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9}
		$1467 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1468 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 C6 01 83 ED 02 66 89 45 00 E9}
		$1469 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F7 55 00 66 8B 45 00 83 ED 02 66 21 45 04 9C 8F 45 00 E9}
		$1470 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1471 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1472 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1473 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 36 8B 00 66 89 45 00 E9}
		$1474 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1475 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1476 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 46 E9}
		$1477 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 83 ED 02 00 45 04 9C 8F 45 00 E9}
		$1478 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1479 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1480 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1481 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1482 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1483 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 46 66 89 45 00 E9}
		$1484 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1485 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1486 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 8A 4D 02 83 ED 02 D2 E0 66 89 45 04 9C 8F 45 00 E9}
		$1487 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9}
		$1488 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9}
		$1489 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 EE FC 83 ED 04 89 45 00 E9}
		$1490 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9}
		$1491 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 36 89 10 E9}
		$1492 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 83 C6 04 89 45 00 E9}
		$1493 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 C6 04 83 ED 04 89 45 00 E9}
		$1494 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 8A 4D 02 83 ED 02 D2 E8 66 89 45 04 9C 8F 45 00 E9}
		$1495 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 EE FC E9}
		$1496 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9}
		$1497 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9}
		$1498 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 58 5E 5D 5B 5B 9D 59 5F C3}
		$1499 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1500 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 46 E9}
		$1501 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 46 66 89 45 00 E9}
		$1502 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1503 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1504 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1505 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 46 E9}
		$1506 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 46 66 89 45 00 E9}
		$1507 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 83 ED 02 66 89 45 00 E9}
		$1508 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1509 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 8D 76 01 66 89 45 00 E9}
		$1510 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1511 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1512 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1513 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1514 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1515 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 46 66 89 45 00 E9}
		$1516 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 46 83 ED 02 66 89 45 00 E9}
		$1517 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1518 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 83 EE FF E9}
		$1519 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1520 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 46 E9}
		$1521 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1522 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1523 = {8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9}
		$1524 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 83 ED 02 66 89 45 00 E9}
		$1525 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 98 98 83 ED 04 89 45 00 E9}
		$1526 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1527 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1528 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 EE FF 83 C5 02 66 89 14 07 E9}
		$1529 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 83 C6 01 E9}
		$1530 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 46 E9}
		$1531 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 46 E9}
		$1532 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 46 89 45 00 E9}
		$1533 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 C6 01 83 ED 04 89 45 00 E9}
		$1534 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 46 88 14 07 E9}
		$1535 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 46 83 C5 02 88 14 07 E9}
		$1536 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 46 83 C5 02 66 89 14 07 E9}
		$1537 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 C6 01 66 89 14 07 E9}
		$1538 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 83 C6 01 E9}
		$1539 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 46 E9}
		$1540 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 83 EE FE 89 45 00 E9}
		$1541 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 83 C6 02 89 45 00 E9}
		$1542 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 C6 02 83 ED 04 89 45 00 E9}
		$1543 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 8D 76 02 E9}
		$1544 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 EE FE E9}
		$1545 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 C6 02 E9}
		$1546 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 83 EE FE 66 89 45 00 E9}
		$1547 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 83 C6 02 66 89 45 00 E9}
		$1548 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 C6 02 83 ED 02 66 89 45 00 E9}
		$1549 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 8D 76 02 83 ED 02 66 89 45 00 E9}
		$1550 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 EE FE 98 83 ED 04 89 45 00 E9}
		$1551 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 8D 76 02 66 89 45 00 E9}
		$1552 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 EE FE 83 ED 04 89 45 00 E9}
		$1553 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 E0 3C 8B 55 00 83 C5 04 89 14 07 E9}
		$1554 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 E0 3C 8B 14 07 83 ED 04 89 55 00 E9}
		$1555 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5F 58 5A 9D 5D 5E 5E 5B C3}
		$1556 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5E 5B 5F 5B 9D 58 5D 5A C3}
		$1557 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 83 ED 02 66 01 45 04 9C 8F 45 00 E9}
		$1558 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 8D 76 02 83 ED 04 89 45 00 E9}
		$1559 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 EE FE 83 ED 04 89 45 00 E9}
		$1560 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 C6 02 98 83 ED 04 89 45 00 E9}
		$1561 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 C6 02 83 ED 02 66 89 45 00 E9}
		$1562 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 83 C6 02 E9}
		$1563 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 83 C6 02 E9}
		$1564 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 83 EE FE 89 45 00 E9}
		$1565 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 83 C6 02 89 45 00 E9}
		$1566 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 8D 76 02 89 45 00 E9}
		$1567 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 8D 76 02 E9}
		$1568 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 83 EE FE E9}
		$1569 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 83 EE FE 66 89 45 00 E9}
		$1570 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 83 C6 02 66 89 45 00 E9}
		$1571 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 8D 76 02 E9}
		$1572 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 8D 76 02 98 83 ED 04 89 45 00 E9}
		$1573 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 EE FE 83 ED 02 66 89 45 00 E9}
		$1574 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 8D 76 02 66 89 45 00 E9}
		$1575 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 83 EE FF E9}
		$1576 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1577 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1578 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1579 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 83 C6 01 66 89 45 00 E9}
		$1580 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 8D 76 01 E9}
		$1581 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 8D 76 01 83 ED 04 89 45 00 E9}
		$1582 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 EE FF 83 ED 04 89 45 00 E9}
		$1583 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 8D 76 01 89 45 00 E9}
		$1584 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 98 98 83 ED 04 89 45 00 E9}
		$1585 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1586 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 04 07 83 ED 02 66 89 45 00 E9}
		$1587 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1588 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 8D 76 01 83 ED 02 66 89 45 00 E9}
		$1589 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 83 EE FF 66 89 45 00 E9}
		$1590 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 83 EE FF E9}
		$1591 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 98 98 83 ED 04 89 45 00 E9}
		$1592 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 55 00 83 C5 02 88 14 07 E9}
		$1593 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 55 00 83 C5 02 66 89 14 07 E9}
		$1594 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 8A 04 07 83 ED 02 66 89 45 00 E9}
		$1595 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1596 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 98 98 83 ED 04 89 45 00 E9}
		$1597 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 83 C6 01 E9}
		$1598 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 C6 01 83 ED 02 66 89 45 00 E9}
		$1599 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 46 83 ED 02 66 89 45 00 E9}
		$1600 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 8D 76 01 E9}
		$1601 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 8D 76 01 E9}
		$1602 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 83 EE FF E9}
		$1603 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 EE FF 88 14 07 E9}
		$1604 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C6 01 83 C5 02 66 89 14 07 E9}
		$1605 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 8D 76 01 88 14 07 E9}
		$1606 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 8D 76 01 66 89 14 07 E9}
		$1607 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 83 EE FF E9}
		$1608 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 46 66 89 14 07 E9}
		$1609 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 EE FF 83 ED 02 66 89 45 00 E9}
		$1610 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 EE FF 66 89 14 07 E9}
		$1611 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 C6 01 88 14 07 E9}
		$1612 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 8D 76 01 E9}
		$1613 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C6 01 83 C5 02 88 14 07 E9}
		$1614 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 83 C6 01 89 45 00 E9}
		$1615 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 46 83 ED 04 89 45 00 E9}
		$1616 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 8D 76 01 98 83 ED 04 89 45 00 E9}
		$1617 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 83 EE FF E9}
		$1618 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 83 C6 01 E9}
		$1619 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 83 EE FF 89 45 00 E9}
		$1620 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 8D 76 01 83 C5 02 88 14 07 E9}
		$1621 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 8D 76 01 83 C5 02 66 89 14 07 E9}
		$1622 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 EE FF 83 C5 02 88 14 07 E9}
		$1623 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 83 EE FF 98 83 ED 04 89 45 00 E9}
		$1624 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 83 C6 01 98 83 ED 04 89 45 00 E9}
		$1625 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 46 98 83 ED 04 89 45 00 E9}
		$1626 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06}
		$1627 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9}
		$1628 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9}
		$1629 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 6D 00 E9}
		$1630 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9}
		$1631 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9}
		$1632 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9}
		$1633 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 6D 00 E9}
		$1634 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06}
		$1635 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06}
		$1636 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06}
		$1637 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06}
		$1638 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58}
		$1639 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59}
		$1640 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A}
		$1641 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B}
		$1642 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 52}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint or $5 at entrypoint or $6 at entrypoint or $7 at entrypoint or $8 at entrypoint or $9 at entrypoint or $10 at entrypoint or $11 at entrypoint or $12 at entrypoint or $13 at entrypoint or $14 at entrypoint or $15 at entrypoint or $16 at entrypoint or $17 at entrypoint or $18 at entrypoint or $19 at entrypoint or $20 at entrypoint or $21 at entrypoint or $22 at entrypoint or $23 at entrypoint or $24 at entrypoint or $25 at entrypoint or $26 at entrypoint or $27 at entrypoint or $28 at entrypoint or $29 at entrypoint or $30 at entrypoint or $31 at entrypoint or $32 at entrypoint or $33 at entrypoint or $34 at entrypoint or $35 at entrypoint or $36 at entrypoint or $37 at entrypoint or $38 at entrypoint or $39 at entrypoint or $40 at entrypoint or $41 at entrypoint or $42 at entrypoint or $43 at entrypoint or $44 at entrypoint or $45 at entrypoint or $46 at entrypoint or $47 at entrypoint or $48 at entrypoint or $49 at entrypoint or $50 at entrypoint or $51 at entrypoint or $52 at entrypoint or $53 at entrypoint or $54 at entrypoint or $55 at entrypoint or $56 at entrypoint or $57 at entrypoint or $58 at entrypoint or $59 at entrypoint or $60 at entrypoint or $61 at entrypoint or $62 at entrypoint or $63 at entrypoint or $64 at entrypoint or $65 at entrypoint or $66 at entrypoint or $67 at entrypoint or $68 at entrypoint or $69 at entrypoint or $70 at entrypoint or $71 at entrypoint or $72 at entrypoint or $73 at entrypoint or $74 at entrypoint or $75 at entrypoint or $76 at entrypoint or $77 at entrypoint or $78 at entrypoint or $79 at entrypoint or $80 at entrypoint or $81 at entrypoint or $82 at entrypoint or $83 at entrypoint or $84 at entrypoint or $85 at entrypoint or $86 at entrypoint or $87 at entrypoint or $88 at entrypoint or $89 at entrypoint or $90 at entrypoint or $91 at entrypoint or $92 at entrypoint or $93 at entrypoint or $94 at entrypoint or $95 at entrypoint or $96 at entrypoint or $97 at entrypoint or $98 at entrypoint or $99 at entrypoint or $100 at entrypoint or $101 at entrypoint or $102 at entrypoint or $103 at entrypoint or $104 at entrypoint or $105 at entrypoint or $106 at entrypoint or $107 at entrypoint or $108 at entrypoint or $109 at entrypoint or $110 at entrypoint or $111 at entrypoint or $112 at entrypoint or $113 at entrypoint or $114 at entrypoint or $115 at entrypoint or $116 at entrypoint or $117 at entrypoint or $118 at entrypoint or $119 at entrypoint or $120 at entrypoint or $121 at entrypoint or $122 at entrypoint or $123 at entrypoint or $124 at entrypoint or $125 at entrypoint or $126 at entrypoint or $127 at entrypoint or $128 at entrypoint or $129 at entrypoint or $130 at entrypoint or $131 at entrypoint or $132 at entrypoint or $133 at entrypoint or $134 at entrypoint or $135 at entrypoint or $136 at entrypoint or $137 at entrypoint or $138 at entrypoint or $139 at entrypoint or $140 at entrypoint or $141 at entrypoint or $142 at entrypoint or $143 at entrypoint or $144 at entrypoint or $145 at entrypoint or $146 at entrypoint or $147 at entrypoint or $148 at entrypoint or $149 at entrypoint or $150 at entrypoint or $151 at entrypoint or $152 at entrypoint or $153 at entrypoint or $154 at entrypoint or $155 at entrypoint or $156 at entrypoint or $157 at entrypoint or $158 at entrypoint or $159 at entrypoint or $160 at entrypoint or $161 at entrypoint or $162 at entrypoint or $163 at entrypoint or $164 at entrypoint or $165 at entrypoint or $166 at entrypoint or $167 at entrypoint or $168 at entrypoint or $169 at entrypoint or $170 at entrypoint or $171 at entrypoint or $172 at entrypoint or $173 at entrypoint or $174 at entrypoint or $175 at entrypoint or $176 at entrypoint or $177 at entrypoint or $178 at entrypoint or $179 at entrypoint or $180 at entrypoint or $181 at entrypoint or $182 at entrypoint or $183 at entrypoint or $184 at entrypoint or $185 at entrypoint or $186 at entrypoint or $187 at entrypoint or $188 at entrypoint or $189 at entrypoint or $190 at entrypoint or $191 at entrypoint or $192 at entrypoint or $193 at entrypoint or $194 at entrypoint or $195 at entrypoint or $196 at entrypoint or $197 at entrypoint or $198 at entrypoint or $199 at entrypoint or $200 at entrypoint or $201 at entrypoint or $202 at entrypoint or $203 at entrypoint or $204 at entrypoint or $205 at entrypoint or $206 at entrypoint or $207 at entrypoint or $208 at entrypoint or $209 at entrypoint or $210 at entrypoint or $211 at entrypoint or $212 at entrypoint or $213 at entrypoint or $214 at entrypoint or $215 at entrypoint or $216 at entrypoint or $217 at entrypoint or $218 at entrypoint or $219 at entrypoint or $220 at entrypoint or $221 at entrypoint or $222 at entrypoint or $223 at entrypoint or $224 at entrypoint or $225 at entrypoint or $226 at entrypoint or $227 at entrypoint or $228 at entrypoint or $229 at entrypoint or $230 at entrypoint or $231 at entrypoint or $232 at entrypoint or $233 at entrypoint or $234 at entrypoint or $235 at entrypoint or $236 at entrypoint or $237 at entrypoint or $238 at entrypoint or $239 at entrypoint or $240 at entrypoint or $241 at entrypoint or $242 at entrypoint or $243 at entrypoint or $244 at entrypoint or $245 at entrypoint or $246 at entrypoint or $247 at entrypoint or $248 at entrypoint or $249 at entrypoint or $250 at entrypoint or $251 at entrypoint or $252 at entrypoint or $253 at entrypoint or $254 at entrypoint or $255 at entrypoint or $256 at entrypoint or $257 at entrypoint or $258 at entrypoint or $259 at entrypoint or $260 at entrypoint or $261 at entrypoint or $262 at entrypoint or $263 at entrypoint or $264 at entrypoint or $265 at entrypoint or $266 at entrypoint or $267 at entrypoint or $268 at entrypoint or $269 at entrypoint or $270 at entrypoint or $271 at entrypoint or $272 at entrypoint or $273 at entrypoint or $274 at entrypoint or $275 at entrypoint or $276 at entrypoint or $277 at entrypoint or $278 at entrypoint or $279 at entrypoint or $280 at entrypoint or $281 at entrypoint or $282 at entrypoint or $283 at entrypoint or $284 at entrypoint or $285 at entrypoint or $286 at entrypoint or $287 at entrypoint or $288 at entrypoint or $289 at entrypoint or $290 at entrypoint or $291 at entrypoint or $292 at entrypoint or $293 at entrypoint or $294 at entrypoint or $295 at entrypoint or $296 at entrypoint or $297 at entrypoint or $298 at entrypoint or $299 at entrypoint or $300 at entrypoint or $301 at entrypoint or $302 at entrypoint or $303 at entrypoint or $304 at entrypoint or $305 at entrypoint or $306 at entrypoint or $307 at entrypoint or $308 at entrypoint or $309 at entrypoint or $310 at entrypoint or $311 at entrypoint or $312 at entrypoint or $313 at entrypoint or $314 at entrypoint or $315 at entrypoint or $316 at entrypoint or $317 at entrypoint or $318 at entrypoint or $319 at entrypoint or $320 at entrypoint or $321 at entrypoint or $322 at entrypoint or $323 at entrypoint or $324 at entrypoint or $325 at entrypoint or $326 at entrypoint or $327 at entrypoint or $328 at entrypoint or $329 at entrypoint or $330 at entrypoint or $331 at entrypoint or $332 at entrypoint or $333 at entrypoint or $334 at entrypoint or $335 at entrypoint or $336 at entrypoint or $337 at entrypoint or $338 at entrypoint or $339 at entrypoint or $340 at entrypoint or $341 at entrypoint or $342 at entrypoint or $343 at entrypoint or $344 at entrypoint or $345 at entrypoint or $346 at entrypoint or $347 at entrypoint or $348 at entrypoint or $349 at entrypoint or $350 at entrypoint or $351 at entrypoint or $352 at entrypoint or $353 at entrypoint or $354 at entrypoint or $355 at entrypoint or $356 at entrypoint or $357 at entrypoint or $358 at entrypoint or $359 at entrypoint or $360 at entrypoint or $361 at entrypoint or $362 at entrypoint or $363 at entrypoint or $364 at entrypoint or $365 at entrypoint or $366 at entrypoint or $367 at entrypoint or $368 at entrypoint or $369 at entrypoint or $370 at entrypoint or $371 at entrypoint or $372 at entrypoint or $373 at entrypoint or $374 at entrypoint or $375 at entrypoint or $376 at entrypoint or $377 at entrypoint or $378 at entrypoint or $379 at entrypoint or $380 at entrypoint or $381 at entrypoint or $382 at entrypoint or $383 at entrypoint or $384 at entrypoint or $385 at entrypoint or $386 at entrypoint or $387 at entrypoint or $388 at entrypoint or $389 at entrypoint or $390 at entrypoint or $391 at entrypoint or $392 at entrypoint or $393 at entrypoint or $394 at entrypoint or $395 at entrypoint or $396 at entrypoint or $397 at entrypoint or $398 at entrypoint or $399 at entrypoint or $400 at entrypoint or $401 at entrypoint or $402 at entrypoint or $403 at entrypoint or $404 at entrypoint or $405 at entrypoint or $406 at entrypoint or $407 at entrypoint or $408 at entrypoint or $409 at entrypoint or $410 at entrypoint or $411 at entrypoint or $412 at entrypoint or $413 at entrypoint or $414 at entrypoint or $415 at entrypoint or $416 at entrypoint or $417 at entrypoint or $418 at entrypoint or $419 at entrypoint or $420 at entrypoint or $421 at entrypoint or $422 at entrypoint or $423 at entrypoint or $424 at entrypoint or $425 at entrypoint or $426 at entrypoint or $427 at entrypoint or $428 at entrypoint or $429 at entrypoint or $430 at entrypoint or $431 at entrypoint or $432 at entrypoint or $433 at entrypoint or $434 at entrypoint or $435 at entrypoint or $436 at entrypoint or $437 at entrypoint or $438 at entrypoint or $439 at entrypoint or $440 at entrypoint or $441 at entrypoint or $442 at entrypoint or $443 at entrypoint or $444 at entrypoint or $445 at entrypoint or $446 at entrypoint or $447 at entrypoint or $448 at entrypoint or $449 at entrypoint or $450 at entrypoint or $451 at entrypoint or $452 at entrypoint or $453 at entrypoint or $454 at entrypoint or $455 at entrypoint or $456 at entrypoint or $457 at entrypoint or $458 at entrypoint or $459 at entrypoint or $460 at entrypoint or $461 at entrypoint or $462 at entrypoint or $463 at entrypoint or $464 at entrypoint or $465 at entrypoint or $466 at entrypoint or $467 at entrypoint or $468 at entrypoint or $469 at entrypoint or $470 at entrypoint or $471 at entrypoint or $472 at entrypoint or $473 at entrypoint or $474 at entrypoint or $475 at entrypoint or $476 at entrypoint or $477 at entrypoint or $478 at entrypoint or $479 at entrypoint or $480 at entrypoint or $481 at entrypoint or $482 at entrypoint or $483 at entrypoint or $484 at entrypoint or $485 at entrypoint or $486 at entrypoint or $487 at entrypoint or $488 at entrypoint or $489 at entrypoint or $490 at entrypoint or $491 at entrypoint or $492 at entrypoint or $493 at entrypoint or $494 at entrypoint or $495 at entrypoint or $496 at entrypoint or $497 at entrypoint or $498 at entrypoint or $499 at entrypoint or $500 at entrypoint or $501 at entrypoint or $502 at entrypoint or $503 at entrypoint or $504 at entrypoint or $505 at entrypoint or $506 at entrypoint or $507 at entrypoint or $508 at entrypoint or $509 at entrypoint or $510 at entrypoint or $511 at entrypoint or $512 at entrypoint or $513 at entrypoint or $514 at entrypoint or $515 at entrypoint or $516 at entrypoint or $517 at entrypoint or $518 at entrypoint or $519 at entrypoint or $520 at entrypoint or $521 at entrypoint or $522 at entrypoint or $523 at entrypoint or $524 at entrypoint or $525 at entrypoint or $526 at entrypoint or $527 at entrypoint or $528 at entrypoint or $529 at entrypoint or $530 at entrypoint or $531 at entrypoint or $532 at entrypoint or $533 at entrypoint or $534 at entrypoint or $535 at entrypoint or $536 at entrypoint or $537 at entrypoint or $538 at entrypoint or $539 at entrypoint or $540 at entrypoint or $541 at entrypoint or $542 at entrypoint or $543 at entrypoint or $544 at entrypoint or $545 at entrypoint or $546 at entrypoint or $547 at entrypoint or $548 at entrypoint or $549 at entrypoint or $550 at entrypoint or $551 at entrypoint or $552 at entrypoint or $553 at entrypoint or $554 at entrypoint or $555 at entrypoint or $556 at entrypoint or $557 at entrypoint or $558 at entrypoint or $559 at entrypoint or $560 at entrypoint or $561 at entrypoint or $562 at entrypoint or $563 at entrypoint or $564 at entrypoint or $565 at entrypoint or $566 at entrypoint or $567 at entrypoint or $568 at entrypoint or $569 at entrypoint or $570 at entrypoint or $571 at entrypoint or $572 at entrypoint or $573 at entrypoint or $574 at entrypoint or $575 at entrypoint or $576 at entrypoint or $577 at entrypoint or $578 at entrypoint or $579 at entrypoint or $580 at entrypoint or $581 at entrypoint or $582 at entrypoint or $583 at entrypoint or $584 at entrypoint or $585 at entrypoint or $586 at entrypoint or $587 at entrypoint or $588 at entrypoint or $589 at entrypoint or $590 at entrypoint or $591 at entrypoint or $592 at entrypoint or $593 at entrypoint or $594 at entrypoint or $595 at entrypoint or $596 at entrypoint or $597 at entrypoint or $598 at entrypoint or $599 at entrypoint or $600 at entrypoint or $601 at entrypoint or $602 at entrypoint or $603 at entrypoint or $604 at entrypoint or $605 at entrypoint or $606 at entrypoint or $607 at entrypoint or $608 at entrypoint or $609 at entrypoint or $610 at entrypoint or $611 at entrypoint or $612 at entrypoint or $613 at entrypoint or $614 at entrypoint or $615 at entrypoint or $616 at entrypoint or $617 at entrypoint or $618 at entrypoint or $619 at entrypoint or $620 at entrypoint or $621 at entrypoint or $622 at entrypoint or $623 at entrypoint or $624 at entrypoint or $625 at entrypoint or $626 at entrypoint or $627 at entrypoint or $628 at entrypoint or $629 at entrypoint or $630 at entrypoint or $631 at entrypoint or $632 at entrypoint or $633 at entrypoint or $634 at entrypoint or $635 at entrypoint or $636 at entrypoint or $637 at entrypoint or $638 at entrypoint or $639 at entrypoint or $640 at entrypoint or $641 at entrypoint or $642 at entrypoint or $643 at entrypoint or $644 at entrypoint or $645 at entrypoint or $646 at entrypoint or $647 at entrypoint or $648 at entrypoint or $649 at entrypoint or $650 at entrypoint or $651 at entrypoint or $652 at entrypoint or $653 at entrypoint or $654 at entrypoint or $655 at entrypoint or $656 at entrypoint or $657 at entrypoint or $658 at entrypoint or $659 at entrypoint or $660 at entrypoint or $661 at entrypoint or $662 at entrypoint or $663 at entrypoint or $664 at entrypoint or $665 at entrypoint or $666 at entrypoint or $667 at entrypoint or $668 at entrypoint or $669 at entrypoint or $670 at entrypoint or $671 at entrypoint or $672 at entrypoint or $673 at entrypoint or $674 at entrypoint or $675 at entrypoint or $676 at entrypoint or $677 at entrypoint or $678 at entrypoint or $679 at entrypoint or $680 at entrypoint or $681 at entrypoint or $682 at entrypoint or $683 at entrypoint or $684 at entrypoint or $685 at entrypoint or $686 at entrypoint or $687 at entrypoint or $688 at entrypoint or $689 at entrypoint or $690 at entrypoint or $691 at entrypoint or $692 at entrypoint or $693 at entrypoint or $694 at entrypoint or $695 at entrypoint or $696 at entrypoint or $697 at entrypoint or $698 at entrypoint or $699 at entrypoint or $700 at entrypoint or $701 at entrypoint or $702 at entrypoint or $703 at entrypoint or $704 at entrypoint or $705 at entrypoint or $706 at entrypoint or $707 at entrypoint or $708 at entrypoint or $709 at entrypoint or $710 at entrypoint or $711 at entrypoint or $712 at entrypoint or $713 at entrypoint or $714 at entrypoint or $715 at entrypoint or $716 at entrypoint or $717 at entrypoint or $718 at entrypoint or $719 at entrypoint or $720 at entrypoint or $721 at entrypoint or $722 at entrypoint or $723 at entrypoint or $724 at entrypoint or $725 at entrypoint or $726 at entrypoint or $727 at entrypoint or $728 at entrypoint or $729 at entrypoint or $730 at entrypoint or $731 at entrypoint or $732 at entrypoint or $733 at entrypoint or $734 at entrypoint or $735 at entrypoint or $736 at entrypoint or $737 at entrypoint or $738 at entrypoint or $739 at entrypoint or $740 at entrypoint or $741 at entrypoint or $742 at entrypoint or $743 at entrypoint or $744 at entrypoint or $745 at entrypoint or $746 at entrypoint or $747 at entrypoint or $748 at entrypoint or $749 at entrypoint or $750 at entrypoint or $751 at entrypoint or $752 at entrypoint or $753 at entrypoint or $754 at entrypoint or $755 at entrypoint or $756 at entrypoint or $757 at entrypoint or $758 at entrypoint or $759 at entrypoint or $760 at entrypoint or $761 at entrypoint or $762 at entrypoint or $763 at entrypoint or $764 at entrypoint or $765 at entrypoint or $766 at entrypoint or $767 at entrypoint or $768 at entrypoint or $769 at entrypoint or $770 at entrypoint or $771 at entrypoint or $772 at entrypoint or $773 at entrypoint or $774 at entrypoint or $775 at entrypoint or $776 at entrypoint or $777 at entrypoint or $778 at entrypoint or $779 at entrypoint or $780 at entrypoint or $781 at entrypoint or $782 at entrypoint or $783 at entrypoint or $784 at entrypoint or $785 at entrypoint or $786 at entrypoint or $787 at entrypoint or $788 at entrypoint or $789 at entrypoint or $790 at entrypoint or $791 at entrypoint or $792 at entrypoint or $793 at entrypoint or $794 at entrypoint or $795 at entrypoint or $796 at entrypoint or $797 at entrypoint or $798 at entrypoint or $799 at entrypoint or $800 at entrypoint or $801 at entrypoint or $802 at entrypoint or $803 at entrypoint or $804 at entrypoint or $805 at entrypoint or $806 at entrypoint or $807 at entrypoint or $808 at entrypoint or $809 at entrypoint or $810 at entrypoint or $811 at entrypoint or $812 at entrypoint or $813 at entrypoint or $814 at entrypoint or $815 at entrypoint or $816 at entrypoint or $817 at entrypoint or $818 at entrypoint or $819 at entrypoint or $820 at entrypoint or $821 at entrypoint or $822 at entrypoint or $823 at entrypoint or $824 at entrypoint or $825 at entrypoint or $826 at entrypoint or $827 at entrypoint or $828 at entrypoint or $829 at entrypoint or $830 at entrypoint or $831 at entrypoint or $832 at entrypoint or $833 at entrypoint or $834 at entrypoint or $835 at entrypoint or $836 at entrypoint or $837 at entrypoint or $838 at entrypoint or $839 at entrypoint or $840 at entrypoint or $841 at entrypoint or $842 at entrypoint or $843 at entrypoint or $844 at entrypoint or $845 at entrypoint or $846 at entrypoint or $847 at entrypoint or $848 at entrypoint or $849 at entrypoint or $850 at entrypoint or $851 at entrypoint or $852 at entrypoint or $853 at entrypoint or $854 at entrypoint or $855 at entrypoint or $856 at entrypoint or $857 at entrypoint or $858 at entrypoint or $859 at entrypoint or $860 at entrypoint or $861 at entrypoint or $862 at entrypoint or $863 at entrypoint or $864 at entrypoint or $865 at entrypoint or $866 at entrypoint or $867 at entrypoint or $868 at entrypoint or $869 at entrypoint or $870 at entrypoint or $871 at entrypoint or $872 at entrypoint or $873 at entrypoint or $874 at entrypoint or $875 at entrypoint or $876 at entrypoint or $877 at entrypoint or $878 at entrypoint or $879 at entrypoint or $880 at entrypoint or $881 at entrypoint or $882 at entrypoint or $883 at entrypoint or $884 at entrypoint or $885 at entrypoint or $886 at entrypoint or $887 at entrypoint or $888 at entrypoint or $889 at entrypoint or $890 at entrypoint or $891 at entrypoint or $892 at entrypoint or $893 at entrypoint or $894 at entrypoint or $895 at entrypoint or $896 at entrypoint or $897 at entrypoint or $898 at entrypoint or $899 at entrypoint or $900 at entrypoint or $901 at entrypoint or $902 at entrypoint or $903 at entrypoint or $904 at entrypoint or $905 at entrypoint or $906 at entrypoint or $907 at entrypoint or $908 at entrypoint or $909 at entrypoint or $910 at entrypoint or $911 at entrypoint or $912 at entrypoint or $913 at entrypoint or $914 at entrypoint or $915 at entrypoint or $916 at entrypoint or $917 at entrypoint or $918 at entrypoint or $919 at entrypoint or $920 at entrypoint or $921 at entrypoint or $922 at entrypoint or $923 at entrypoint or $924 at entrypoint or $925 at entrypoint or $926 at entrypoint or $927 at entrypoint or $928 at entrypoint or $929 at entrypoint or $930 at entrypoint or $931 at entrypoint or $932 at entrypoint or $933 at entrypoint or $934 at entrypoint or $935 at entrypoint or $936 at entrypoint or $937 at entrypoint or $938 at entrypoint or $939 at entrypoint or $940 at entrypoint or $941 at entrypoint or $942 at entrypoint or $943 at entrypoint or $944 at entrypoint or $945 at entrypoint or $946 at entrypoint or $947 at entrypoint or $948 at entrypoint or $949 at entrypoint or $950 at entrypoint or $951 at entrypoint or $952 at entrypoint or $953 at entrypoint or $954 at entrypoint or $955 at entrypoint or $956 at entrypoint or $957 at entrypoint or $958 at entrypoint or $959 at entrypoint or $960 at entrypoint or $961 at entrypoint or $962 at entrypoint or $963 at entrypoint or $964 at entrypoint or $965 at entrypoint or $966 at entrypoint or $967 at entrypoint or $968 at entrypoint or $969 at entrypoint or $970 at entrypoint or $971 at entrypoint or $972 at entrypoint or $973 at entrypoint or $974 at entrypoint or $975 at entrypoint or $976 at entrypoint or $977 at entrypoint or $978 at entrypoint or $979 at entrypoint or $980 at entrypoint or $981 at entrypoint or $982 at entrypoint or $983 at entrypoint or $984 at entrypoint or $985 at entrypoint or $986 at entrypoint or $987 at entrypoint or $988 at entrypoint or $989 at entrypoint or $990 at entrypoint or $991 at entrypoint or $992 at entrypoint or $993 at entrypoint or $994 at entrypoint or $995 at entrypoint or $996 at entrypoint or $997 at entrypoint or $998 at entrypoint or $999 at entrypoint or $1000 at entrypoint or $1001 at entrypoint or $1002 at entrypoint or $1003 at entrypoint or $1004 at entrypoint or $1005 at entrypoint or $1006 at entrypoint or $1007 at entrypoint or $1008 at entrypoint or $1009 at entrypoint or $1010 at entrypoint or $1011 at entrypoint or $1012 at entrypoint or $1013 at entrypoint or $1014 at entrypoint or $1015 at entrypoint or $1016 at entrypoint or $1017 at entrypoint or $1018 at entrypoint or $1019 at entrypoint or $1020 at entrypoint or $1021 at entrypoint or $1022 at entrypoint or $1023 at entrypoint or $1024 at entrypoint or $1025 at entrypoint or $1026 at entrypoint or $1027 at entrypoint or $1028 at entrypoint or $1029 at entrypoint or $1030 at entrypoint or $1031 at entrypoint or $1032 at entrypoint or $1033 at entrypoint or $1034 at entrypoint or $1035 at entrypoint or $1036 at entrypoint or $1037 at entrypoint or $1038 at entrypoint or $1039 at entrypoint or $1040 at entrypoint or $1041 at entrypoint or $1042 at entrypoint or $1043 at entrypoint or $1044 at entrypoint or $1045 at entrypoint or $1046 at entrypoint or $1047 at entrypoint or $1048 at entrypoint or $1049 at entrypoint or $1050 at entrypoint or $1051 or $1052 at entrypoint or $1053 at entrypoint or $1054 at entrypoint or $1055 at entrypoint or $1056 at entrypoint or $1057 at entrypoint or $1058 at entrypoint or $1059 at entrypoint or $1060 at entrypoint or $1061 at entrypoint or $1062 at entrypoint or $1063 at entrypoint or $1064 at entrypoint or $1065 at entrypoint or $1066 at entrypoint or $1067 at entrypoint or $1068 at entrypoint or $1069 at entrypoint or $1070 at entrypoint or $1071 at entrypoint or $1072 at entrypoint or $1073 at entrypoint or $1074 at entrypoint or $1075 at entrypoint or $1076 at entrypoint or $1077 at entrypoint or $1078 at entrypoint or $1079 at entrypoint or $1080 at entrypoint or $1081 at entrypoint or $1082 at entrypoint or $1083 at entrypoint or $1084 at entrypoint or $1085 at entrypoint or $1086 at entrypoint or $1087 at entrypoint or $1088 at entrypoint or $1089 at entrypoint or $1090 at entrypoint or $1091 at entrypoint or $1092 at entrypoint or $1093 at entrypoint or $1094 at entrypoint or $1095 at entrypoint or $1096 at entrypoint or $1097 at entrypoint or $1098 at entrypoint or $1099 at entrypoint or $1100 at entrypoint or $1101 at entrypoint or $1102 at entrypoint or $1103 at entrypoint or $1104 at entrypoint or $1105 at entrypoint or $1106 at entrypoint or $1107 at entrypoint or $1108 at entrypoint or $1109 at entrypoint or $1110 at entrypoint or $1111 at entrypoint or $1112 at entrypoint or $1113 at entrypoint or $1114 at entrypoint or $1115 at entrypoint or $1116 at entrypoint or $1117 at entrypoint or $1118 at entrypoint or $1119 at entrypoint or $1120 at entrypoint or $1121 at entrypoint or $1122 at entrypoint or $1123 at entrypoint or $1124 at entrypoint or $1125 at entrypoint or $1126 at entrypoint or $1127 at entrypoint or $1128 at entrypoint or $1129 at entrypoint or $1130 at entrypoint or $1131 at entrypoint or $1132 at entrypoint or $1133 at entrypoint or $1134 at entrypoint or $1135 at entrypoint or $1136 at entrypoint or $1137 at entrypoint or $1138 at entrypoint or $1139 at entrypoint or $1140 at entrypoint or $1141 at entrypoint or $1142 at entrypoint or $1143 at entrypoint or $1144 at entrypoint or $1145 at entrypoint or $1146 at entrypoint or $1147 at entrypoint or $1148 at entrypoint or $1149 at entrypoint or $1150 at entrypoint or $1151 at entrypoint or $1152 at entrypoint or $1153 at entrypoint or $1154 at entrypoint or $1155 at entrypoint or $1156 at entrypoint or $1157 at entrypoint or $1158 at entrypoint or $1159 at entrypoint or $1160 at entrypoint or $1161 at entrypoint or $1162 at entrypoint or $1163 at entrypoint or $1164 at entrypoint or $1165 at entrypoint or $1166 at entrypoint or $1167 at entrypoint or $1168 at entrypoint or $1169 at entrypoint or $1170 at entrypoint or $1171 at entrypoint or $1172 at entrypoint or $1173 at entrypoint or $1174 at entrypoint or $1175 at entrypoint or $1176 at entrypoint or $1177 at entrypoint or $1178 at entrypoint or $1179 at entrypoint or $1180 at entrypoint or $1181 at entrypoint or $1182 at entrypoint or $1183 at entrypoint or $1184 at entrypoint or $1185 at entrypoint or $1186 at entrypoint or $1187 at entrypoint or $1188 at entrypoint or $1189 at entrypoint or $1190 at entrypoint or $1191 at entrypoint or $1192 at entrypoint or $1193 at entrypoint or $1194 at entrypoint or $1195 at entrypoint or $1196 at entrypoint or $1197 at entrypoint or $1198 at entrypoint or $1199 at entrypoint or $1200 at entrypoint or $1201 at entrypoint or $1202 at entrypoint or $1203 at entrypoint or $1204 at entrypoint or $1205 at entrypoint or $1206 at entrypoint or $1207 at entrypoint or $1208 at entrypoint or $1209 at entrypoint or $1210 at entrypoint or $1211 at entrypoint or $1212 at entrypoint or $1213 at entrypoint or $1214 at entrypoint or $1215 at entrypoint or $1216 at entrypoint or $1217 at entrypoint or $1218 at entrypoint or $1219 at entrypoint or $1220 at entrypoint or $1221 at entrypoint or $1222 at entrypoint or $1223 at entrypoint or $1224 at entrypoint or $1225 at entrypoint or $1226 at entrypoint or $1227 at entrypoint or $1228 at entrypoint or $1229 at entrypoint or $1230 at entrypoint or $1231 at entrypoint or $1232 at entrypoint or $1233 at entrypoint or $1234 at entrypoint or $1235 at entrypoint or $1236 at entrypoint or $1237 at entrypoint or $1238 at entrypoint or $1239 at entrypoint or $1240 at entrypoint or $1241 at entrypoint or $1242 at entrypoint or $1243 at entrypoint or $1244 at entrypoint or $1245 at entrypoint or $1246 at entrypoint or $1247 at entrypoint or $1248 at entrypoint or $1249 at entrypoint or $1250 at entrypoint or $1251 at entrypoint or $1252 at entrypoint or $1253 at entrypoint or $1254 at entrypoint or $1255 at entrypoint or $1256 at entrypoint or $1257 at entrypoint or $1258 at entrypoint or $1259 at entrypoint or $1260 at entrypoint or $1261 at entrypoint or $1262 at entrypoint or $1263 at entrypoint or $1264 at entrypoint or $1265 at entrypoint or $1266 at entrypoint or $1267 at entrypoint or $1268 at entrypoint or $1269 at entrypoint or $1270 at entrypoint or $1271 at entrypoint or $1272 at entrypoint or $1273 at entrypoint or $1274 at entrypoint or $1275 at entrypoint or $1276 at entrypoint or $1277 at entrypoint or $1278 at entrypoint or $1279 at entrypoint or $1280 at entrypoint or $1281 at entrypoint or $1282 at entrypoint or $1283 at entrypoint or $1284 at entrypoint or $1285 at entrypoint or $1286 at entrypoint or $1287 at entrypoint or $1288 at entrypoint or $1289 at entrypoint or $1290 at entrypoint or $1291 at entrypoint or $1292 at entrypoint or $1293 at entrypoint or $1294 at entrypoint or $1295 at entrypoint or $1296 at entrypoint or $1297 at entrypoint or $1298 at entrypoint or $1299 at entrypoint or $1300 at entrypoint or $1301 at entrypoint or $1302 at entrypoint or $1303 at entrypoint or $1304 at entrypoint or $1305 at entrypoint or $1306 at entrypoint or $1307 at entrypoint or $1308 at entrypoint or $1309 at entrypoint or $1310 at entrypoint or $1311 at entrypoint or $1312 at entrypoint or $1313 at entrypoint or $1314 at entrypoint or $1315 at entrypoint or $1316 at entrypoint or $1317 at entrypoint or $1318 at entrypoint or $1319 at entrypoint or $1320 at entrypoint or $1321 at entrypoint or $1322 at entrypoint or $1323 at entrypoint or $1324 at entrypoint or $1325 at entrypoint or $1326 at entrypoint or $1327 at entrypoint or $1328 at entrypoint or $1329 at entrypoint or $1330 at entrypoint or $1331 at entrypoint or $1332 at entrypoint or $1333 at entrypoint or $1334 at entrypoint or $1335 at entrypoint or $1336 at entrypoint or $1337 at entrypoint or $1338 at entrypoint or $1339 at entrypoint or $1340 at entrypoint or $1341 at entrypoint or $1342 at entrypoint or $1343 at entrypoint or $1344 at entrypoint or $1345 at entrypoint or $1346 at entrypoint or $1347 at entrypoint or $1348 at entrypoint or $1349 at entrypoint or $1350 at entrypoint or $1351 at entrypoint or $1352 at entrypoint or $1353 at entrypoint or $1354 at entrypoint or $1355 at entrypoint or $1356 at entrypoint or $1357 at entrypoint or $1358 at entrypoint or $1359 at entrypoint or $1360 at entrypoint or $1361 at entrypoint or $1362 at entrypoint or $1363 at entrypoint or $1364 at entrypoint or $1365 at entrypoint or $1366 at entrypoint or $1367 at entrypoint or $1368 at entrypoint or $1369 at entrypoint or $1370 at entrypoint or $1371 at entrypoint or $1372 at entrypoint or $1373 at entrypoint or $1374 at entrypoint or $1375 at entrypoint or $1376 at entrypoint or $1377 at entrypoint or $1378 at entrypoint or $1379 at entrypoint or $1380 at entrypoint or $1381 at entrypoint or $1382 at entrypoint or $1383 at entrypoint or $1384 at entrypoint or $1385 at entrypoint or $1386 at entrypoint or $1387 at entrypoint or $1388 at entrypoint or $1389 at entrypoint or $1390 at entrypoint or $1391 at entrypoint or $1392 at entrypoint or $1393 at entrypoint or $1394 at entrypoint or $1395 at entrypoint or $1396 at entrypoint or $1397 at entrypoint or $1398 at entrypoint or $1399 at entrypoint or $1400 at entrypoint or $1401 at entrypoint or $1402 at entrypoint or $1403 at entrypoint or $1404 at entrypoint or $1405 at entrypoint or $1406 at entrypoint or $1407 at entrypoint or $1408 at entrypoint or $1409 at entrypoint or $1410 at entrypoint or $1411 at entrypoint or $1412 at entrypoint or $1413 at entrypoint or $1414 at entrypoint or $1415 at entrypoint or $1416 at entrypoint or $1417 at entrypoint or $1418 at entrypoint or $1419 at entrypoint or $1420 at entrypoint or $1421 at entrypoint or $1422 at entrypoint or $1423 at entrypoint or $1424 at entrypoint or $1425 at entrypoint or $1426 at entrypoint or $1427 at entrypoint or $1428 at entrypoint or $1429 at entrypoint or $1430 at entrypoint or $1431 at entrypoint or $1432 at entrypoint or $1433 at entrypoint or $1434 at entrypoint or $1435 at entrypoint or $1436 at entrypoint or $1437 at entrypoint or $1438 at entrypoint or $1439 at entrypoint or $1440 at entrypoint or $1441 at entrypoint or $1442 at entrypoint or $1443 at entrypoint or $1444 at entrypoint or $1445 at entrypoint or $1446 at entrypoint or $1447 at entrypoint or $1448 at entrypoint or $1449 at entrypoint or $1450 at entrypoint or $1451 at entrypoint or $1452 at entrypoint or $1453 at entrypoint or $1454 at entrypoint or $1455 at entrypoint or $1456 at entrypoint or $1457 at entrypoint or $1458 at entrypoint or $1459 at entrypoint or $1460 at entrypoint or $1461 at entrypoint or $1462 at entrypoint or $1463 at entrypoint or $1464 at entrypoint or $1465 at entrypoint or $1466 at entrypoint or $1467 at entrypoint or $1468 at entrypoint or $1469 at entrypoint or $1470 at entrypoint or $1471 at entrypoint or $1472 at entrypoint or $1473 at entrypoint or $1474 at entrypoint or $1475 at entrypoint or $1476 at entrypoint or $1477 at entrypoint or $1478 at entrypoint or $1479 at entrypoint or $1480 at entrypoint or $1481 at entrypoint or $1482 at entrypoint or $1483 at entrypoint or $1484 at entrypoint or $1485 at entrypoint or $1486 at entrypoint or $1487 at entrypoint or $1488 at entrypoint or $1489 at entrypoint or $1490 at entrypoint or $1491 at entrypoint or $1492 at entrypoint or $1493 at entrypoint or $1494 at entrypoint or $1495 at entrypoint or $1496 at entrypoint or $1497 at entrypoint or $1498 at entrypoint or $1499 at entrypoint or $1500 at entrypoint or $1501 at entrypoint or $1502 at entrypoint or $1503 at entrypoint or $1504 at entrypoint or $1505 at entrypoint or $1506 at entrypoint or $1507 at entrypoint or $1508 at entrypoint or $1509 at entrypoint or $1510 at entrypoint or $1511 at entrypoint or $1512 at entrypoint or $1513 at entrypoint or $1514 at entrypoint or $1515 at entrypoint or $1516 at entrypoint or $1517 at entrypoint or $1518 at entrypoint or $1519 at entrypoint or $1520 at entrypoint or $1521 at entrypoint or $1522 at entrypoint or $1523 or $1524 at entrypoint or $1525 at entrypoint or $1526 at entrypoint or $1527 at entrypoint or $1528 at entrypoint or $1529 at entrypoint or $1530 at entrypoint or $1531 at entrypoint or $1532 at entrypoint or $1533 at entrypoint or $1534 at entrypoint or $1535 at entrypoint or $1536 at entrypoint or $1537 at entrypoint or $1538 at entrypoint or $1539 at entrypoint or $1540 at entrypoint or $1541 at entrypoint or $1542 at entrypoint or $1543 at entrypoint or $1544 at entrypoint or $1545 at entrypoint or $1546 at entrypoint or $1547 at entrypoint or $1548 at entrypoint or $1549 at entrypoint or $1550 at entrypoint or $1551 at entrypoint or $1552 at entrypoint or $1553 at entrypoint or $1554 at entrypoint or $1555 at entrypoint or $1556 at entrypoint or $1557 at entrypoint or $1558 at entrypoint or $1559 at entrypoint or $1560 at entrypoint or $1561 at entrypoint or $1562 at entrypoint or $1563 at entrypoint or $1564 at entrypoint or $1565 at entrypoint or $1566 at entrypoint or $1567 at entrypoint or $1568 at entrypoint or $1569 at entrypoint or $1570 at entrypoint or $1571 at entrypoint or $1572 at entrypoint or $1573 at entrypoint or $1574 at entrypoint or $1575 at entrypoint or $1576 at entrypoint or $1577 at entrypoint or $1578 at entrypoint or $1579 at entrypoint or $1580 at entrypoint or $1581 at entrypoint or $1582 at entrypoint or $1583 at entrypoint or $1584 at entrypoint or $1585 at entrypoint or $1586 at entrypoint or $1587 at entrypoint or $1588 at entrypoint or $1589 at entrypoint or $1590 at entrypoint or $1591 at entrypoint or $1592 at entrypoint or $1593 at entrypoint or $1594 at entrypoint or $1595 at entrypoint or $1596 at entrypoint or $1597 at entrypoint or $1598 at entrypoint or $1599 at entrypoint or $1600 at entrypoint or $1601 at entrypoint or $1602 at entrypoint or $1603 at entrypoint or $1604 at entrypoint or $1605 at entrypoint or $1606 at entrypoint or $1607 at entrypoint or $1608 at entrypoint or $1609 at entrypoint or $1610 at entrypoint or $1611 at entrypoint or $1612 at entrypoint or $1613 at entrypoint or $1614 at entrypoint or $1615 at entrypoint or $1616 at entrypoint or $1617 at entrypoint or $1618 at entrypoint or $1619 at entrypoint or $1620 at entrypoint or $1621 at entrypoint or $1622 at entrypoint or $1623 at entrypoint or $1624 at entrypoint or $1625 at entrypoint or $1626 at entrypoint or $1627 at entrypoint or $1628 at entrypoint or $1629 at entrypoint or $1630 at entrypoint or $1631 at entrypoint or $1632 at entrypoint or $1633 at entrypoint or $1634 at entrypoint or $1635 at entrypoint or $1636 at entrypoint or $1637 at entrypoint or $1638 at entrypoint or $1639 at entrypoint or $1640 at entrypoint or $1641 at entrypoint or $1642 at entrypoint
}
rule _UPX_050__070_
{
	meta:
		description = "UPX 0.50 - 0.70"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_LTC_13__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [LTC 1.3] --> Anorganix"
	strings:
		$0 = {54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9}
		$1 = {54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Turbo_C_1990_or_Turbo_C_1988_
{
	meta:
		description = "Turbo C 1990 or Turbo C 1988"
	strings:
		$0 = {BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 8B ?? ?? ?? 8B ?? ?? ?? 8E DA}
	condition:
		$0 at entrypoint
}
rule _nPack_V112002006Beta__NEOxuinC_
{
	meta:
		description = "nPack V1.1.200.2006.Beta -> NEOx/[uinC]"
	strings:
		$0 = {83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 EC 01 00 00 E8 F8 06 00 00 E8 03 06 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3}
	condition:
		$0 at entrypoint
}
rule _PKLITE_v100_v103_
{
	meta:
		description = "PKLITE v1.00, v1.03"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B}
	condition:
		$0 at entrypoint
}
rule _ASPack_v105b_
{
	meta:
		description = "ASPack v1.05b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_02_LCC_Win32_1x__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [LCC Win32 1.x] --> Anorganix"
	strings:
		$0 = {64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50}
		$1 = {64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Hyings_PEArmor_075exe__Hying_CCG_h_
{
	meta:
		description = "Hying's PE-Armor 0.75.exe -> Hying [CCG] (h)"
	strings:
		$0 = {00 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 ?? ?? 01 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 74 ?? ?? ?? 00 00 00 00 00}
	condition:
		$0
}
rule _tElock_v071b2_
{
	meta:
		description = "tElock v0.71b2"
	strings:
		$0 = {60 E8 44 11 00 00 C3 83}
	condition:
		$0 at entrypoint
}
rule _tElock_v090_
{
	meta:
		description = "tElock v0.90"
	strings:
		$0 = {E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B}
	condition:
		$0 at entrypoint
}
rule _STNPEE_113_
{
	meta:
		description = "STNPEE 1.13"
	strings:
		$0 = {55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v305c4_Unextr_Passwcheck_Vir_shield_
{
	meta:
		description = "WWPACK v3.05c4 (Unextr. Passw.check. Vir. shield)"
	strings:
		$0 = {03 05 C0 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _PEQuake_v006_by_fORGAT_
{
	meta:
		description = "PEQuake v0.06 by fORGAT"
	strings:
		$0 = {E8 A5 00 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 3D ?? 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? 00 00 5B ?? 00 00 6E ?? 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64}
	condition:
		$0
}
rule _FSG_v120_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cpp_
{
	meta:
		description = "FSG v1.20 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)"
	strings:
		$0 = {0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01}
		$1 = {0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Inbuild_v10_hard_
{
	meta:
		description = "Inbuild v1.0 [hard]"
	strings:
		$0 = {B9 ?? ?? BB ?? ?? 2E ?? ?? 2E ?? ?? 43 E2}
	condition:
		$0 at entrypoint
}
rule _PEBundle_v20b5__v23_
{
	meta:
		description = "PEBundle v2.0b5 - v2.3"
	strings:
		$0 = {9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt_v100v101_
{
	meta:
		description = "PE Crypt v1.00/v1.01"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_REALBasic__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [REALBasic] --> Anorganix"
	strings:
		$0 = {55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9}
		$1 = {55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PKLITE_v112_v115_v120_2_
{
	meta:
		description = "PKLITE v1.12, v1.15, v1.20 (2)"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 3B C4 73}
	condition:
		$0 at entrypoint
}
rule _Vx_Trivial25_
{
	meta:
		description = "Vx: Trivial.25"
	strings:
		$0 = {B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD}
	condition:
		$0 at entrypoint
}
rule _tElock_v099_Special_Build__heXer__forgot_
{
	meta:
		description = "tElock v0.99 Special Build -> heXer & forgot"
	strings:
		$0 = {E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00}
	condition:
		$0 at entrypoint
}
rule _Inno_Setup_Module_v2018_
{
	meta:
		description = "Inno Setup Module v2.0.18"
	strings:
		$0 = {55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8}
	condition:
		$0
}
rule _Upack_v036_beta__Dwing_
{
	meta:
		description = "Upack v0.36 beta -> Dwing"
	strings:
		$0 = {BE E0 11 ?? ?? FF 36 E9 C3 00 00 00 48 01 ?? ?? 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C}
	condition:
		$0 at entrypoint
}
rule _eXPressor_12__CGSoftLabs_
{
	meta:
		description = "eXPressor 1.2 -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E}
	condition:
		$0 at entrypoint
}
rule _SPEC_b3_
{
	meta:
		description = "SPEC b3"
	strings:
		$0 = {5B 53 50 45 43 5D E8 ?? ?? ?? ?? 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v123_RC4_build_0807_dll__Alexey_Solodovnikov_h_
{
	meta:
		description = "ASProtect v1.23 RC4 build 08.07 (dll) -> Alexey Solodovnikov (h)"
	strings:
		$0 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$1 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Compiler_
{
	meta:
		description = "Vx: Compiler"
	strings:
		$0 = {8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_C__Basic_NET_
{
	meta:
		description = "Microsoft Visual C# / Basic .NET"
	strings:
		$0 = {FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Turbo_C_or_Borland_Cpp_
{
	meta:
		description = "Turbo C or Borland C++"
	strings:
		$0 = {BA ?? ?? 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA}
	condition:
		$0 at entrypoint
}
rule _dePACK__deNULL_
{
	meta:
		description = "dePACK -> deNULL"
	strings:
		$0 = {EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? 00 00 E8 ?? 00 00 00}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v303_
{
	meta:
		description = "WWPACK v3.03"
	strings:
		$0 = {B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53}
	condition:
		$0 at entrypoint
}
rule _BeRo_Tiny_Pascal__BeRo_
{
	meta:
		description = "BeRo Tiny Pascal -> BeRo"
	strings:
		$0 = {E9 ?? ?? ?? ?? 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20}
		$1 = {E9 ?? ?? ?? ?? 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASProtect_V2X_DLL__Alexey_Solodovnikov_
{
	meta:
		description = "ASProtect V2.X DLL -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD}
	condition:
		$0 at entrypoint
}
rule _PC_Shrinker_v071_
{
	meta:
		description = "PC Shrinker v0.71"
	strings:
		$0 = {9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_CDCops_II__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [CD-Cops II] --> Anorganix"
	strings:
		$0 = {53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9}
		$1 = {53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _SafeDisc_v4_
{
	meta:
		description = "SafeDisc v4"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F}
	condition:
		$0
}
rule _PE_Password_v02_SMTSMF_
{
	meta:
		description = "PE Password v0.2 SMT/SMF"
	strings:
		$0 = {E8 04 ?? ?? ?? 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80}
	condition:
		$0 at entrypoint
}
rule _EncryptPE_V22006115__WFS_
{
	meta:
		description = "EncryptPE V2.2006.1.15 -> WFS"
	strings:
		$0 = {45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 36 2E 31 2E 31 35}
	condition:
		$0
}
rule _Krypton_v04_
{
	meta:
		description = "Krypton v0.4"
	strings:
		$0 = {54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06}
	condition:
		$0 at entrypoint
}
rule _Obsidium_v1331__Obsidium_Software_h_
{
	meta:
		description = "Obsidium v1.3.3.1 -> Obsidium Software (h)"
	strings:
		$0 = {EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b3_
{
	meta:
		description = "PECompact v1.10b3"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_Gleam_100__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Gleam 1.00] --> Anorganix"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _WATCOM_CCpp_RunTime_systempDOS4GW_DOS_Extender_198893_
{
	meta:
		description = "WATCOM C/C++ Run-Time system+DOS4GW DOS Extender 1988-93"
	strings:
		$0 = {BF ?? ?? 8E D7 81 C4 ?? ?? BE ?? ?? 2B F7 8B C6 B1 ?? D3}
	condition:
		$0 at entrypoint
}
rule _MS_RunTime_Library_1987_
{
	meta:
		description = "MS Run-Time Library 1987"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? 9A ?? ?? ?? ?? B8 ?? ?? 50 9A ?? ?? ?? ?? 92}
	condition:
		$0 at entrypoint
}
rule _Upack_V037V039__Dwing_
{
	meta:
		description = "Upack V0.37-V0.39 -> Dwing"
	strings:
		$0 = {BE ?? ?? ?? ?? AD 50 FF ?? ?? EB}
	condition:
		$0 at entrypoint
}
rule _PEncrypt_v31_
{
	meta:
		description = "PEncrypt v3.1"
	strings:
		$0 = {E9 ?? ?? ?? 00 F0 0F C6}
	condition:
		$0 at entrypoint
}
rule _PeCompact2_253276__BitSum_Technologies_
{
	meta:
		description = "PeCompact2 2.53-2.76 --> BitSum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 C9 11 00 10 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 5A 8B F8 50 52 8B 33 8B 43 20 03 C2 8B 08 89 4B 20 8B 43 1C 03 C2 8B 08 89 4B 1C 03 F2 8B 4B 0C 03 CA 8D 43 1C 50 57 56 FF}
	condition:
		$0
}
rule _PseudoSigner_02_Borland_Cpp_DLL_Method_2__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Borland C++ DLL (Method 2)] --> Anorganix"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90}
		$1 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Virogen_Crypt_v075_
{
	meta:
		description = "Virogen Crypt v0.75"
	strings:
		$0 = {9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01}
	condition:
		$0 at entrypoint
}
rule _Unknown_Protected_Mode_compiler_1_
{
	meta:
		description = "Unknown Protected Mode compiler (1)"
	strings:
		$0 = {FA BC ?? ?? 8C C8 8E D8 E8 ?? ?? E8 ?? ?? E8 ?? ?? 66 B8 ?? ?? ?? ?? 66 C1}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_ZCode_101__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [ZCode 1.01] --> Anorganix"
	strings:
		$0 = {E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00}
		$1 = {E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _JDPack_2x__JDPack_
{
	meta:
		description = "JDPack 2.x -> JDPack"
	strings:
		$0 = {55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_PE_Intro_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PE Intro 1.0] --> Anorganix"
	strings:
		$0 = {8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A}
		$1 = {8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _SEN_Debug_Protector_
{
	meta:
		description = "SEN Debug Protector???"
	strings:
		$0 = {BB ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 29 ?? ?? 4E E8}
	condition:
		$0 at entrypoint
}
rule _PECompact_v125_
{
	meta:
		description = "PECompact v1.25"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? F3 0D}
	condition:
		$0 at entrypoint
}
rule _REC_v032_
{
	meta:
		description = "REC v0.32"
	strings:
		$0 = {06 1E 52 B8 ?? ?? 1E CD 21 86 E0 3D}
	condition:
		$0 at entrypoint
}
rule _Sentinel_SuperPro_Automatic_Protection_v641__Safenet_
{
	meta:
		description = "Sentinel SuperPro (Automatic Protection) v6.4.1 -> Safenet"
	strings:
		$0 = {A1 ?? ?? ?? ?? 55 8B ?? ?? ?? 85 C0 74 ?? 85 ED 75 ?? A1 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 55 51 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 15 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 01 00 00 00 5D C2 0C 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_Lockless_Intro_Pack__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Lockless Intro Pack] --> Anorganix"
	strings:
		$0 = {2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD}
		$1 = {2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _tElock_v098_
{
	meta:
		description = "tElock v0.98"
	strings:
		$0 = {E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E}
	condition:
		$0 at entrypoint
}
rule _EXEStealth_v275a__WebtoolMaster_h_
{
	meta:
		description = "EXEStealth v2.75a -> WebtoolMaster (h)"
	strings:
		$0 = {EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72}
	condition:
		$0 at entrypoint
}
rule _NsPacK_V30__LiuXingPing_
{
	meta:
		description = "NsPacK V3.0 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74}
	condition:
		$0 at entrypoint
}
rule _PEPACK_v10_by_ANAKiN_1998__
{
	meta:
		description = "PE-PACK v1.0 by ANAKiN 1998 (???)"
	strings:
		$0 = {74 ?? E9 ?? ?? ?? ?? 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Software_Compress_V12__BG_Software_Protect_Technologies_
{
	meta:
		description = "Software Compress V1.2 -> BG Software Protect Technologies"
	strings:
		$0 = {E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00}
	condition:
		$0 at entrypoint
}
rule _ASPack_v212_
{
	meta:
		description = "ASPack v2.12"
	strings:
		$0 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB}
		$1 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_v50_
{
	meta:
		description = "Microsoft Visual C++ v5.0"
	strings:
		$0 = {55 8B EC 6A FF 68 68 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 53 56 57}
	condition:
		$0 at entrypoint
}
rule _NFO_v10_
{
	meta:
		description = "NFO v1.0"
	strings:
		$0 = {8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v305c4_Unextractable_
{
	meta:
		description = "WWPACK v3.05c4 (Unextractable)"
	strings:
		$0 = {03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _Crunch_V50__Bitarts_
{
	meta:
		description = "Crunch V5.0 -> Bitarts"
	strings:
		$0 = {EB 15 03 00 00 00 06}
	condition:
		$0 at entrypoint
}
rule _UPX_Protector_v10x_
{
	meta:
		description = "UPX Protector v1.0x"
	strings:
		$0 = {EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07}
	condition:
		$0 at entrypoint
}
rule _Obsidium_13017__Obsidium_software_
{
	meta:
		description = "Obsidium 1.3.0.17 -> Obsidium software"
	strings:
		$0 = {EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04}
	condition:
		$0 at entrypoint
}
rule _ACProtect_109g__Risco_software_Inc_
{
	meta:
		description = "ACProtect 1.09g -> Risco software Inc."
	strings:
		$0 = {60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00}
		$1 = {60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Obsidium_v1300__Obsidium_Software_h_
{
	meta:
		description = "Obsidium v1.3.0.0 -> Obsidium Software (h)"
	strings:
		$0 = {EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B 50 EB 03 8A 0B 93 33 C0 EB 02 28 B9 8B 00 EB 01 04 C3 EB 04 65 B3 54 0A E9 FA 00 00 00 EB 01 A2 E8 D5 FF FF FF EB 02 2B 49 EB 03 7C 3E 76 58 EB 04 B8 94 92 56 EB 01 72 64 67 8F 06 00 00 EB 02 23 72 83 C4 04 EB 02 A9 CB E8 47 26 00 00}
		$1 = {EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _XPEOR_v099b_
{
	meta:
		description = "X-PEOR v0.99b"
	strings:
		$0 = {E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00}
		$1 = {E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Basic_v60_
{
	meta:
		description = "Microsoft Visual Basic v6.0"
	strings:
		$0 = {FF 25 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF ?? ?? ?? ?? ?? ?? 30}
	condition:
		$0
}
rule _Themida_10xx__1800_compressed_engine__Oreans_Technologies_
{
	meta:
		description = "Themida 1.0.x.x - 1.8.0.0 (compressed engine) -> Oreans Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 5A ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01}
	condition:
		$0 at entrypoint
}
rule _UPX_v0896__v102__v105_v122_Delphi_stub_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 -v1.22 (Delphi) stub"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_4x__LCC_Win32_1x_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 4.x / LCC Win32 1.x)"
	strings:
		$0 = {2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB}
	condition:
		$0 at entrypoint
}
rule _Gardian_Angel_10_
{
	meta:
		description = "Gardian Angel 1.0"
	strings:
		$0 = {06 8C C8 8E D8 8E C0 FC BF ?? ?? EB}
	condition:
		$0 at entrypoint
}
rule _nBinder_v361_
{
	meta:
		description = "nBinder v3.6.1"
	strings:
		$0 = {6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C 00 5C 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C}
	condition:
		$0
}
rule _PECompact_v167_
{
	meta:
		description = "PECompact v1.67"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 8B 11}
	condition:
		$0 at entrypoint
}
rule _Vx_Einstein_
{
	meta:
		description = "Vx: Einstein"
	strings:
		$0 = {00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42}
	condition:
		$0 at entrypoint
}
rule _ReversingLabsProtector_074_beta__Ap0x_
{
	meta:
		description = "ReversingLabsProtector 0.7.4 beta -> Ap0x"
	strings:
		$0 = {68 00 00 41 00 E8 01 00 00 00 C3 C3}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_VideoLanClient__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Video-Lan-Client] --> Anorganix"
	strings:
		$0 = {55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9}
		$1 = {55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v146_
{
	meta:
		description = "PECompact v1.46"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12}
	condition:
		$0 at entrypoint
}
rule _MetaWare_High_C_RunTime_Library_p_Phar_Lap_DOS_Extender_198389_
{
	meta:
		description = "MetaWare High C Run-Time Library + Phar Lap DOS Extender 1983-89"
	strings:
		$0 = {B8 ?? ?? 50 B8 ?? ?? 50 CB}
	condition:
		$0 at entrypoint
}
rule _PECompact_v20_beta__Jeremy_Collake_
{
	meta:
		description = "PECompact v2.0 beta -> Jeremy Collake"
	strings:
		$0 = {B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90}
	condition:
		$0 at entrypoint
}
rule _kryptor_9_
{
	meta:
		description = "kryptor 9"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Borland_Cpp_1999_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland C++ 1999)"
	strings:
		$0 = {EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9}
	condition:
		$0 at entrypoint
}
rule _ShellModify_01__pll621_
{
	meta:
		description = "ShellModify 0.1 -> pll621"
	strings:
		$0 = {55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Ding_Boys_PElock_Phantasm_v08_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v0.8"
	strings:
		$0 = {55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00}
	condition:
		$0 at entrypoint
}
rule _Upack_v010__v012Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.10 - v0.12Beta -> Sign by hot_UNP"
	strings:
		$0 = {BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0}
	condition:
		$0 at entrypoint
}
rule _Upack_v029_Beta__v031_Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.29 Beta ~ v0.31 Beta -> Sign by hot_UNP"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3}
	condition:
		$0
}
rule _BopCrypt_v10_
{
	meta:
		description = "BopCrypt v1.0"
	strings:
		$0 = {60 BD ?? ?? ?? ?? E8 ?? ?? 00 00}
	condition:
		$0 at entrypoint
}
rule _FSG_v100_Eng__dulekxt_
{
	meta:
		description = "FSG v1.00 (Eng) -> dulek/xt"
	strings:
		$0 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38}
		$1 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _SLVc0deProtector_060__SLV__ICU_
{
	meta:
		description = "SLVc0deProtector 0.60 -> SLV / ICU"
	strings:
		$0 = {EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD}
	condition:
		$0
}
rule _ASPack_v10801_
{
	meta:
		description = "ASPack v1.08.01"
	strings:
		$0 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D}
		$1 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D}
		$2 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D}
		$3 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D}
		$4 = {60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9}
		$5 = {90 90 75 ?? 90 E9}
		$6 = {90 75 ?? 90 E9}
		$7 = {90 90 90 75 ?? 90 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint or $5 at entrypoint or $6 at entrypoint or $7 at entrypoint
}
rule _LCC_Win32_DLL_
{
	meta:
		description = "LCC Win32 DLL"
	strings:
		$0 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp__
{
	meta:
		description = "Microsoft Visual C++ ?.?"
	strings:
		$0 = {83 ?? ?? 6A 00 FF 15 F8 10 0B B0 8D ?? ?? ?? 51 6A 08 6A 00 6A 00 68}
	condition:
		$0 at entrypoint
}
rule _VProtector_V10E__vcasm_
{
	meta:
		description = "VProtector V1.0E -> vcasm"
	strings:
		$0 = {EB 0A 5B 56 50 72 6F 74 65 63 74 5D E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PENightMare_v13_
{
	meta:
		description = "PENightMare v1.3"
	strings:
		$0 = {60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v1xx__v2xx_
{
	meta:
		description = "Armadillo v1.xx - v2.xx"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6}
	condition:
		$0 at entrypoint
}
rule _WATCOM_CCpp_32_RunTime_System_19881995_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1995"
	strings:
		$0 = {E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54}
		$1 = {E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D ?? 43 2F 43 2B 2B 33 32 ?? 52 75}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__MASM32_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (MASM32)"
	strings:
		$0 = {EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A}
	condition:
		$0 at entrypoint
}
rule _Alloy_4x__PGWare_LLC_
{
	meta:
		description = "Alloy 4.x -> PGWare LLC"
	strings:
		$0 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68}
		$1 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _RatPacker_Glue_stub_
{
	meta:
		description = "RatPacker (Glue) stub"
	strings:
		$0 = {40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF}
		$1 = {40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF}
	condition:
		$0 at entrypoint or $1
}
rule _Microsoft_Visual_Basic_v50v60_
{
	meta:
		description = "Microsoft Visual Basic v5.0/v6.0"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 00 00 00 00 30 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PolyCrypt_PE__214b215__JLab_Software_Creations_hoep_
{
	meta:
		description = "PolyCrypt PE - 2.1.4b/2.1.5 -> JLab Software Creations (h-oep)"
	strings:
		$0 = {91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB}
	condition:
		$0
}
rule _Unknown_packer_04_
{
	meta:
		description = "Unknown packer (04)"
	strings:
		$0 = {BC ?? ?? C3 2E FF 2E ?? ?? CF}
	condition:
		$0 at entrypoint
}
rule _eXPressor_v12__CGSoftLabs_h_
{
	meta:
		description = "eXPressor v1.2 -> CGSoftLabs (h)"
	strings:
		$0 = {55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? ?? 2B 05 84 ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 16 A1 ?? ?? ?? ?? 03 05 80 ?? ?? ?? 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 68 04}
		$1 = {55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? ?? 2B 05 84 ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 16 A1 ?? ?? ?? ?? 03 05 80 ?? ?? ?? 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 68 04}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UNITA3_tm_by_Sanitary_Equipment_Research_
{
	meta:
		description = "UNITA3 (tm) by Sanitary Equipment Research"
	strings:
		$0 = {E8 ?? ?? 4D 5A 3E}
	condition:
		$0 at entrypoint
}
rule _Feokt_
{
	meta:
		description = "Feokt"
	strings:
		$0 = {89 25 A8 11 40 00 BF ?? ?? ?? 00 31 C0 B9 ?? ?? ?? 00 29 F9 FC F3 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8}
	condition:
		$0 at entrypoint
}
rule _PEBundle_v310_
{
	meta:
		description = "PEBundle v3.10"
	strings:
		$0 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01}
	condition:
		$0
}
rule _Private_EXE_Protector_18__SetiSoft_
{
	meta:
		description = "Private EXE Protector 1.8 -> SetiSoft"
	strings:
		$0 = {A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 FF 31 F6 C3}
	condition:
		$0
}
rule _SPEC_b2_
{
	meta:
		description = "SPEC b2"
	strings:
		$0 = {55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6}
	condition:
		$0 at entrypoint
}
rule _RCryptor_v16__Vaska_
{
	meta:
		description = "RCryptor v1.6 -> Vaska"
	strings:
		$0 = {33 D0 68 ?? ?? ?? ?? FF D2 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Pack_Master_10_PEX_Clone__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Pack Master 1.0 (PEX Clone)] --> Anorganix"
	strings:
		$0 = {60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FF FF E9}
		$1 = {60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
		$2 = {60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _ASPack_v211d_
{
	meta:
		description = "ASPack v2.11d"
	strings:
		$0 = {60 E8 02 00 00 00 EB 09 5D 55}
	condition:
		$0 at entrypoint
}
rule _ExeJoiner_10__Yoda_f2f_
{
	meta:
		description = "ExeJoiner 1.0 -> Yoda f2f"
	strings:
		$0 = {68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50}
		$1 = {68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Shrink_v20_
{
	meta:
		description = "Shrink v2.0"
	strings:
		$0 = {E9 ?? ?? 50 9C FC BE ?? ?? 8B FE 8C C8 05 ?? ?? 8E C0 06 57 B9}
	condition:
		$0 at entrypoint
}
rule _EPW_v12_
{
	meta:
		description = "EPW v1.2"
	strings:
		$0 = {06 57 1E 56 55 52 51 53 50 2E ?? ?? ?? ?? 8C C0 05 ?? ?? 2E ?? ?? ?? 8E D8 A1 ?? ?? 2E}
	condition:
		$0 at entrypoint
}
rule _AINEXE_v21_
{
	meta:
		description = "AINEXE v2.1"
	strings:
		$0 = {A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8 36 A3 ?? ?? 05 ?? ?? 36 A3 ?? ?? 2E A1 ?? ?? 8A D4 B1 04 D2 EA FE C9}
	condition:
		$0 at entrypoint
}
rule _MetaWare_High_C_p_Phar_Lap_DOS_Extender_198389_
{
	meta:
		description = "MetaWare High C + Phar Lap DOS Extender 1983-89"
	strings:
		$0 = {B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09}
	condition:
		$0 at entrypoint
}
rule _UPX_v0896__v102__v105__v122_DLL_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF}
	condition:
		$0 at entrypoint
}
rule _BeRoEXEPacker_v100_DLL_LZMA__BeRo__Farbrausch_
{
	meta:
		description = "BeRoEXEPacker v1.00 DLL [LZMA] -> BeRo / Farbrausch"
	strings:
		$0 = {83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8}
	condition:
		$0 at entrypoint
}
rule _MSLRH_V031__emadicius_
{
	meta:
		description = "[MSLRH] V0.31 -> emadicius"
	strings:
		$0 = {60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1}
	condition:
		$0 at entrypoint
}
rule _FSG_v120_Eng__dulekxt__MASM32__TASM32_
{
	meta:
		description = "FSG v1.20 (Eng) -> dulek/xt -> (MASM32 / TASM32)"
	strings:
		$0 = {33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE}
		$1 = {33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_SK_
{
	meta:
		description = "Vx: SK"
	strings:
		$0 = {CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09}
	condition:
		$0 at entrypoint
}
rule _Packanoid_10__ackanoid_
{
	meta:
		description = "Packanoid 1.0 -> ackanoid"
	strings:
		$0 = {BF 00 ?? 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 ?? ?? ?? 00 8B 30 8B 78 04 BB ?? ?? ?? 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 5E EB DB B9 ?? ?? 00 00 BE 00 ?? ?? 00 EB 01 00 BF ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _MingWin32_GCC_3x_
{
	meta:
		description = "MingWin32 GCC 3.x"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? 40 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _MingWin32_v_h_
{
	meta:
		description = "MingWin32 v?.? (h)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FE FF FF 90 8D B4 26 00 00 00 00 55}
	condition:
		$0 at entrypoint
}
rule _Thinstall_25___h_
{
	meta:
		description = "Thinstall 2.5 -> ??? (h)"
	strings:
		$0 = {55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D A7 1A 00 00 B9 6C 1A 00 00 BA 20 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD EC 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10}
	condition:
		$0 at entrypoint
}
rule _Hardlock_dongle_Alladin_
{
	meta:
		description = "Hardlock dongle (Alladin)"
	strings:
		$0 = {5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76}
	condition:
		$0 at entrypoint
}
rule _PGMPACK_v014_
{
	meta:
		description = "PGMPACK v0.14"
	strings:
		$0 = {1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3}
	condition:
		$0 at entrypoint
}
rule _Microsoft_C_for_Windows_2_
{
	meta:
		description = "Microsoft C for Windows (2)"
	strings:
		$0 = {8C D8 ?? 45 55 8B EC 1E 8E D8 57 56 89}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Cpp_19901992_
{
	meta:
		description = "Microsoft C++ (1990/1992)"
	strings:
		$0 = {B8 00 30 CD 21 3C 03 73 ?? 0E 1F BA ?? ?? B4 09 CD 21 06 33 C0 50 CB}
	condition:
		$0 at entrypoint
}
rule _Vx_CIH_Version_12_TTIT__WIN95CIH__
{
	meta:
		description = "Vx: CIH Version 1.2 TTIT (! WIN95CIH !)"
	strings:
		$0 = {55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D}
	condition:
		$0 at entrypoint
}
rule _MS_FORTRAN_Library_19_
{
	meta:
		description = "MS FORTRAN Library 19??"
	strings:
		$0 = {FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC B8 ?? ?? 8E C0 26 C7 ?? ?? ?? ?? ?? 26}
		$1 = {FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC 8C DB 8E C3 BB ?? ?? 9A ?? ?? ?? ?? 9B DB E3 9B D9 2E ?? ?? 33 C9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_60_DLL_Debug_
{
	meta:
		description = "Microsoft Visual C++ 6.0 DLL (Debug)"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 ?? ?? 83}
	condition:
		$0
}
rule _EXECryptor_224__StrongbitSoftComplete_Development_h1_
{
	meta:
		description = "EXECryptor 2.2.4 -> Strongbit/SoftComplete Development (h1)"
	strings:
		$0 = {E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3}
		$1 = {E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Private_EXE_Protector_197__SetiSoft_h_
{
	meta:
		description = "Private EXE Protector 1.9.7 -> SetiSoft (h)"
	strings:
		$0 = {55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB BA 00 00 00 80 C7 44 24 14 08 00 00 00 43 8D A4 24 00 00 00 00 8B FF 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 2C 8B 4C 24 10 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 02 44 24 0C 88 07 47 EB C6 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 82 6E 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 83 DC 00 00 00 B9 04 00 00 00 33 C0 8D A4 24 00 00 00 00 8D 64 24 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 48 74 B1 0F 89 EF 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 42 BD 00 01 00 00 B9 08 00 00 00 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 88 07 47 4D 75 D6}
	condition:
		$0
}
rule _Free_Pascal_v1010_win32_GUI_
{
	meta:
		description = "Free Pascal v1.0.10 (win32 GUI)"
	strings:
		$0 = {C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5}
	condition:
		$0
}
rule _EXE_Shield_v01b__v03b_v03__SMoKE_
{
	meta:
		description = "EXE Shield v0.1b - v0.3b, v0.3 -> SMoKE"
	strings:
		$0 = {E8 04 00 00 00 83 60 EB 0C 5D EB 05}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v20_
{
	meta:
		description = "ASProtect v2.0"
	strings:
		$0 = {68 01 ?? 40 00 E8 01 00 00 00 C3 C3}
	condition:
		$0
}
rule _EXE_Stealth_v272_
{
	meta:
		description = "EXE Stealth v2.72"
	strings:
		$0 = {EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20}
	condition:
		$0 at entrypoint
}
rule _SecureEXE_30__ZipWorx_
{
	meta:
		description = "SecureEXE 3.0 -> ZipWorx"
	strings:
		$0 = {E9 B8 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _RARSFX_Archive_1_
{
	meta:
		description = "RAR-SFX Archive (1)"
	strings:
		$0 = {4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 53 46 58}
	condition:
		$0
}
rule _eXPressor_v14__CGSoftLabs_
{
	meta:
		description = "eXPressor v1.4 -> CGSoftLabs"
	strings:
		$0 = {65 58 50 72 2D 76 2E 31 2E 34 2E}
	condition:
		$0
}
rule _tElock_v098b1_
{
	meta:
		description = "tElock v0.98b1"
	strings:
		$0 = {E9 25 E4 FF FF}
	condition:
		$0 at entrypoint
}
rule _Elicense_System_V4000__ViaTech_Inc_
{
	meta:
		description = "Elicense System V4.0.0.0 -> ViaTech Inc"
	strings:
		$0 = {00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00}
	condition:
		$0
}
rule _VOB_ProtectCD_
{
	meta:
		description = "VOB ProtectCD"
	strings:
		$0 = {5F 81 EF ?? ?? ?? ?? BE ?? ?? 40 ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7 ?? ?? ?? ?? FF 10 89 87 ?? ?? ?? ?? 5E 5F}
	condition:
		$0 at entrypoint
}
rule _PowerBASICCC_40_
{
	meta:
		description = "PowerBASIC/CC 4.0"
	strings:
		$0 = {55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 68 05 00 00 E9 6E 03}
	condition:
		$0 at entrypoint
}
rule _Upack_v030_beta__Dwing_
{
	meta:
		description = "Upack v0.30 beta -> Dwing"
	strings:
		$0 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30}
	condition:
		$0 at entrypoint
}
rule _MoleBox_v20_
{
	meta:
		description = "MoleBox v2.0"
	strings:
		$0 = {E8 ?? ?? ?? ?? 60 E8 4F}
	condition:
		$0
}
rule _BookManager_v9510_
{
	meta:
		description = "BookManager v9510"
	strings:
		$0 = {FC A3 ?? ?? 89 1E ?? ?? 49 89 0E ?? ?? BB ?? ?? 8C 1F 83 ?? ?? 89 ?? ?? B8 ?? ?? 50 89 ?? ?? F7 D0 50}
	condition:
		$0 at entrypoint
}
rule _Stealth_PE_v11_
{
	meta:
		description = "Stealth PE v1.1"
	strings:
		$0 = {BA ?? ?? ?? 00 FF E2 BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2}
	condition:
		$0 at entrypoint
}
rule _BeRoEXEPacker_v100_DLL__BeRo__Farbrausch_
{
	meta:
		description = "BeRoEXEPacker v1.00 (DLL) -> BeRo / Farbrausch"
	strings:
		$0 = {83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 BA ?? ?? ?? ?? 8D B2}
		$1 = {83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10}
		$2 = {83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8}
		$3 = {83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _PEArmor_V07X__Hying_
{
	meta:
		description = "PEArmor V0.7X -> Hying"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 81 C5 ?? ?? ?? ?? 55 C3}
	condition:
		$0 at entrypoint
}
rule _PECompact_v166_
{
	meta:
		description = "PECompact v1.66"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11}
	condition:
		$0 at entrypoint
}
rule _EXE_Stealth_v25_
{
	meta:
		description = "EXE Stealth v2.5"
	strings:
		$0 = {60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC}
		$1 = {60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC}
	condition:
		$0 or $1
}
rule _UPXShit_v01__500mhz_
{
	meta:
		description = "UPX-Shit v0.1 -> 500mhz"
	strings:
		$0 = {E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79}
		$1 = {E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79}
		$2 = {E8 ?? ?? ?? ?? 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _PESHiELD_v02__v02b__v02b2_
{
	meta:
		description = "PESHiELD v0.2 / v0.2b / v0.2b2"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04}
	condition:
		$0 at entrypoint
}
rule _RLPack_V112V114_LZMA_430__ap0x_
{
	meta:
		description = "RLPack V1.12-V1.14 (LZMA 4.30) -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? 60}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v253b3_
{
	meta:
		description = "Armadillo v2.53b3"
	strings:
		$0 = {55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_PE_Protect_09__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PE Protect 0.9] --> Anorganix"
	strings:
		$0 = {52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3}
		$1 = {52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _nbuild_v10_soft_
{
	meta:
		description = "nbuild v1.0 [soft]"
	strings:
		$0 = {B9 ?? ?? BB ?? ?? C0 ?? ?? 80 ?? ?? 43 E2}
	condition:
		$0 at entrypoint
}
rule _hyings_PEArmor_V076__hying_
{
	meta:
		description = "hying's PEArmor V0.76 -> hying"
	strings:
		$0 = {E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00}
	condition:
		$0 at entrypoint
}
rule _USERNAME_v300_
{
	meta:
		description = "USERNAME v3.00"
	strings:
		$0 = {FB 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 8C C8 2B C1 8B C8 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 33 C0 8E D8 06 0E 07 FC 33 F6}
	condition:
		$0 at entrypoint
}
rule _SDProtector_Pro_Edition_116__Randy_Li_h_
{
	meta:
		description = "SDProtector Pro Edition 1.16 -> Randy Li (h)"
	strings:
		$0 = {55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41}
	condition:
		$0 at entrypoint
}
rule _North_Star_PE_Shrinker_v13_by_Liuxingping_
{
	meta:
		description = "North Star PE Shrinker v1.3 by Liuxingping"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01}
	condition:
		$0
}
rule _RSCs_Process_Patcher_v151_
{
	meta:
		description = "R!SC's Process Patcher v1.5.1"
	strings:
		$0 = {68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83}
	condition:
		$0
}
rule _ARCSFX_Archive_
{
	meta:
		description = "ARC-SFX Archive"
	strings:
		$0 = {8C C8 8C DB 8E D8 8E C0 89 ?? ?? ?? 2B C3 A3 ?? ?? 89 ?? ?? ?? BE ?? ?? B9 ?? ?? BF ?? ?? BA ?? ?? FC AC 32 C2 8A D8}
	condition:
		$0 at entrypoint
}
rule _hmimys_Protect_v10_
{
	meta:
		description = "hmimys Protect v1.0"
	strings:
		$0 = {E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 00 00 00}
	condition:
		$0 at entrypoint
}
rule _SimplePack_V10X__bagie_
{
	meta:
		description = "SimplePack V1.0X -> bagie"
	strings:
		$0 = {60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 ?? ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_
{
	meta:
		description = "Microsoft Visual C++ v6.0"
	strings:
		$0 = {55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B}
		$1 = {55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 89 65 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF}
		$2 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57}
	condition:
		$0 at entrypoint or $1 or $2
}
rule _Nakedbind_10__nakedcrew_
{
	meta:
		description = "Nakedbind 1.0 -> nakedcrew"
	strings:
		$0 = {64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00}
	condition:
		$0 at entrypoint
}
rule _tElock_v092a_
{
	meta:
		description = "tElock v0.92a"
	strings:
		$0 = {E9 7E E9 FF FF 00}
	condition:
		$0 at entrypoint
}
rule _DxPack_V086__Dxd_
{
	meta:
		description = "DxPack V0.86 -> Dxd"
	strings:
		$0 = {60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00}
		$1 = {60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v251_
{
	meta:
		description = "Armadillo v2.51"
	strings:
		$0 = {55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v261_
{
	meta:
		description = "Armadillo v2.61"
	strings:
		$0 = {55 8B EC 6A FF 68 28 ?? ?? ?? 68 E4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 0C}
	condition:
		$0 at entrypoint
}
rule _Vx_Modification_of_Hi924_
{
	meta:
		description = "Vx: Modification of Hi.924"
	strings:
		$0 = {50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B}
	condition:
		$0 at entrypoint
}
rule _Inno_Setup_Module_v304betav306v307_
{
	meta:
		description = "Inno Setup Module v3.0.4-beta/v3.0.6/v3.0.7"
	strings:
		$0 = {55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C}
	condition:
		$0
}
rule _ZCode_Win32PE_Protector_v101_
{
	meta:
		description = "ZCode Win32/PE Protector v1.01"
	strings:
		$0 = {E9 12 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 FB FF FF FF C3 68 ?? ?? ?? ?? 64 FF 35}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v50_
{
	meta:
		description = "Microsoft Visual Basic v5.0"
	strings:
		$0 = {FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v123_RC4_build_0807_exe__Alexey_Solodovnikov_h_
{
	meta:
		description = "ASProtect v1.23 RC4 build 08.07 (exe) -> Alexey Solodovnikov (h)"
	strings:
		$0 = {90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$1 = {90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 or $1
}
rule _ASPack_v107b_
{
	meta:
		description = "ASPack v1.07b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE}
		$1 = {90 90 75 ?? E9}
		$2 = {90 90 90 75 ?? E9}
		$3 = {90 75 ?? E9}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _MS_RunTime_Library_OS2__FORTRAN_Compiler_1989_
{
	meta:
		description = "MS Run-Time Library (OS/2) & FORTRAN Compiler 1989"
	strings:
		$0 = {B4 30 CD 21 86 E0 2E A3 ?? ?? 3D ?? ?? 73}
	condition:
		$0 at entrypoint
}
rule _PECompact_v200_alpha_38_
{
	meta:
		description = "PECompact v2.00 alpha 38"
	strings:
		$0 = {B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F}
	condition:
		$0
}
rule _Microsoft_Visual_Cpp_v50v60_MFC_
{
	meta:
		description = "Microsoft Visual C++ v5.0/v6.0 (MFC)"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_CodeLock__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Code-Lock] --> Anorganix"
	strings:
		$0 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9}
		$1 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_Microsoft_Visual_Cpp_60_Debug_Version__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual C++ 6.0 (Debug Version)] --> Anorganix"
	strings:
		$0 = {55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 10 01 90 90 90 90 90 90 90 90 E8 00 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 E9}
		$1 = {55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90}
		$2 = {55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Unknown_packer_03_
{
	meta:
		description = "Unknown packer (03)"
	strings:
		$0 = {06 1E 57 56 50 53 51 52 BD ?? ?? 0E 1F 8C}
	condition:
		$0 at entrypoint
}
rule _PECompact_v123b3__v1241_
{
	meta:
		description = "PECompact v1.23b3 - v1.24.1"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 08}
	condition:
		$0 at entrypoint
}
rule _Upack_021_beta__Dwing_
{
	meta:
		description = "Upack 0.21 beta -> Dwing"
	strings:
		$0 = {BE 88 01 40 00 AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00}
	condition:
		$0 at entrypoint
}
rule _Unknown_by_SMT_
{
	meta:
		description = "Unknown by SMT"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 83 ?? ?? 57 EB}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_DxPack_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [DxPack 1.0] --> Anorganix"
	strings:
		$0 = {60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9}
		$1 = {60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _AVPACK_v120_
{
	meta:
		description = "AVPACK v1.20"
	strings:
		$0 = {50 1E 0E 1F 16 07 33 F6 8B FE B9 ?? ?? FC F3 A5 06 BB ?? ?? 53 CB}
	condition:
		$0 at entrypoint
}
rule _DxPack_10_
{
	meta:
		description = "DxPack 1.0"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84}
	condition:
		$0 at entrypoint
}
rule _Vx_Hafen1641_
{
	meta:
		description = "Vx: Hafen.1641"
	strings:
		$0 = {E8 ?? ?? 01 ?? ?? ?? CE CC 25 ?? ?? 25 ?? ?? 25 ?? ?? 40 51 D4 ?? ?? ?? CC 47 CA ?? ?? 46 8A CC 44 88 CC}
	condition:
		$0 at entrypoint
}
rule _PocketPC_MIB_
{
	meta:
		description = "PocketPC MIB"
	strings:
		$0 = {E8 FF BD 27 14 00 BF AF 18 00 A4 AF 1C 00 A5 AF 20 00 A6 AF 24 00 A7 AF ?? ?? ?? 0C 00 00 00 00 18 00 A4 8F 1C 00 A5 8F 20 00 A6 8F ?? ?? ?? 0C 24 00 A7 8F ?? ?? ?? 0C 25 20 40 00 14 00 BF 8F 08 00 E0 03 18 00 BD 27 ?? FF BD 27 18 00 ?? AF ?? 00}
	condition:
		$0 at entrypoint
}
rule _PEncrypt_v10_
{
	meta:
		description = "PEncrypt v1.0"
	strings:
		$0 = {60 9C BE 00 10 40 00 8B FE B9 28 03 00 00 BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61}
	condition:
		$0 at entrypoint
}
rule _pirit_v15_
{
	meta:
		description = "$pirit v1.5"
	strings:
		$0 = {5B 24 55 50 44 FB 32 2E 31 5D}
	condition:
		$0 at entrypoint
}
rule _Go32Stub_v200T_DOSExtender_
{
	meta:
		description = "Go32Stub v.2.00T DOS-Extender"
	strings:
		$0 = {0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 3C}
	condition:
		$0 at entrypoint
}
rule _SuperDAT_
{
	meta:
		description = "SuperDAT"
	strings:
		$0 = {55 8B EC 6A FF 68 40 F3 42 00 68 A4 BF 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 F2 42 00 33 D2 8A D4 89 15 60 42 43 00 8B C8 81 E1 FF 00 00 00 89 0D}
	condition:
		$0 at entrypoint
}
rule _Upack_v037_beta__Dwing_
{
	meta:
		description = "Upack v0.37 beta -> Dwing"
	strings:
		$0 = {BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _eXPressor_v13__CGSoftLabs_h_
{
	meta:
		description = "eXPressor v1.3 -> CGSoftLabs (h)"
	strings:
		$0 = {55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 13 A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 ?? ?? E9 ?? ?? 00 00 C7 05}
	condition:
		$0 at entrypoint
}
rule _NsPack_V11__LiuXingPing_
{
	meta:
		description = "NsPack V1.1 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00}
	condition:
		$0 at entrypoint
}
rule _BobPack_v100__BoB__BobSoft_
{
	meta:
		description = "BobPack v1.00 --> BoB / BobSoft"
	strings:
		$0 = {60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01}
	condition:
		$0 at entrypoint
}
rule _Armadillo_300a__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo 3.00a -> Silicon Realms Toolworks"
	strings:
		$0 = {60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F}
		$1 = {60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MS_RunTime_Library_1990_1992_09_
{
	meta:
		description = "MS Run-Time Library 1990, 1992 (09)"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? C3 8C DF 8B 36 ?? ?? 2E}
	condition:
		$0 at entrypoint
}
rule _Upack_v039_final__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.39 final -> Sign by hot_UNP"
	strings:
		$0 = {56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91}
		$1 = {FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF}
	condition:
		$0 or $1
}
rule _VideoLanClient__UnknownCompiler_
{
	meta:
		description = "Video-Lan-Client -> (UnknownCompiler)"
	strings:
		$0 = {55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _PEnguinCrypt_v10_
{
	meta:
		description = "PEnguinCrypt v1.0"
	strings:
		$0 = {B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0}
	condition:
		$0 at entrypoint
}
rule _Inno_Setup_Module_
{
	meta:
		description = "Inno Setup Module"
	strings:
		$0 = {49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43}
		$1 = {55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF}
	condition:
		$0 at entrypoint or $1
}
rule _Vx_GRUNT1Family_
{
	meta:
		description = "Vx: GRUNT.1.Family"
	strings:
		$0 = {01 B9 ?? 00 31 17}
	condition:
		$0 at entrypoint
}
rule _modified_HACKSTOP_v111f_
{
	meta:
		description = "modified HACKSTOP v1.11f"
	strings:
		$0 = {52 B4 30 CD 21 52 FA ?? FB 3D ?? ?? EB ?? CD 20 0E 1F B4 09 E8}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_60_SFX_Custom_
{
	meta:
		description = "Microsoft Visual C++ 6.0 SFX Custom"
	strings:
		$0 = {E8 21 48 00 00 E9 16 FE FF FF 51 C7 01 08 B4 00 30 E8 A4 48 00 00 59 C3 56 8B F1 E8 EA FF FF FF F6 ?? ?? ?? ?? 74 07 56 E8 F6 04 00 00 59 8B C6 5E C2 04 00 8B 44 24 04 83 C1 09 51 83 C0 09 50}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v3xx_
{
	meta:
		description = "Armadillo v3.xx"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58}
		$1 = {60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _EXEStealth_275__WebtoolMaster_
{
	meta:
		description = "EXEStealth 2.75 -> WebtoolMaster"
	strings:
		$0 = {90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00}
	condition:
		$0 at entrypoint
}
rule _CipherWall_SelfExtratorDecryptor_Console_v15_
{
	meta:
		description = "CipherWall Self-Extrator/Decryptor (Console) v1.5"
	strings:
		$0 = {90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4}
		$1 = {90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _dUP2__diablo2oo2_
{
	meta:
		description = "dUP2 -> diablo2oo2"
	strings:
		$0 = {E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 3C 01 75 19 BE ?? ?? ?? ?? 68 00 02 00 00 56 68}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v12_
{
	meta:
		description = "ASProtect v1.2"
	strings:
		$0 = {68 01 ?? ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _PE_Diminisher_V01__Teraphy_
{
	meta:
		description = "PE Diminisher V0.1 -> Teraphy"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _FSG_v120_Eng__dulekxt__Microsoft_Visual_Cpp_60_
{
	meta:
		description = "FSG v1.20 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0)"
	strings:
		$0 = {C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3}
		$1 = {C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FreeBasic_014_
{
	meta:
		description = "FreeBasic 0.14"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D}
	condition:
		$0 at entrypoint
}
rule _Themida_18xx__Oreans_Technologies_
{
	meta:
		description = "Themida 1.8.x.x -> Oreans Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_VOB_ProtectCD_5__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [VOB ProtectCD 5] --> Anorganix"
	strings:
		$0 = {36 3E 26 8A C0 60 E8 00 00 00 00 E9}
		$1 = {36 3E 26 8A C0 60 E8 00 00 00 00 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASPack_v10802_
{
	meta:
		description = "ASPack v1.08.02"
	strings:
		$0 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72}
		$1 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72}
		$2 = {90 90 75 01 90 E9}
		$3 = {90 75 01 90 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _COMPACK_v45_2_
{
	meta:
		description = "COMPACK v4.5 (2)"
	strings:
		$0 = {BE ?? ?? E8 ?? ?? 5D 83 ?? ?? 55 50 53 51 52 0E 07 0E 1F 8B CE}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v177_
{
	meta:
		description = "Armadillo v1.77"
	strings:
		$0 = {55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _CrypKey_V61X_DLL__CrypKey_Canada_Inc_
{
	meta:
		description = "CrypKey V6.1X DLL -> CrypKey (Canada) Inc."
	strings:
		$0 = {83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8}
	condition:
		$0 at entrypoint
}
rule _PECompact_v140b5__v140b6_
{
	meta:
		description = "PECompact v1.40b5 - v1.40b6"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11}
	condition:
		$0 at entrypoint
}
rule _AHpack_01__FEUERRADER_h_
{
	meta:
		description = "AHpack 0.1 -> FEUERRADER (h)"
	strings:
		$0 = {60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41}
		$1 = {60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v090_
{
	meta:
		description = "PECompact v0.90"
	strings:
		$0 = {EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_PENightMare_2_Beta__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PENightMare 2 Beta] --> Anorganix"
	strings:
		$0 = {60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9}
		$1 = {60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Safeguard_10__Simonzh_
{
	meta:
		description = "Safeguard 1.0 -> Simonzh"
	strings:
		$0 = {E8 00 00 00 00 EB 29}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_CodeSafe_20__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [CodeSafe 2.0] --> Anorganix"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _WWPACK_v300_v301_Relocations_pack_
{
	meta:
		description = "WWPACK v3.00, v3.01 (Relocations pack)"
	strings:
		$0 = {BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC}
	condition:
		$0 at entrypoint
}
rule _MicroJoiner_17__coban2k_
{
	meta:
		description = "MicroJoiner 1.7 -> coban2k"
	strings:
		$0 = {BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00}
	condition:
		$0 at entrypoint
}
rule _UPX_072_
{
	meta:
		description = "UPX 0.72"
	strings:
		$0 = {60 E8 00 00 00 00 83 CD FF 31 DB 5E}
	condition:
		$0 at entrypoint
}
rule _y0das_Crypter_v1x__Modified_
{
	meta:
		description = "y0da's Crypter v1.x / Modified"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_Install_System_v20b4_
{
	meta:
		description = "Nullsoft Install System v2.0b4"
	strings:
		$0 = {83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71}
		$1 = {83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00}
	condition:
		$0 or $1
}
rule _ExeBundle_v30_standard_loader_
{
	meta:
		description = "ExeBundle v3.0 (standard loader)"
	strings:
		$0 = {00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB}
		$1 = {00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FucknJoy_v10c__UsAr_
{
	meta:
		description = "Fuck'n'Joy v1.0c -> UsAr"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00}
		$1 = {60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PowerBASICWin_800_
{
	meta:
		description = "PowerBASIC/Win 8.00"
	strings:
		$0 = {55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 14 04 00 00 E9 19 02}
	condition:
		$0 at entrypoint
}
rule _UPXHiT_001__sibaway7yahoocom_
{
	meta:
		description = "UPX$HiT 0.0.1 -> sibaway7@yahoo.com"
	strings:
		$0 = {E2 FA 94 FF E0 61 00 00 00 00 00 00 00}
	condition:
		$0
}
rule _PseudoSigner_02_BJFNT_12__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [.BJFNT 1.2] --> Anorganix"
	strings:
		$0 = {EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00}
		$1 = {EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MEW_10_by_Northfox_
{
	meta:
		description = "MEW 10 by Northfox"
	strings:
		$0 = {33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40}
	condition:
		$0
}
rule _UPX_v051_
{
	meta:
		description = "UPX v0.51"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 D8 01 ?? ?? 83 CD FF 31 DB ?? ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90}
	condition:
		$0 at entrypoint
}
rule _PEBundle_v244_
{
	meta:
		description = "PEBundle v2.44"
	strings:
		$0 = {9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD}
	condition:
		$0 at entrypoint
}
rule _EXEPACK_v531009_LINK_v369_
{
	meta:
		description = "EXEPACK v5.31.009 (LINK v3.69)"
	strings:
		$0 = {8B E8 8C C0}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_Borland_Cpp_1999__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Borland C++ 1999] --> Anorganix"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3}
		$1 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v133_
{
	meta:
		description = "FSG v1.33"
	strings:
		$0 = {BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73}
	condition:
		$0 at entrypoint
}
rule _EXELOCK_666_15_
{
	meta:
		description = "EXELOCK 666 1.5"
	strings:
		$0 = {BA ?? ?? BF ?? ?? EB ?? EA ?? ?? ?? ?? 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9}
	condition:
		$0 at entrypoint
}
rule _PECompact_v126b1__v126b2_
{
	meta:
		description = "PECompact v1.26b1 - v1.26b2"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? 05 0E}
	condition:
		$0 at entrypoint
}
rule _NeoLite_v200_
{
	meta:
		description = "NeoLite v2.00"
	strings:
		$0 = {8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b1_
{
	meta:
		description = "PECompact v1.10b1"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v285_
{
	meta:
		description = "Armadillo v2.85"
	strings:
		$0 = {55 8B EC 6A FF 68 68 ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24}
	condition:
		$0 at entrypoint
}
rule _RLPack_V111__ap0x_
{
	meta:
		description = "RLPack V1.11 -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB}
	condition:
		$0 at entrypoint
}
rule _EZIP_v10_
{
	meta:
		description = "EZIP v1.0"
	strings:
		$0 = {E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C}
		$1 = {E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_Armadillo_300__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Armadillo 3.00] --> Anorganix"
	strings:
		$0 = {60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 E9}
		$1 = {60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _DBPE_v210_
{
	meta:
		description = "DBPE v2.10"
	strings:
		$0 = {9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE}
		$1 = {9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE}
		$2 = {EB 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Armadillo_v275a_
{
	meta:
		description = "Armadillo v2.75a"
	strings:
		$0 = {55 8B EC 6A FF 68 68 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v252_
{
	meta:
		description = "Armadillo v2.52"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? E0 ?? ?? ?? ?? 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 38}
		$1 = {55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Predator2448_
{
	meta:
		description = "Vx: Predator.2448"
	strings:
		$0 = {0E 1F BF ?? ?? B8 ?? ?? B9 ?? ?? 49 ?? ?? ?? ?? 2A C1 4F 4F ?? ?? F9 CC}
	condition:
		$0 at entrypoint
}
rule _CrypKey_V56X_DLL__Kenonic_Controls_Ltd_
{
	meta:
		description = "CrypKey V5.6.X DLL -> Kenonic Controls Ltd."
	strings:
		$0 = {8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8}
	condition:
		$0 at entrypoint
}
rule _Private_EXE_Protector_18_
{
	meta:
		description = "Private EXE Protector 1.8"
	strings:
		$0 = {BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0}
	condition:
		$0 at entrypoint
}
rule _PEtite_v14_
{
	meta:
		description = "PEtite v1.4"
	strings:
		$0 = {66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC}
		$1 = {66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ExeBundle_v30_small_loader_
{
	meta:
		description = "ExeBundle v3.0 (small loader)"
	strings:
		$0 = {00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11}
		$1 = {00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Setup2Go_Installer_Stub_
{
	meta:
		description = "Setup2Go Installer Stub"
	strings:
		$0 = {5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72}
	condition:
		$0
}
rule _Armadillo_v200b2200b3_
{
	meta:
		description = "Armadillo v2.00b2-2.00b3"
	strings:
		$0 = {55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Obsidium_v10061_
{
	meta:
		description = "Obsidium v1.0.0.61"
	strings:
		$0 = {E8 AF 1C 00 00}
	condition:
		$0 at entrypoint
}
rule _UpxLock_10__12__CyberDoom__TeamX__BoB__BobSoft_
{
	meta:
		description = "Upx-Lock 1.0 - 1.2 --> CyberDoom / Team-X & BoB / BobSoft"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61}
	condition:
		$0 at entrypoint
}
rule _ASPack_v108x_
{
	meta:
		description = "ASPack v1.08.x"
	strings:
		$0 = {60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A}
	condition:
		$0 at entrypoint
}
rule _PKLITE_v114_v115_v120_3_
{
	meta:
		description = "PKLITE v1.14, v1.15, v1.20 (3)"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 05 ?? ?? 3B ?? ?? ?? 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_Microsoft_Visual_Cpp_70_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Microsoft Visual C++ 7.0 DLL] --> Anorganix"
	strings:
		$0 = {55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84}
		$1 = {55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PEArmor_046__Hying_
{
	meta:
		description = "PE-Armor 0.46 -> Hying"
	strings:
		$0 = {E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D}
	condition:
		$0 at entrypoint
}
rule _PESpin_V071__cyberbob_
{
	meta:
		description = "PESpin V0.71 -> cyberbob"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E}
	condition:
		$0 at entrypoint
}
rule _Vx_Backfont900_
{
	meta:
		description = "Vx: Backfont.900"
	strings:
		$0 = {E8 ?? ?? B4 30 CD 21 3C 03 ?? ?? B8 ?? ?? BA ?? ?? CD 21 81 FA ?? ?? ?? ?? BA ?? ?? 8C C0 48 8E C0 8E D8 80 ?? ?? ?? 5A ?? ?? 03 ?? ?? ?? 40 8E D8 80 ?? ?? ?? 5A ?? ?? 83}
	condition:
		$0 at entrypoint
}
rule _Metrowerks_CodeWarrior_v20_GUI_
{
	meta:
		description = "Metrowerks CodeWarrior v2.0 (GUI)"
	strings:
		$0 = {55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 ?? ?? 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8}
	condition:
		$0
}
rule _EP_ExE_Pack_V10__Elite_Coding_Group_
{
	meta:
		description = "!EP (ExE Pack) V1.0 -> Elite Coding Group"
	strings:
		$0 = {60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10}
	condition:
		$0 at entrypoint
}
rule _PENightMare_2_Beta_
{
	meta:
		description = "PENightMare 2 Beta"
	strings:
		$0 = {60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A}
	condition:
		$0 at entrypoint
}
rule _MASM__TASM_
{
	meta:
		description = "MASM / TASM"
	strings:
		$0 = {6A 00 E8 ?? ?? 00 00 A3 ?? 32 40 00 E8 ?? ?? 00 00}
	condition:
		$0 at entrypoint
}
rule _Cracked_by_AutoHack_1_
{
	meta:
		description = "Cracked by AutoHack (1)"
	strings:
		$0 = {FA 50 51 57 56 1E 06 2E 80 3E ?? ?? ?? 74 ?? 8E 06 ?? ?? 2B FF FC}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_XCR_011__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [XCR 0.11] --> Anorganix"
	strings:
		$0 = {60 8B F0 33 DB 83 C3 01 83 C0 01}
		$1 = {60 8B F0 33 DB 83 C3 01 83 C0 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PC_Shrinker_v029_
{
	meta:
		description = "PC Shrinker v0.29"
	strings:
		$0 = {BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40}
	condition:
		$0 at entrypoint
}
rule _PIRIT_v15_
{
	meta:
		description = "PIRIT v1.5"
	strings:
		$0 = {B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21}
	condition:
		$0 at entrypoint
}
rule _PEEncrypt_v40b_JunkCode_
{
	meta:
		description = "PEEncrypt v4.0b (JunkCode)"
	strings:
		$0 = {66 ?? ?? 00 66 83 ?? 00}
	condition:
		$0 at entrypoint
}
rule _UPX_v071__v072_
{
	meta:
		description = "UPX v0.71 - v0.72"
	strings:
		$0 = {60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07}
	condition:
		$0 at entrypoint
}
rule _PECompact_v25_Retail__Bitsum_Technologies_
{
	meta:
		description = "PECompact v2.5 Retail -> Bitsum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00}
	condition:
		$0 at entrypoint
}
rule _CrypKey_V56X__Kenonic_Controls_Ltd_
{
	meta:
		description = "CrypKey V5.6.X -> Kenonic Controls Ltd."
	strings:
		$0 = {E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8}
	condition:
		$0 at entrypoint
}
rule _Vx_Trivial46_
{
	meta:
		description = "Vx: Trivial.46"
	strings:
		$0 = {B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_LCC_Win32_1x__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [LCC Win32 1.x] --> Anorganix"
	strings:
		$0 = {64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9}
		$1 = {64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _HACKSTOP_v113_
{
	meta:
		description = "HACKSTOP v1.13"
	strings:
		$0 = {52 B8 ?? ?? 1E CD 21 86 E0 3D ?? ?? 73 ?? CD 20 0E 1F B4 09 E8 ?? ?? 24 ?? EA}
	condition:
		$0 at entrypoint
}
rule _ExeShield_Protector_V36__wwwexeshieldcom_
{
	meta:
		description = "ExeShield Protector V3.6 -> www.exeshield.com"
	strings:
		$0 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC}
		$1 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v260c_
{
	meta:
		description = "Armadillo v2.60c"
	strings:
		$0 = {55 8B EC 6A FF 68 40 ?? ?? ?? 68 F4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 F4}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_VBOX_43_MTE__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [VBOX 4.3 MTE] --> Anorganix"
	strings:
		$0 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0}
		$1 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_v70_
{
	meta:
		description = "Microsoft Visual C++ v7.0"
	strings:
		$0 = {6A 0C 68 88 BF 01 10 E8 B8 1C 00 00 33 C0 40 89 45 E4 8B 75 0C 33 FF 3B F7 75 0C 39 3D 6C 1E 12 10 0F 84 B3 00 00 00 89 7D FC 3B F0 74 05 83 FE 02 75 31 A1 98 36 12 10 3B C7 74 0C FF 75 10 56}
		$1 = {6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? ?? 8B 46 ?? A3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _EXE__yy66_
{
	meta:
		description = "心奇EXE合并器 -> yy66"
	strings:
		$0 = {68 78 18 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30}
	condition:
		$0 at entrypoint
}
rule _DzA_Patcher_v13_Loader_
{
	meta:
		description = "DzA Patcher v1.3 Loader"
	strings:
		$0 = {BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35}
		$1 = {BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35}
	condition:
		$0 or $1
}
rule _Vx_Eddie2000_
{
	meta:
		description = "Vx: Eddie.2000"
	strings:
		$0 = {E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C5 ?? ?? ?? B4 30 CD 21}
	condition:
		$0 at entrypoint
}
rule _ASPack_v102b_
{
	meta:
		description = "ASPack v1.02b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43}
		$2 = {60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _ExeTools_v21_Encruptor_by_DISMEMBER_
{
	meta:
		description = "ExeTools v2.1 Encruptor by DISMEMBER"
	strings:
		$0 = {E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74}
	condition:
		$0 at entrypoint
}
rule _HideProtect_V10X_SoftWar_Company_
{
	meta:
		description = "Hide&Protect V1.0X-> SoftWar Company"
	strings:
		$0 = {90 90 90 E9 D8}
	condition:
		$0 at entrypoint
}
rule _Frusion__biff_
{
	meta:
		description = "Frusion -> biff"
	strings:
		$0 = {83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Microsoft_Visual_Basic_50__60__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual Basic 5.0 - 6.0] --> Anorganix"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9}
		$1 = {68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _CA_Visual_Objects_20__25_
{
	meta:
		description = "CA Visual Objects 2.0 - 2.5"
	strings:
		$0 = {89 25 ?? ?? ?? ?? 33 ED 55 8B EC E8 ?? ?? ?? ?? 8B D0 81 E2 FF 00 00 00 89 15 ?? ?? ?? ?? 8B D0 C1 EA 08 81 E2 FF 00 00 00 A3 ?? ?? ?? ?? D1 E0 0F 93 C3 33 C0 8A C3 A3 ?? ?? ?? ?? 68 FF 00 00 00 E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? BB}
	condition:
		$0 at entrypoint
}
rule _DIET_v100_v100d_
{
	meta:
		description = "DIET v1.00, v1.00d"
	strings:
		$0 = {BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v305c4_Extractable_
{
	meta:
		description = "WWPACK v3.05c4 (Extractable)"
	strings:
		$0 = {03 05 00 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _SecuPack_v15_
{
	meta:
		description = "SecuPack v1.5"
	strings:
		$0 = {55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 ?? ?? ?? 6A 03 6A ?? 6A 01 ?? ?? ?? 80}
	condition:
		$0 at entrypoint
}
rule _Vx_November_17768_
{
	meta:
		description = "Vx: November 17.768"
	strings:
		$0 = {E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC}
	condition:
		$0 at entrypoint
}
rule _NeoLite_v20_
{
	meta:
		description = "NeoLite v2.0"
	strings:
		$0 = {E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4E 65 6F 4C 69 74 65}
	condition:
		$0 at entrypoint
}
rule _Upack_v0399__Dwing_
{
	meta:
		description = "Upack v0.399 -> Dwing"
	strings:
		$0 = {0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? 00 14 00 00 00 00 ?? ?? 00 ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? 00 ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5}
		$1 = {BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PeCompact_2xx_Slim_Loader__BitSum_Technologies_
{
	meta:
		description = "PeCompact 2.xx (Slim Loader) --> BitSum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00}
	condition:
		$0 at entrypoint
}
rule _PEArmor_046__China_Cracking_Group_
{
	meta:
		description = "PE-Armor 0.46 -> China Cracking Group"
	strings:
		$0 = {E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41}
	condition:
		$0 at entrypoint
}
rule _FreePascal_104_Win32__Berczi_Gabor_Pierre_Muller__Peter_Vreman_
{
	meta:
		description = "FreePascal 1.0.4 Win32 -> (Berczi Gabor, Pierre Muller & Peter Vreman)"
	strings:
		$0 = {55 89 E5 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 55 31 ED 89 E0 A3 ?? ?? ?? ?? 66 8C D5 89 2D ?? ?? ?? ?? DB E3 D9 2D ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? 5D E8 ?? ?? ?? ?? C9 C3}
	condition:
		$0
}
rule _RECSmall_v102_
{
	meta:
		description = "REC.Small v1.02"
	strings:
		$0 = {8C D8 1E E8 ?? ?? 83 ?? ?? 5D B9 ?? ?? 81 ?? ?? ?? 40 8E D8 2B DB B2 ?? ?? ?? FE C2 43 83}
	condition:
		$0 at entrypoint
}
rule _ENIGMA_Protector_V11_Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector V1.1-> Sukhov Vladimir"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ?? ?? 81}
	condition:
		$0 at entrypoint
}
rule _tElock_v04x__v05x_
{
	meta:
		description = "tElock v0.4x - v0.5x"
	strings:
		$0 = {C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01}
	condition:
		$0 at entrypoint
}
rule _Vx_Hafen809_
{
	meta:
		description = "Vx: Hafen.809"
	strings:
		$0 = {E8 ?? ?? 1C ?? 81 EE ?? ?? 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 ?? ?? ?? 07 3D}
	condition:
		$0 at entrypoint
}
rule _tElock_v07x__v084_
{
	meta:
		description = "tElock v0.7x - v0.84"
	strings:
		$0 = {60 E8 00 00 C3 83}
	condition:
		$0 at entrypoint
}
rule _EXE2COM_Packed_
{
	meta:
		description = "EXE2COM (Packed)"
	strings:
		$0 = {BD ?? ?? 89 ?? ?? ?? 81 ?? ?? ?? ?? ?? 8C ?? ?? ?? 8C C8 05 ?? ?? 8E C0 BE ?? ?? 8B FE 0E 57 54 59 F3 A4 06 68 ?? ?? CB}
	condition:
		$0 at entrypoint
}
rule _Macromedia_Windows_Flash_ProjectorPlayer_v30_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v3.0"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_PENightMare_2_Beta__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PENightMare 2 Beta] --> Anorganix"
	strings:
		$0 = {60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A}
		$1 = {60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_v062_DLL_
{
	meta:
		description = "UPX v0.62 [DLL]"
	strings:
		$0 = {80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 58}
	condition:
		$0 at entrypoint
}
rule _Pe123__v2006412_
{
	meta:
		description = "Pe123  v2006.4.12"
	strings:
		$0 = {8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B}
	condition:
		$0 at entrypoint
}
rule _EXEPACK_v405_v406_
{
	meta:
		description = "EXEPACK v4.05, v4.06"
	strings:
		$0 = {8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 06 ?? ?? 8E C0 8B 0E ?? ?? 8B F9 4F 8B F7 FD F3 A4}
	condition:
		$0 at entrypoint
}
rule _WinZip_32bit_SFX_v8x_module_
{
	meta:
		description = "WinZip 32-bit SFX v8.x module"
	strings:
		$0 = {53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 ?? ?? ?? ?? FF 15}
	condition:
		$0 at entrypoint
}
rule _Unknown_packer_02_
{
	meta:
		description = "Unknown packer (02)"
	strings:
		$0 = {FA 8C DE 8C CF 8E DF 8E C7 83 C7 ?? BB}
	condition:
		$0 at entrypoint
}
rule _Packman_0001__Bubbasoft_h_
{
	meta:
		description = "Packman 0.0.0.1 -> Bubbasoft (h)"
	strings:
		$0 = {0F 85 ?? FF FF FF 8D B3 ?? ?? ?? ?? EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00}
	condition:
		$0
}
rule _EXE2COM_With_CRC_check_
{
	meta:
		description = "EXE2COM (With CRC check)"
	strings:
		$0 = {B3 ?? B9 ?? ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 43 49 32 E4 03 D0 E3}
	condition:
		$0 at entrypoint
}
rule _VMProtect_07x__08__PolyTech_
{
	meta:
		description = "VMProtect 0.7x - 0.8 -> PolyTech"
	strings:
		$0 = {5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D}
	condition:
		$0
}
rule _CICompress_v10_
{
	meta:
		description = "CICompress v1.0"
	strings:
		$0 = {6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35}
		$1 = {6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ExeShield_36__wwwexeshieldcom_
{
	meta:
		description = "ExeShield 3.6 -> www.exeshield.com"
	strings:
		$0 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F}
	condition:
		$0 at entrypoint
}
rule _PE_Spin_v04x_
{
	meta:
		description = "PE Spin v0.4x"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B}
	condition:
		$0
}
rule _Thinstall_v2460__Jitit_
{
	meta:
		description = "Thinstall v2.460 -> Jitit"
	strings:
		$0 = {55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 F4 18 40 00 50 E8 87 FC FF FF 59 59 A1 94 1A 40 00 8B 40 10 03 05 90 1A 40 00 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 76 0C 00 00 D4 0C 00 00 1E}
	condition:
		$0 at entrypoint
}
rule _Vx_TravJack883_
{
	meta:
		description = "Vx: TravJack.883"
	strings:
		$0 = {EB ?? 9C 9E 26 ?? ?? 51 04 ?? 7D ?? 00 ?? 2E ?? ?? ?? ?? 8C C8 8E C0 8E D8 80 ?? ?? ?? ?? 74 ?? 8A ?? ?? ?? BB ?? ?? 8A ?? 32 C2 88 ?? FE C2 43 81}
	condition:
		$0 at entrypoint
}
rule _FSG_v20_
{
	meta:
		description = "FSG v2.0"
	strings:
		$0 = {87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75}
	condition:
		$0
}
rule _Vx_Gotcha879_
{
	meta:
		description = "Vx: Gotcha.879"
	strings:
		$0 = {E8 ?? ?? 5B 81 EB ?? ?? 9C FC 2E ?? ?? ?? ?? ?? ?? ?? 8C D8 05 ?? ?? 2E ?? ?? ?? ?? 50 2E ?? ?? ?? ?? ?? ?? 8B C3 05 ?? ?? 8B F0 BF 00 01 B9 20 00 F3 A4 0E B8 00 01 50 B8 DA DA CD 21}
	condition:
		$0 at entrypoint
}
rule _Exe_Shield_v29_
{
	meta:
		description = "Exe Shield v2.9"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8}
		$1 = {60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _LSI_C86_RunTime_Libray_
{
	meta:
		description = "LSI C-86 Run-Time Libray"
	strings:
		$0 = {B8 ?? ?? 8E C0 06 17 BC ?? ?? 26 8C ?? ?? ?? B4 30 CD 21 26 A3 ?? ?? FC}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_Dll_main_
{
	meta:
		description = "MinGW v3.2.x (Dll_main)"
	strings:
		$0 = {55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00}
	condition:
		$0 at entrypoint
}
rule _Vx_FaxFreeTopo_
{
	meta:
		description = "Vx: FaxFree.Topo"
	strings:
		$0 = {FA 06 33 C0 8E C0 B8 ?? ?? 26 ?? ?? ?? ?? 50 8C C8 26 ?? ?? ?? ?? 50 CC 58 9D 58 26 ?? ?? ?? ?? 58 26 ?? ?? ?? ?? 07 FB}
	condition:
		$0 at entrypoint
}
rule _from_NORMAN_AntiVirus_Utilites_
{
	meta:
		description = "from NORMAN Anti-Virus Utilites"
	strings:
		$0 = {E8 ?? ?? 5B 52 45 2F 4E 44 44 53 5D 0D 0A}
	condition:
		$0 at entrypoint
}
rule _DSHIELD_
{
	meta:
		description = "DSHIELD"
	strings:
		$0 = {06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E}
	condition:
		$0 at entrypoint
}
rule _Upack_v036_alpha__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.36 alpha -> Sign by hot_UNP"
	strings:
		$0 = {AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0}
	condition:
		$0
}
rule _Trivial173_by_SMTSMF_
{
	meta:
		description = "Trivial173 by SMT/SMF"
	strings:
		$0 = {EB ?? ?? 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29}
	condition:
		$0 at entrypoint
}
rule _Lockless_Intro_Pack_
{
	meta:
		description = "Lockless Intro Pack"
	strings:
		$0 = {2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85}
	condition:
		$0 at entrypoint
}
rule _ASPack_v10803_
{
	meta:
		description = "ASPack v1.08.03"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E}
		$1 = {60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E}
		$2 = {60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E}
		$3 = {60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD}
		$4 = {60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint
}
rule _SLVc0deProtector_11x__SLV__ICU_
{
	meta:
		description = "SLVc0deProtector 1.1x -> SLV / ICU"
	strings:
		$0 = {E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_Microsoft_Visual_Basic_50__60__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Microsoft Visual Basic 5.0 - 6.0] --> Anorganix"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00}
		$1 = {68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _NoodleCrypt_v20_
{
	meta:
		description = "NoodleCrypt v2.0"
	strings:
		$0 = {EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01}
		$1 = {EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01}
	condition:
		$0 at entrypoint or $1
}
rule _Armadillo_v250b3_
{
	meta:
		description = "Armadillo v2.50b3"
	strings:
		$0 = {55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt_v102_
{
	meta:
		description = "PE Crypt v1.02"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44}
	condition:
		$0 at entrypoint
}
rule _Gleam_100_
{
	meta:
		description = "Gleam 1.00"
	strings:
		$0 = {83 EC 0C 53 56 57 E8 24 02 00}
	condition:
		$0
}
rule _PEPROTECT_09_
{
	meta:
		description = "PE-PROTECT 0.9"
	strings:
		$0 = {E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_ASProtect__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [ASProtect] --> Anorganix"
	strings:
		$0 = {60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD}
		$1 = {60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PowerBASICWin_70x_
{
	meta:
		description = "PowerBASIC/Win 7.0x"
	strings:
		$0 = {55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 0F 85 DB 00 00 00}
	condition:
		$0 at entrypoint
}
rule _FreePascal_104_Win32_DLL__Berczi_Gabor_Pierre_Muller__Peter_Vreman_
{
	meta:
		description = "FreePascal 1.0.4 Win32 DLL -> (Berczi Gabor, Pierre Muller & Peter Vreman)"
	strings:
		$0 = {C6 05 ?? ?? ?? ?? 00 55 89 E5 53 56 57 8B 7D 08 89 3D ?? ?? ?? ?? 8B 7D 0C 89 3D ?? ?? ?? ?? 8B 7D 10 89 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5B 5D C2 0C 00}
	condition:
		$0
}
rule _FASM_v13x_
{
	meta:
		description = "FASM v1.3x"
	strings:
		$0 = {6A ?? FF 15 ?? ?? ?? ?? A3}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v220_
{
	meta:
		description = "Armadillo v2.20"
	strings:
		$0 = {55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Upack_012_betaDwing_
{
	meta:
		description = "Upack 0.12 beta-->Dwing"
	strings:
		$0 = {BE 48 01 40 00 AD ?? ?? ?? A5 ?? C0 33 C9 ?? ?? ?? ?? ?? ?? ?? F3 AB ?? ?? 0A ?? ?? ?? ?? AD 50 97 51 ?? 87 F5 58 8D 54 86 5C ?? D5 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B6 5F FF C1}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v70_64_Bit_
{
	meta:
		description = "Microsoft Visual C++ v7.0 (64 Bit)"
	strings:
		$0 = {41 00 00 00 00 00 00 00 63 00 00 00 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 20 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0
}
rule _IMPPacker_10__Mahdi_Hezavehi_IMPOSTER_h_
{
	meta:
		description = "IMP-Packer 1.0 -> Mahdi Hezavehi [IMPOSTER] (h)"
	strings:
		$0 = {28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63}
	condition:
		$0
}
rule _ASPack_v21_
{
	meta:
		description = "ASPack v2.1"
	strings:
		$0 = {60 E8 72 05 00 00 EB 33 87 DB 90 00}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_vxx_
{
	meta:
		description = "Microsoft Visual C++ vx.x"
	strings:
		$0 = {55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04}
		$1 = {55 8B EC 56 57 BF ?? ?? ?? ?? 8B ?? ?? 3B F7 0F}
		$2 = {53 55 56 8B ?? ?? ?? 85 F6 57 B8 ?? ?? ?? ?? 75 ?? 8B ?? ?? ?? ?? ?? 85 C9 75 ?? 33 C0 5F 5E 5D 5B C2}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_Debug_Version_
{
	meta:
		description = "Microsoft Visual C++ v6.0 (Debug Version)"
	strings:
		$0 = {55 8B EC 51 ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _RLPack_Full_Edition_117_DLL__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 DLL -> Ap0x"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8}
	condition:
		$0 at entrypoint
}
rule _LameCrypt_v10_
{
	meta:
		description = "LameCrypt v1.0"
	strings:
		$0 = {60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61}
	condition:
		$0 at entrypoint
}
rule _iPBProtect_v013_
{
	meta:
		description = "iPBProtect v0.1.3"
	strings:
		$0 = {55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78}
	condition:
		$0
}
rule _PKLITE_v114_v120_
{
	meta:
		description = "PKLITE v1.14, v1.20"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 20}
	condition:
		$0 at entrypoint
}
rule _DAEMON_Protect_v067_
{
	meta:
		description = "DAEMON Protect v0.6.7"
	strings:
		$0 = {60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_main_
{
	meta:
		description = "MinGW v3.2.x (main)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D}
	condition:
		$0 at entrypoint
}
rule _EmbedPE_V1X__cyclotron_
{
	meta:
		description = "EmbedPE V1.X -> cyclotron"
	strings:
		$0 = {83 EC 50 60 68 ?? ?? ?? ?? E8 ?? ?? 00 00}
	condition:
		$0 at entrypoint
}
rule _EXE_Stealth_v27_
{
	meta:
		description = "EXE Stealth v2.7"
	strings:
		$0 = {EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40}
	condition:
		$0 at entrypoint
}
rule _HPA_
{
	meta:
		description = "HPA"
	strings:
		$0 = {E8 ?? ?? 5E 8B D6 83 ?? ?? 83 ?? ?? 06 0E 1E 0E 1F 33 FF 8C D3}
	condition:
		$0 at entrypoint
}
rule _UPX_v103__v104_Modified_
{
	meta:
		description = "UPX v1.03 - v1.04 Modified"
	strings:
		$0 = {01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v300_
{
	meta:
		description = "Armadillo v3.00"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9}
		$1 = {60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPXFreak_V01__HMX0101_
{
	meta:
		description = "UPXFreak V0.1 -> HMX0101"
	strings:
		$0 = {BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_Install_System_v20b2_v20b3_
{
	meta:
		description = "Nullsoft Install System v2.0b2, v2.0b3"
	strings:
		$0 = {83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v253_
{
	meta:
		description = "Armadillo v2.53"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89}
		$1 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89}
		$2 = {55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _FSG_v110_Eng__dulekxt_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt"
	strings:
		$0 = {EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00}
		$1 = {EB 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? F6}
		$2 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE}
		$3 = {E8 01 00 00 00 ?? ?? E8 ?? 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _PseudoSigner_01_WATCOM_CCpp_EXE__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [WATCOM C/C++ EXE] --> Anorganix"
	strings:
		$0 = {E9 00 00 00 00 90 90 90 90 57 41 E9}
		$1 = {E9 00 00 00 00 90 90 90 90 57 41 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MicroJoiner_11__coban2k_
{
	meta:
		description = "MicroJoiner 1.1 -> coban2k"
	strings:
		$0 = {BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11}
	condition:
		$0 at entrypoint
}
rule _UPX_V194__Markus_Oberhumer__Laszlo_Molnar__John_Reiser_
{
	meta:
		description = "UPX V1.94 -> Markus Oberhumer & Laszlo Molnar & John Reiser"
	strings:
		$0 = {FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9}
	condition:
		$0
}
rule _PseudoSigner_01_32Lite_003__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [32Lite 0.03] --> Anorganix"
	strings:
		$0 = {60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 ?? ?? ?? ?? E9}
		$1 = {60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 ?? ?? ?? ?? E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Sonik_Youth_
{
	meta:
		description = "Vx: Sonik Youth"
	strings:
		$0 = {8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB}
	condition:
		$0 at entrypoint
}
rule _Lattice_C_v30_
{
	meta:
		description = "Lattice C v3.0"
	strings:
		$0 = {FA B8 ?? ?? 8E D8 B8 ?? ?? 8E}
	condition:
		$0 at entrypoint
}
rule _Upack_v038_beta__Dwing_
{
	meta:
		description = "Upack v0.38 beta -> Dwing"
	strings:
		$0 = {BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _CRYPT_Version_17_c_Dismember_
{
	meta:
		description = "CRYPT Version 1.7 (c) Dismember"
	strings:
		$0 = {0E 17 9C 58 F6 ?? ?? 74 ?? E9}
	condition:
		$0 at entrypoint
}
rule _TPACK_v05c_m1_
{
	meta:
		description = "T-PACK v0.5c -m1"
	strings:
		$0 = {68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 8E FE}
	condition:
		$0 at entrypoint
}
rule _PEtite_vxx_
{
	meta:
		description = "PEtite vx.x"
	strings:
		$0 = {B8 ?? ?? ?? ?? 66 9C 60 50}
	condition:
		$0 at entrypoint
}
rule _Ding_Boys_PElock_Phantasm_v15b3_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v1.5b3"
	strings:
		$0 = {9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0}
	condition:
		$0 at entrypoint
}
rule _Vx_ARCV4_
{
	meta:
		description = "Vx: ARCV.4"
	strings:
		$0 = {E8 00 00 5D 81 ED 06 01 81 FC 4F 50 74 0B 8D B6 86 01 BF 00 01 57 A4 EB 11 1E 06}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b6_
{
	meta:
		description = "PECompact v1.10b6"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_C_50_
{
	meta:
		description = "Microsoft Visual C 5.0"
	strings:
		$0 = {64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57}
	condition:
		$0
}
rule _Turbo_C_
{
	meta:
		description = "Turbo C"
	strings:
		$0 = {BC ?? ?? E8 ?? ?? 2E 8E ?? ?? ?? E8 ?? ?? 2E 80 ?? ?? ?? ?? 75 ?? E8 ?? ?? 8B C3 2E F7 ?? ?? ?? E8}
	condition:
		$0 at entrypoint
}
rule _PECompact_v1242__v1243_
{
	meta:
		description = "PECompact v1.24.2 - v1.24.3"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09}
	condition:
		$0 at entrypoint
}
rule _WARNING__TROJAN__XiaoHui_
{
	meta:
		description = "WARNING -> TROJAN -> XiaoHui"
	strings:
		$0 = {60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00}
	condition:
		$0 at entrypoint
}
rule _PROTECT_EXECOM_v60_
{
	meta:
		description = "PROTECT! EXE/COM v6.0"
	strings:
		$0 = {1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8}
	condition:
		$0 at entrypoint
}
rule _RLPack_Full_Edition_117__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 -> Ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF}
	condition:
		$0 at entrypoint
}
rule _Vx_Eddie1530_
{
	meta:
		description = "Vx: Eddie.1530"
	strings:
		$0 = {E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? 50 06 56 1E 33 C0 50 1F C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E}
	condition:
		$0 at entrypoint
}
rule _Special_EXE_Pasword_Protector_v101_Eng__Pavol_Cerven_
{
	meta:
		description = "Special EXE Pasword Protector v1.01 (Eng) -> Pavol Cerven"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 00 00 8D 95 C6 77 00 00 8D 8D FF 77 00 00 55 68 00 20 00 00 51 52 6A 00 FF 95 04 7A 00 00 5D 6A 00 FF 95 FC 79 00 00 8D 8D 60 78 00 00 8D 95 85 01 00 00 55 68 00}
		$1 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_XRCV1015_
{
	meta:
		description = "Vx: XRCV.1015"
	strings:
		$0 = {E8 ?? ?? 5E 83 ?? ?? 53 51 1E 06 B4 99 CD 21 80 FC 21 ?? ?? ?? ?? ?? 33 C0 50 8C D8 48 8E C0 1F A1 ?? ?? 8B}
	condition:
		$0 at entrypoint
}
rule _Crinkler_V03V04__Rune_LHStubbe_and_Aske_Simon_Christensen_
{
	meta:
		description = "Crinkler V0.3-V0.4 -> Rune L.H.Stubbe and Aske Simon Christensen"
	strings:
		$0 = {B8 00 00 42 00 31 DB 43 EB 58}
	condition:
		$0 at entrypoint
}
rule _Packman_v0001_
{
	meta:
		description = "Packman v0.0.0.1"
	strings:
		$0 = {60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00}
	condition:
		$0 at entrypoint
}
rule _PE_Intro_v10_
{
	meta:
		description = "PE Intro v1.0"
	strings:
		$0 = {8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48}
	condition:
		$0 at entrypoint
}
rule _MEW_11_SE_v12__NorthfoxHCC_
{
	meta:
		description = "MEW 11 SE v1.2 -> Northfox[HCC]"
	strings:
		$0 = {E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_PIMP_Install_System_v13x_
{
	meta:
		description = "Nullsoft PIMP Install System v1.3x"
	strings:
		$0 = {55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD}
	condition:
		$0 at entrypoint
}
rule _Alex_Protector_v10__Alex_
{
	meta:
		description = "Alex Protector v1.0 -> Alex"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B}
	condition:
		$0 at entrypoint
}
rule _Shrinker_32_
{
	meta:
		description = "Shrinker 3.2"
	strings:
		$0 = {55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04}
	condition:
		$0
}
rule _Microsoft_Visual_Cpp_80_
{
	meta:
		description = "Microsoft Visual C++ 8.0"
	strings:
		$0 = {6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8}
	condition:
		$0 at entrypoint
}
rule _Turbo_Pascal_v30_1985_
{
	meta:
		description = "Turbo Pascal v3.0 1985"
	strings:
		$0 = {90 90 CD AB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 35}
	condition:
		$0 at entrypoint
}
rule _Install_Stub_32bit_
{
	meta:
		description = "Install Stub 32-bit"
	strings:
		$0 = {55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29}
	condition:
		$0 at entrypoint
}
rule _PE_Lock_NT_v204_
{
	meta:
		description = "PE Lock NT v2.04"
	strings:
		$0 = {EB ?? CD ?? ?? ?? ?? ?? CD ?? ?? ?? ?? ?? EB ?? EB ?? EB ?? EB ?? CD ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 50 C3}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v252_beta2_
{
	meta:
		description = "Armadillo v2.52 beta2"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v265b1_
{
	meta:
		description = "Armadillo v2.65b1"
	strings:
		$0 = {55 8B EC 6A FF 68 38 ?? ?? ?? 68 40 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 F4}
	condition:
		$0 at entrypoint
}
rule _MS_RunTime_Library_1992_14_
{
	meta:
		description = "MS Run-Time Library 1992 (14)"
	strings:
		$0 = {1E 06 8C C8 8E D8 8C C0 A3 ?? ?? 83 C0 ?? A3 ?? ?? B4 30}
	condition:
		$0 at entrypoint
}
rule _MEW_11_SE_v11_
{
	meta:
		description = "MEW 11 SE v1.1"
	strings:
		$0 = {E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0
}
rule _Microsoft_Visual_Cpp_v70_DLL_
{
	meta:
		description = "Microsoft Visual C++ v7.0 DLL"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10}
		$1 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 ?? ?? 83}
	condition:
		$0 at entrypoint or $1
}
rule _tElock_v041x_
{
	meta:
		description = "tElock v0.41x"
	strings:
		$0 = {66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08}
	condition:
		$0 at entrypoint
}
rule _EXE_Manager_Version_30_1994_c_Solar_Designer_
{
	meta:
		description = "EXE Manager Version 3.0 1994 (c) Solar Designer"
	strings:
		$0 = {B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2}
	condition:
		$0 at entrypoint
}
rule _ExeJoiner_V10__Yoda_f2f_
{
	meta:
		description = "ExeJoiner V1.0 -> Yoda f2f"
	strings:
		$0 = {68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00}
	condition:
		$0 at entrypoint
}
rule _Vx_Horse1776_
{
	meta:
		description = "Vx: Horse.1776"
	strings:
		$0 = {E8 ?? ?? 5D 83 ?? ?? 06 1E 26 ?? ?? ?? ?? BF ?? ?? 1E 0E 1F 8B F7 01 EE B9 ?? ?? FC F3 A6 1F 1E 07}
	condition:
		$0 at entrypoint
}
rule _RLPack_Full_Edition_117_LZMA__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 [LZMA] -> Ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 73 26 00 00 8D 9D 58 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A}
	condition:
		$0 at entrypoint
}
rule _yodas_Protector_102__103__Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Protector 1.02 - 1.03 -> Ashkbiz Danehkar"
	strings:
		$0 = {E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00}
	condition:
		$0 at entrypoint
}
rule _kryptor_6_
{
	meta:
		description = "kryptor 6"
	strings:
		$0 = {E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02}
	condition:
		$0 at entrypoint
}
rule _ASPack_v10804_
{
	meta:
		description = "ASPack v1.08.04"
	strings:
		$0 = {60 E8 41 06 00 00 EB 41}
		$1 = {60 E8 ?? ?? ?? ?? EB}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Exact_Audio_Copy_
{
	meta:
		description = "Exact Audio Copy"
	strings:
		$0 = {E8 ?? ?? ?? 00 31 ED 55 89 E5 81 EC ?? 00 00 00 8D BD ?? FF FF FF B9 ?? 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PMODEW_v112_116_121_133_DOS_extender_
{
	meta:
		description = "PMODE/W v.1.12, 1.16, 1.21, 1.33 DOS extender"
	strings:
		$0 = {FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_UPX_06__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [UPX 0.6] --> Anorganix"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00}
		$1 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Upack_v032_beta__Dwing_
{
	meta:
		description = "Upack v0.32 beta -> Dwing"
	strings:
		$0 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_BJFNT_11b__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [.BJFNT 1.1b] --> Anorganix"
	strings:
		$0 = {EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90}
		$1 = {EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_430a__Silicon_Realms_Toolworks_h_
{
	meta:
		description = "Armadillo 4.30a -> Silicon Realms Toolworks (h)"
	strings:
		$0 = {44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43}
		$1 = {44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43}
	condition:
		$0 or $1
}
rule _REALbasic_
{
	meta:
		description = "REALbasic"
	strings:
		$0 = {55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _Petite_12_
{
	meta:
		description = "Petite 1.2"
	strings:
		$0 = {66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00}
	condition:
		$0 at entrypoint
}
rule _eXPressor_11__CGSoftLabs_
{
	meta:
		description = "eXPressor 1.1 -> CGSoftLabs"
	strings:
		$0 = {E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00}
	condition:
		$0 at entrypoint
}
rule _Spalsher_v10__v30_
{
	meta:
		description = "Spalsher v1.0 - v3.0"
	strings:
		$0 = {9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84}
	condition:
		$0 at entrypoint
}
rule _WATCOM_CCpp_
{
	meta:
		description = "WATCOM C/C++"
	strings:
		$0 = {E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41}
	condition:
		$0 at entrypoint
}
rule _NeoLite_v10_
{
	meta:
		description = "NeoLite v1.0"
	strings:
		$0 = {8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25}
		$1 = {E9 9B 00 00 00 A0}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v184_
{
	meta:
		description = "Armadillo v1.84"
	strings:
		$0 = {55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_v062_
{
	meta:
		description = "UPX v0.62"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07}
		$1 = {60 E8 ?? ?? ?? ?? 58 83 ?? ?? 50 8D ?? ?? ?? ?? ?? 57 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? 31 DB ?? ?? ?? EB}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Hasp_dongle_Alladin_
{
	meta:
		description = "Hasp dongle (Alladin)"
	strings:
		$0 = {50 53 51 52 57 56 8B 75 1C 8B 3E ?? ?? ?? ?? ?? 8B 5D 08 8A FB ?? ?? 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF 32}
	condition:
		$0 at entrypoint
}
rule _RCryptor_v16d__Vaska_
{
	meta:
		description = "RCryptor v1.6d --> Vaska"
	strings:
		$0 = {60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at entrypoint
}
rule _Unknown_packer_01_
{
	meta:
		description = "Unknown packer (01)"
	strings:
		$0 = {EB ?? ?? BE ?? ?? BF ?? ?? 2E}
	condition:
		$0 at entrypoint
}
rule _ASPack_108_
{
	meta:
		description = "ASPack 1.08"
	strings:
		$0 = {90 90 90 75 01 90 E9}
	condition:
		$0 at entrypoint
}
rule _Stranik_13_ModulaCPascal_
{
	meta:
		description = "Stranik 1.3 Modula/C/Pascal"
	strings:
		$0 = {E8 ?? ?? FF FF E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _ChSfx_small_v11_
{
	meta:
		description = "ChSfx (small) v1.1"
	strings:
		$0 = {BA ?? ?? E8 ?? ?? 8B EC 83 EC ?? 8C C8 BB ?? ?? B1 ?? D3 EB 03 C3 8E D8 05 ?? ?? 89}
	condition:
		$0 at entrypoint
}
rule _Turbo_C_1987_
{
	meta:
		description = "Turbo C 1987"
	strings:
		$0 = {FB 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA}
	condition:
		$0 at entrypoint
}
rule _yodas_Protector_v1032_exescrcom__Ashkbiz_Danehkar_h_
{
	meta:
		description = "yoda's Protector v1.03.2 (.exe,.scr,.com) -> Ashkbiz Danehkar (h)"
	strings:
		$0 = {E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75}
	condition:
		$0 at entrypoint
}
rule _Cracked_by_Autohack_2_
{
	meta:
		description = "Cracked by Autohack (2)"
	strings:
		$0 = {0E 1F B4 09 BA ?? ?? CD 21 FA 8E 06 ?? ?? BE ?? ?? 8B 0E ?? ?? 83 F9}
	condition:
		$0 at entrypoint
}
rule _nSpack_V2x__LiuXingPing_
{
	meta:
		description = "nSpack V2.x -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5}
	condition:
		$0
}
rule _tElock_v042_
{
	meta:
		description = "tElock v0.42"
	strings:
		$0 = {C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08}
	condition:
		$0 at entrypoint
}
rule _Exe_Stealth_275a__WebtoolMaster_
{
	meta:
		description = "Exe Stealth 2.75a -> WebtoolMaster"
	strings:
		$0 = {EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v252b2_
{
	meta:
		description = "Armadillo v2.52b2"
	strings:
		$0 = {55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24}
	condition:
		$0 at entrypoint
}
rule _Adys_Glue_110_
{
	meta:
		description = "Ady's Glue 1.10"
	strings:
		$0 = {2E ?? ?? ?? ?? 0E 1F BF ?? ?? 33 DB 33 C0 AC}
	condition:
		$0 at entrypoint
}
rule _PE_Spin_v0b_
{
	meta:
		description = "PE Spin v0.b"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 26 E8 01 00 00 00 EA 5A 33 C9}
	condition:
		$0 at entrypoint
}
rule _Obsidium_V1258__Obsidium_Software_
{
	meta:
		description = "Obsidium V1.2.5.8 -> Obsidium Software"
	strings:
		$0 = {EB 01 ?? E8 ?? 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PrincessSandy_v10_eMiNENCE_Process_Patcher_Patch_
{
	meta:
		description = "PrincessSandy v1.0 eMiNENCE Process Patcher Patch"
	strings:
		$0 = {68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08}
	condition:
		$0
}
rule _Alloy_v1x2000_
{
	meta:
		description = "Alloy v1.x.2000"
	strings:
		$0 = {9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_LCC_Win32_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [LCC Win32 DLL] --> Anorganix"
	strings:
		$0 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9}
		$1 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASProtect_v11_BRS_
{
	meta:
		description = "ASProtect v1.1 BRS"
	strings:
		$0 = {60 E9 ?? 05}
	condition:
		$0 at entrypoint
}
rule _tElock_v098__tHE_EGOiSTE_h_
{
	meta:
		description = "tElock v0.98 -> tHE EGOiSTE (h)"
	strings:
		$0 = {E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_ExeSmasher__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [ExeSmasher] --> Anorganix"
	strings:
		$0 = {9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B}
		$1 = {9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v092_
{
	meta:
		description = "PECompact v0.92"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5}
	condition:
		$0 at entrypoint
}
rule _Exe_Shield_v17_
{
	meta:
		description = "Exe Shield v1.7"
	strings:
		$0 = {EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90}
		$1 = {EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _pex_V099__params_
{
	meta:
		description = "pex V0.99 -> params"
	strings:
		$0 = {E9 F5 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PESpin_v11__Cyberbob_h_
{
	meta:
		description = "PESpin v1.1 -> Cyberbob (h)"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF}
	condition:
		$0 at entrypoint
}
rule _RCryptor_v13__v14__Vaska_
{
	meta:
		description = "RCryptor v1.3 / v1.4 --> Vaska"
	strings:
		$0 = {55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at entrypoint
}
rule _FSG_v131_
{
	meta:
		description = "FSG v1.31"
	strings:
		$0 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9}
		$1 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PE_Ninja_v10__pDzA_kRAker_TNT_
{
	meta:
		description = "PE Ninja v1.0 -> +DzA kRAker TNT"
	strings:
		$0 = {BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint
}
rule _NsPacK_V37__LiuXingPing_
{
	meta:
		description = "NsPacK V3.7 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Microsoft_Visual_Cpp_50p_MFC__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual C++ 5.0+ (MFC)] --> Anorganix"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9}
		$1 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _RCryptor_v11__Vaska_
{
	meta:
		description = "RCryptor v1.1 --> Vaska"
	strings:
		$0 = {8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0
}
rule _UPX_v070_
{
	meta:
		description = "UPX v0.70"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07}
		$1 = {8C CB B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8D ?? ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC 2E ?? ?? ?? ?? 73}
		$2 = {60 E8 ?? ?? ?? ?? 58 83 ?? ?? 50 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 83 ?? ?? 31 DB EB}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Can2Exe_v001_
{
	meta:
		description = "Can2Exe v0.01"
	strings:
		$0 = {0E 1F 0E 07 E8 ?? ?? E8 ?? ?? 3A C6 73}
	condition:
		$0 at entrypoint
}
rule _WinZip_32bit_6x_
{
	meta:
		description = "WinZip (32-bit) 6.x"
	strings:
		$0 = {FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10}
	condition:
		$0 at entrypoint
}
rule _vfpexeNc_V500__Wang_JianGuo_
{
	meta:
		description = "vfp&exeNc V5.00 -> Wang JianGuo"
	strings:
		$0 = {60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC}
	condition:
		$0 at entrypoint
}
rule _tElock_v098b2_
{
	meta:
		description = "tElock v0.98b2"
	strings:
		$0 = {E9 1B E4 FF FF}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b7_
{
	meta:
		description = "PECompact v1.10b7"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14}
	condition:
		$0 at entrypoint
}
rule _CodeCrypt_v015b_
{
	meta:
		description = "CodeCrypt v0.15b"
	strings:
		$0 = {E9 31 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F}
	condition:
		$0 at entrypoint
}
rule _Vterminal_V10X__Lei_Peng_
{
	meta:
		description = "Vterminal V1.0X -> Lei Peng"
	strings:
		$0 = {E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_Install_System_v198_
{
	meta:
		description = "Nullsoft Install System v1.98"
	strings:
		$0 = {83 EC 0C 53 56 57 FF 15 2C 81 40}
	condition:
		$0 at entrypoint
}
rule _Spalsher_10__30__Amok_
{
	meta:
		description = "Spalsher 1.0 - 3.0 -> Amok"
	strings:
		$0 = {9C 60 8B 44 24 24 E8 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PEtite_v12_
{
	meta:
		description = "PEtite v1.2"
	strings:
		$0 = {9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_60__70__ASM_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0 / ASM)"
	strings:
		$0 = {E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v__If_you_know_this_version_post_on_PEiD_board_h2_
{
	meta:
		description = "ASProtect v?.? -> If you know this version, post on PEiD board (h2)"
	strings:
		$0 = {90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$1 = {90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 or $1
}
rule _PseudoSigner_02_FSG_131__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [FSG 1.31] --> Anorganix"
	strings:
		$0 = {BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80}
		$1 = {BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _XtremeProtector_v105_
{
	meta:
		description = "Xtreme-Protector v1.05"
	strings:
		$0 = {E9 ?? ?? 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _ASPack_v101b_
{
	meta:
		description = "ASPack v1.01b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _EXECryptor_2117__StrongbitSoftComplete_Development_h_
{
	meta:
		description = "EXECryptor 2.1.17 -> Strongbit/SoftComplete Development (h)"
	strings:
		$0 = {BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01}
	condition:
		$0
}
rule _VProtector_V10B__vcasm_
{
	meta:
		description = "VProtector V1.0B -> vcasm"
	strings:
		$0 = {55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50}
	condition:
		$0 at entrypoint
}
rule _Armadillo_440__Silicon_Realms_Toolworks_h_
{
	meta:
		description = "Armadillo 4.40 -> Silicon Realms Toolworks (h)"
	strings:
		$0 = {31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8}
		$1 = {31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8}
	condition:
		$0 or $1
}
rule _ORiEN_V212__Fisun_AV_
{
	meta:
		description = "ORiEN V2.12 -> Fisun A.V."
	strings:
		$0 = {E9 5D 01 00 00 CE D1 CE CD 0D}
	condition:
		$0 at entrypoint
}
rule _ThemidaWinLicense_V1802_p___Oreans_Technologies_
{
	meta:
		description = "Themida/WinLicense V1.8.0.2 +  -> Oreans Technologies"
	strings:
		$0 = {B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _beria_v007_public_WIP__symbiont_
{
	meta:
		description = "beria v0.07 public WIP --> symbiont"
	strings:
		$0 = {83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0}
	condition:
		$0 at entrypoint
}
rule _ASPack_v104b_
{
	meta:
		description = "ASPack v1.04b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D}
	condition:
		$0 at entrypoint
}
rule _Upack_v032_Beta_Patch__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.32 Beta (Patch) -> Sign by hot_UNP"
	strings:
		$0 = {BE 88 01 ?? ?? AD 50 ?? AD 91 F3 A5}
	condition:
		$0
}
rule _MEW_11_SE_v12_
{
	meta:
		description = "MEW 11 SE v1.2"
	strings:
		$0 = {E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0
}
rule _tElock_v100_
{
	meta:
		description = "tElock v1.00"
	strings:
		$0 = {E9 E5 E2 FF FF}
	condition:
		$0 at entrypoint
}
rule _Packman_0001__bubba_
{
	meta:
		description = "Packman 0.0.0.1 -> bubba"
	strings:
		$0 = {60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_Macromedia_Flash_Projector_60__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Macromedia Flash Projector 6.0] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Crunch_v5__BitArts_
{
	meta:
		description = "Crunch v5 -> Bit-Arts"
	strings:
		$0 = {EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00}
		$1 = {EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v0977_
{
	meta:
		description = "PECompact v0.977"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87}
	condition:
		$0 at entrypoint
}
rule _Winkript_v10_
{
	meta:
		description = "Winkript v1.0"
	strings:
		$0 = {33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58}
	condition:
		$0 at entrypoint
}
rule _VProtector_V11A__vcasm_
{
	meta:
		description = "VProtector V1.1A -> vcasm"
	strings:
		$0 = {EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _FSG_v120_Eng__dulekxt__Borland_Delphi__Borland_Cpp_
{
	meta:
		description = "FSG v1.20 (Eng) -> dulek/xt -> (Borland Delphi / Borland C++)"
	strings:
		$0 = {0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB}
		$1 = {0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPXcrypter__archphaseNWC_
{
	meta:
		description = "UPXcrypter -> archphase/NWC"
	strings:
		$0 = {BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _DBPE_vxxx_
{
	meta:
		description = "DBPE vx.xx"
	strings:
		$0 = {EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v260a_
{
	meta:
		description = "Armadillo v2.60a"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4}
	condition:
		$0 at entrypoint
}
rule _aPack_v082_
{
	meta:
		description = "aPack v0.82"
	strings:
		$0 = {1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB}
	condition:
		$0 at entrypoint
}
rule _MSLRH_v01__emadicius_
{
	meta:
		description = "[MSLRH] v0.1 -> emadicius"
	strings:
		$0 = {60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8}
	condition:
		$0
}
rule _Armadillo_v201_
{
	meta:
		description = "Armadillo v2.01"
	strings:
		$0 = {55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _HEALTH_v51_by_Muslim_MPolyak_
{
	meta:
		description = "HEALTH v.5.1 by Muslim M.Polyak"
	strings:
		$0 = {1E E8 ?? ?? 2E 8C 06 ?? ?? 2E 89 3E ?? ?? 8B D7 B8 ?? ?? CD 21 8B D8 0E 1F E8 ?? ?? 06 57 A1 ?? ?? 26}
	condition:
		$0 at entrypoint
}
rule _BeRoEXEPacker_V100__BeRo_
{
	meta:
		description = "BeRoEXEPacker V1.00 -> BeRo"
	strings:
		$0 = {BA ?? ?? ?? ?? 8D B2 ?? ?? ?? ?? 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15 ?? ?? ?? ?? 5F 5A 85 C0 74 2F 8B C8 8B 03 85 C0 74 22 0F BA F0 1F 72 04 8D 44 ?? ?? 51 52 57 50 51 FF 15 ?? ?? ?? ?? 5F 5A 59 85 C0 74 0B AB 83 C3 04 EB D8 83 C6 14 EB AA 61 C3}
	condition:
		$0
}
rule _Unknown_encryptor_2__PK7Tjrvx_
{
	meta:
		description = "Unknown encryptor (2) - PK7Tjrvx"
	strings:
		$0 = {06 B4 52 CD 21 07 E8 ?? ?? B4 62 CD 21 E8}
	condition:
		$0 at entrypoint
}
rule _Hasp_4_envelope_dongle_Alladin_
{
	meta:
		description = "Hasp 4 envelope dongle (Alladin)"
	strings:
		$0 = {10 02 D0 51 0F 00 83}
	condition:
		$0 at entrypoint
}
rule _NSPack_3x__Liu_Xing_Ping_
{
	meta:
		description = "NSPack 3.x -> Liu Xing Ping"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v10_
{
	meta:
		description = "ASProtect v1.0"
	strings:
		$0 = {60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D}
	condition:
		$0 at entrypoint
}
rule _VOB_ProtectCD_5_
{
	meta:
		description = "VOB ProtectCD 5"
	strings:
		$0 = {36 3E 26 8A C0 60 E8}
	condition:
		$0 at entrypoint
}
rule _PE_Diminisher_v01_
{
	meta:
		description = "PE Diminisher v0.1"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74}
		$1 = {5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _NTkrnl_Secure_Suite_V01__NTkrnl_Software_
{
	meta:
		description = "NTkrnl Secure Suite V0.1 -> NTkrnl Software"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3}
	condition:
		$0
}
rule _Password_Protector_c_MiniSoft_1992_
{
	meta:
		description = "Password Protector (c) MiniSoft 1992"
	strings:
		$0 = {06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA}
	condition:
		$0 at entrypoint
}
rule _AsCrypt_v01__SToRM__needs_to_be_added_
{
	meta:
		description = "AsCrypt v0.1 -> SToRM - needs to be added"
	strings:
		$0 = {80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 83 ?? ?? E2}
		$1 = {83 ?? ?? E2 ?? ?? E2 ?? FF}
		$2 = {80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 E2}
		$3 = {81 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? E2 ?? EB}
	condition:
		$0 or $1 or $2 or $3
}
rule _EXE32Pack_v13x_
{
	meta:
		description = "EXE32Pack v1.3x"
	strings:
		$0 = {3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? E8 ?? ?? ?? ?? 3B 74 01 ?? 5D 8B D5 81 ED}
	condition:
		$0 at entrypoint
}
rule _Stones_PE_Encryptor_v10_
{
	meta:
		description = "Stone's PE Encryptor v1.0"
	strings:
		$0 = {55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_02_32Lite_003__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [32Lite 0.03] --> Anorganix"
	strings:
		$0 = {60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68}
		$1 = {60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_02_JDPack_1x__JDProtect_09__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [JDPack 1.x / JDProtect 0.9] --> Anorganix"
	strings:
		$0 = {60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01}
		$1 = {60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _WWPACK_v305c4_Extractable_p_Virus_Shield_
{
	meta:
		description = "WWPACK v3.05c4 (Extractable + Virus Shield)"
	strings:
		$0 = {03 05 40 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at entrypoint
}
rule _DotFix_NiceProtect_vna_
{
	meta:
		description = "DotFix NiceProtect vna"
	strings:
		$0 = {60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29}
	condition:
		$0 at entrypoint
}
rule _PECompact_v09782_
{
	meta:
		description = "PECompact v0.978.2"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85}
	condition:
		$0 at entrypoint
}
rule _GHF_Protector__GPcH_
{
	meta:
		description = "GHF Protector / GPcH"
	strings:
		$0 = {60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 A0 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6}
	condition:
		$0 at entrypoint
}
rule _Obsidium_V12__Obsidium_Software_
{
	meta:
		description = "Obsidium V1.2 -> Obsidium Software"
	strings:
		$0 = {EB 02 ?? ?? E8 77 1E 00 00}
	condition:
		$0 at entrypoint
}
rule _NsPack_V14__LiuXingPing_
{
	meta:
		description = "NsPack V1.4 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Stelth_PE_101__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Ste@lth PE 1.01] --> Anorganix"
	strings:
		$0 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA ?? ?? ?? ?? FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00}
		$1 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA ?? ?? ?? ?? FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_NcuLi1688_
{
	meta:
		description = "Vx: Ncu-Li.1688"
	strings:
		$0 = {0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_FSG_131__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [FSG 1.31] --> Anorganix"
	strings:
		$0 = {BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9}
		$1 = {BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_Morphine_12__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Morphine 1.2] --> Anorganix"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 E2 90 90 90 EB 08 82 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 01 E9}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
		$2 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Stones_PE_Encruptor_v113_
{
	meta:
		description = "Stone`s PE Encruptor v1.13"
	strings:
		$0 = {55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81}
	condition:
		$0 at entrypoint
}
rule _PACKWIN_v101p_
{
	meta:
		description = "PACKWIN v1.01p"
	strings:
		$0 = {8C C0 FA 8E D0 BC ?? ?? FB 06 0E 1F 2E ?? ?? ?? ?? 8B F1 4E 8B FE 8C DB 2E ?? ?? ?? ?? 8E C3 FD F3 A4 53 B8 ?? ?? 50 CB}
	condition:
		$0 at entrypoint
}
rule _Neolite_v20_
{
	meta:
		description = "Neolite v2.0"
	strings:
		$0 = {E9 A6 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Upx_v12__Marcus__Lazlo_
{
	meta:
		description = "Upx v1.2 -> Marcus & Lazlo"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_PIMP_Install_System_v1x_
{
	meta:
		description = "Nullsoft PIMP Install System v1.x"
	strings:
		$0 = {83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _BamBam_v001_
{
	meta:
		description = "BamBam v0.01"
	strings:
		$0 = {6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? 00 A1 2B ?? ?? 00 66 8B 15 2F ?? ?? 00 B9 80 ?? ?? 00 2B CF 89 45 E8 89 0D 6B ?? ?? 00 66 89 55 EC 8B 41 3C 33 D2 03 C1}
	condition:
		$0
}
rule _TMTPascal_v040_
{
	meta:
		description = "TMT-Pascal v0.40"
	strings:
		$0 = {0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9}
	condition:
		$0 at entrypoint
}
rule _PECrypt_102_
{
	meta:
		description = "PE-Crypt 1.02"
	strings:
		$0 = {E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7}
	condition:
		$0 at entrypoint
}
rule _diProtector_V1X__diProtector_Software_
{
	meta:
		description = "diProtector V1.X -> diProtector Software"
	strings:
		$0 = {01 00 A0 E3 14 00 00 EB 00 00 20 E0 44 10 9F E5 03 2A A0 E3 40 30 A0 E3 AE 00 00 EB 30 00 8F E5 00 20 A0 E1 3A 0E 8F E2 00 00 80 E2 1C 10 9F E5 20 30 8F E2 0E 00 00 EB 14 00 9F E5 14 10 9F E5 7F 20 A0 E3 C5 00 00 EB 04 C0 8F E2 00 F0 9C E5}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Windows_Update_CAB_SFX_module_
{
	meta:
		description = "Microsoft Windows Update CAB SFX module"
	strings:
		$0 = {E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18}
	condition:
		$0
}
rule _MinGW_v32x_WinMain_
{
	meta:
		description = "MinGW v3.2.x (WinMain)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D}
	condition:
		$0 at entrypoint
}
rule _NX_PE_Packer_v10_
{
	meta:
		description = "NX PE Packer v1.0"
	strings:
		$0 = {FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_v1401_
{
	meta:
		description = "EXECryptor v1.4.0.1"
	strings:
		$0 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80}
		$1 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Libraries_by_John_Socha_
{
	meta:
		description = "Libraries by John Socha"
	strings:
		$0 = {BB ?? ?? 8E DB 2E 89 ?? ?? ?? 8D ?? ?? ?? 25 ?? ?? FA 8E D3 8B E0 FB 26 A1 A3 ?? ?? B4 30 CD 21}
	condition:
		$0 at entrypoint
}
rule _Upack_022__023_beta__Dwing_
{
	meta:
		description = "Upack 0.22 - 0.23 beta -> Dwing"
	strings:
		$0 = {6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 59 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00}
		$1 = {AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 ?? 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _SimplePack_111_Method_2NT__bagieTMX_h_
{
	meta:
		description = "SimplePack 1.11 Method 2(NT) -> bagie[TMX] (h)"
	strings:
		$0 = {4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 40 00 00 C0 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 EB 01 CD 64 A1 30 00 00 00 EB 01 CD 8B 48 0C E3 6F EB 01 CD 05 AC 00 00 00 EB 01 CD 66 81 38 93 08 EB 01 CD 75 0A EB 01 CD B8 38 FF FF FF EB 14 EB 01 CD 66 81 38 28 0A 75 4A EB 01 CD B8 1A FF FF FF EB 00 EB 01 CD 31 C9 EB 01 CD 51 EB 01 CD 51 EB 01 CD 6A 11 EB 01 CD 6A FE EB 01 CD E8 03 00 00 00 EB 01 CD 83 04 24 18 EB}
	condition:
		$0 at entrypoint
}
rule _CrackStop_v101_c_Stefan_Esser_1997_
{
	meta:
		description = "CrackStop v1.01 (c) Stefan Esser 1997"
	strings:
		$0 = {B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC}
	condition:
		$0 at entrypoint
}
rule _Zortech_C_
{
	meta:
		description = "Zortech C"
	strings:
		$0 = {E8 ?? ?? 2E FF ?? ?? ?? FC 06}
	condition:
		$0 at entrypoint
}
rule _UPX_Modified_stub_
{
	meta:
		description = "UPX Modified stub"
	strings:
		$0 = {79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF}
	condition:
		$0 at entrypoint
}
rule _Simple_UPX_Cryptor_v3042005_multi_layer_encryption__MANtiCORE_
{
	meta:
		description = "Simple UPX Cryptor v30.4.2005 [multi layer encryption] --> MANtiCORE"
	strings:
		$0 = {60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3}
		$1 = {60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v184_
{
	meta:
		description = "PECompact v1.84"
	strings:
		$0 = {33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81}
	condition:
		$0 at entrypoint
}
rule _Petite_13_
{
	meta:
		description = "Petite 1.3"
	strings:
		$0 = {66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1}
	condition:
		$0
}
rule _PC_Shrinker_v045_
{
	meta:
		description = "PC Shrinker v0.45"
	strings:
		$0 = {BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40}
	condition:
		$0 at entrypoint
}
rule _Obsidium_v1111_
{
	meta:
		description = "Obsidium v1.1.1.1"
	strings:
		$0 = {EB 02 ?? ?? E8 E7 1C 00 00}
	condition:
		$0 at entrypoint
}
rule _CRYPToCRACKs_PE_Protector_V092__Lukas_Fleischer_
{
	meta:
		description = "CRYPToCRACK's PE Protector V0.9.2 -> Lukas Fleischer"
	strings:
		$0 = {E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26}
	condition:
		$0 at entrypoint
}
rule _Cygwin32_
{
	meta:
		description = "Cygwin32"
	strings:
		$0 = {55 89 E5 83 EC 04 83 3D}
	condition:
		$0 at entrypoint
}
rule _Packed_with_PKLITE_v150_with_CRC_check_1_
{
	meta:
		description = "Packed with: PKLITE v1.50 with CRC check (1)"
	strings:
		$0 = {1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21}
	condition:
		$0 at entrypoint
}
rule _EP_v10_
{
	meta:
		description = "EP v1.0"
	strings:
		$0 = {50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1}
		$1 = {50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _AntiVirus_Vaccine_v103_
{
	meta:
		description = "AntiVirus Vaccine v.1.03"
	strings:
		$0 = {FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2}
	condition:
		$0 at entrypoint
}
rule _XtremeProtector_v106_
{
	meta:
		description = "Xtreme-Protector v1.06"
	strings:
		$0 = {B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02}
	condition:
		$0 at entrypoint
}
rule _Wise_Installer_Stub_
{
	meta:
		description = "Wise Installer Stub"
	strings:
		$0 = {55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF}
		$1 = {55 8B EC 81 EC ?? 04 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ?? 20}
		$2 = {55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2
}
rule _WinUpack_v030_beta__By_Dwing_h_
{
	meta:
		description = "WinUpack v0.30 beta -> By Dwing (h)"
	strings:
		$0 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00}
	condition:
		$0
}
rule _EXECryptor_v13045_
{
	meta:
		description = "EXECryptor v1.3.0.45"
	strings:
		$0 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1}
		$1 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1}
		$2 = {E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Microsoft_C_
{
	meta:
		description = "Microsoft C"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? B8}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Gleam_100__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Gleam 1.00] --> Anorganix"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Kuku886_
{
	meta:
		description = "Vx: Kuku.886"
	strings:
		$0 = {06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 ?? ?? ?? ?? ?? 90 B4 2F CD 21 53}
	condition:
		$0 at entrypoint
}
rule _ASProtect_vxx_
{
	meta:
		description = "ASProtect vx.x"
	strings:
		$0 = {60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD}
		$1 = {90 60 ?? ?? ?? 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v160__v165_
{
	meta:
		description = "PECompact v1.60 - v1.65"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12}
	condition:
		$0 at entrypoint
}
rule _Upack_v029_beta__Dwing_
{
	meta:
		description = "Upack v0.29 beta -> Dwing"
	strings:
		$0 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29}
	condition:
		$0 at entrypoint
}
rule _Petite_13__c1998_Ian_Luck_h_
{
	meta:
		description = "Petite 1.3 -> (c)1998 Ian Luck (h)"
	strings:
		$0 = {9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03}
	condition:
		$0 at entrypoint
}
rule _PCShrink_071_beta_
{
	meta:
		description = "PCShrink 0.71 beta"
	strings:
		$0 = {01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00}
	condition:
		$0 at entrypoint
}
rule _Soft_Defender_v11x__Randy_Li_
{
	meta:
		description = "Soft Defender v1.1x -> Randy Li"
	strings:
		$0 = {74 07 75 05 ?? ?? ?? ?? ?? 74 1F 75 1D ?? 68 ?? ?? ?? 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 ?? ?? ?? E8 F4 FF FF FF ?? ?? ?? 78 0F 79 0D}
	condition:
		$0 at entrypoint
}
rule _SimplePack_111_Method_1__bagieTMX_h_
{
	meta:
		description = "SimplePack 1.11 Method 1 -> bagie[TMX] (h)"
	strings:
		$0 = {60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC F3 A5 89 C1 83 E1 03 F3 A4 5F 5E 8B 04 24 89 EA 03 57 0C E8 3F 01 00 00 58 68 00 40 00 00 FF 77 10 50 FF 93 3C 03 00 00 83 C7 28 4E 75 9E BE ?? ?? ?? ?? 09 F6 0F 84 0C 01 00 00 01 EE 8B 4E 0C 09 C9 0F 84 FF 00 00 00 01 E9 89 CF 57 FF 93 30 03 00 00 09 C0 75 3D 6A 04 68 00 10 00 00 68 00 10 00 00 6A 00 FF 93 38 03 00 00 89 C6 8D 83 6F 02 00 00 57 50 56 FF 93 44 03 00 00 6A 10 6A 00 56 6A 00 FF 93 48 03 00 00 89 E5}
	condition:
		$0 at entrypoint
}
rule _Vx_Quake518_
{
	meta:
		description = "Vx: Quake.518"
	strings:
		$0 = {1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt32_Console_v10_v101_v102_
{
	meta:
		description = "PE Crypt32 (Console v1.0, v1.01, v1.02)"
	strings:
		$0 = {E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_PE_Pack_099__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PE Pack 0.99] --> Anorganix"
	strings:
		$0 = {60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9}
		$1 = {60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_V200V290__Markus_Oberhumer__Laszlo_Molnar__John_Reiser_
{
	meta:
		description = "UPX V2.00-V2.90 -> Markus Oberhumer & Laszlo Molnar & John Reiser"
	strings:
		$0 = {FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9}
	condition:
		$0
}
rule _BJFnt_v13_
{
	meta:
		description = ".BJFnt v1.3"
	strings:
		$0 = {EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB}
		$1 = {EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v168__v184_
{
	meta:
		description = "PECompact v1.68 - v1.84"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 7B 11}
	condition:
		$0 at entrypoint
}
rule _PROPACK_v208_
{
	meta:
		description = "PRO-PACK v2.08"
	strings:
		$0 = {8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53}
	condition:
		$0 at entrypoint
}
rule _Vx_Heloween1172_
{
	meta:
		description = "Vx: Heloween.1172"
	strings:
		$0 = {E8 ?? ?? 5E 81 EE ?? ?? 56 50 06 0E 1F 8C C0 01 ?? ?? 01 ?? ?? 80 ?? ?? ?? ?? 8B ?? ?? A3 ?? ?? 8A ?? ?? A2 ?? ?? B8 ?? ?? CD 21 3D}
	condition:
		$0 at entrypoint
}
rule _UPXScrambler_RC_v1x_
{
	meta:
		description = "UPX-Scrambler RC v1.x"
	strings:
		$0 = {90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF}
	condition:
		$0 at entrypoint
}
rule _ASPack_v102a_
{
	meta:
		description = "ASPack v1.02a"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v200_
{
	meta:
		description = "Armadillo v2.00"
	strings:
		$0 = {55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_Modifier_v01x_
{
	meta:
		description = "UPX Modifier v0.1x"
	strings:
		$0 = {50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD}
	condition:
		$0 at entrypoint
}
rule _MS_RunTime_Library_1988_04_
{
	meta:
		description = "MS Run-Time Library 1988 (04)"
	strings:
		$0 = {1E B8 ?? ?? 8E D8 B4 30 CD 21 3C 02 73 ?? BA ?? ?? E8 ?? ?? 06 33 C0 50 CB}
	condition:
		$0 at entrypoint
}
rule _WinUpack_v039_final_relocated_image_base__By_Dwing_c2005_h2_
{
	meta:
		description = "WinUpack v0.39 final (relocated image base) -> By Dwing (c)2005 (h2)"
	strings:
		$0 = {60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_60__80_
{
	meta:
		description = "Microsoft Visual C++ 6.0 - 8.0"
	strings:
		$0 = {68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 8B 44 24 10 89 6C 24 10 8D 6C 24 10 2B E0 53 56 57 8B 45 F8 89 65 E8 50 8B 45 FC C7 45 FC FF FF FF FF 89 45 F8 8D 45 F0 64 A3 00 00 00 00 C3 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B C9 51 C3}
		$1 = {3D 00 10 00 00 73 0E F7 D8 03 C4 83 C0 04 85 00 94 8B 00 50 C3 51 8D 4C 24 08 81 E9 00 10 00 00 2D 00 10 00 00 85 01 3D 00 10 00 00 73 EC 2B C8 8B C4 85 01 8B E1 8B 08 8B 40 04 50 C3}
		$2 = {68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 8B 44 24 10 89 6C 24 10 8D 6C 24 10 2B E0 53 56 57 8B 45 F8 89 65 E8 50 8B 45 FC C7 45 FC FF FF FF FF 89 45 F8 C3 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B C9 51 C3}
	condition:
		$0 or $1 or $2
}
rule _GPInstall_v50332_
{
	meta:
		description = "GP-Install v5.0.3.32"
	strings:
		$0 = {55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0}
		$1 = {55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0}
	condition:
		$0 or $1
}
rule _Anskya_Binder_v11__Anskya_
{
	meta:
		description = "Anskya Binder v1.1 -> Anskya"
	strings:
		$0 = {BE ?? ?? ?? 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11}
	condition:
		$0 at entrypoint
}
rule _SVK_Protector_v132_Eng__Pavol_Cerven_
{
	meta:
		description = "SVK Protector v1.32 (Eng) -> Pavol Cerven"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E}
	condition:
		$0 at entrypoint
}
rule _REC_v034_3_
{
	meta:
		description = "REC v0.34 [3]"
	strings:
		$0 = {06 1E B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB}
	condition:
		$0 at entrypoint
}
rule _PECompact_v133_
{
	meta:
		description = "PECompact v1.33"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 00 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E}
	condition:
		$0 at entrypoint
}
rule _PEtite_v22_
{
	meta:
		description = "PEtite v2.2"
	strings:
		$0 = {B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_ACProtect_109__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [ACProtect 1.09] --> Anorganix"
	strings:
		$0 = {60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 90 90 90 EB 06 00 00 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 E9}
		$1 = {60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
		$2 = {60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _ASProtect_v11_
{
	meta:
		description = "ASProtect v1.1"
	strings:
		$0 = {60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE}
	condition:
		$0 at entrypoint
}
rule _VIRUS__IWormKLEZ_
{
	meta:
		description = "VIRUS - I-Worm.KLEZ"
	strings:
		$0 = {55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0}
	condition:
		$0
}
rule _CHECKPRG_c_1992_
{
	meta:
		description = "CHECKPRG (c) 1992"
	strings:
		$0 = {33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74}
	condition:
		$0 at entrypoint
}
rule _WARNING__TROJAN__RobinPE_
{
	meta:
		description = "WARNING -> TROJAN -> RobinPE"
	strings:
		$0 = {60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__MASM32__TASM32_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32)"
	strings:
		$0 = {03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB}
		$1 = {03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB}
		$2 = {03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _PECompact_v110b4_
{
	meta:
		description = "PECompact v1.10b4"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44}
	condition:
		$0 at entrypoint
}
rule _nPack_v11_250_Beta__NEOx_
{
	meta:
		description = "nPack v1.1 250 Beta -> NEOx"
	strings:
		$0 = {83 3D 04 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E ?? ?? ?? 2B 05 08 ?? ?? ?? A3 00 ?? ?? ?? E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 ?? ?? ?? C7 05 04 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00}
	condition:
		$0 at entrypoint
}
rule _EXE_Shield_V06__SMoKE_
{
	meta:
		description = "EXE Shield V0.6 -> SMoKE"
	strings:
		$0 = {E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40}
	condition:
		$0 at entrypoint
}
rule _PESpin_v1304__Cyberbob_h_
{
	meta:
		description = "PESpin v1.304 -> Cyberbob (h)"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF}
	condition:
		$0 at entrypoint
}
rule _PEtite_v13_
{
	meta:
		description = "PEtite v1.3"
	strings:
		$0 = {66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Microsoft_Visual_Basic_60_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual Basic 6.0 DLL] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_Eddie1800_
{
	meta:
		description = "Vx: Eddie.1800"
	strings:
		$0 = {E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E}
	condition:
		$0 at entrypoint
}
rule _EncryptPE_V22006710__WFS_
{
	meta:
		description = "EncryptPE V2.2006.7.10 -> WFS"
	strings:
		$0 = {60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00}
	condition:
		$0 at entrypoint
}
rule _NsPacK_V33__LiuXingPing_
{
	meta:
		description = "NsPacK V3.3 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 00 74}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_C_v20_
{
	meta:
		description = "Microsoft Visual C v2.0"
	strings:
		$0 = {53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75}
	condition:
		$0 at entrypoint
}
rule _Upack_V03X__Dwing_
{
	meta:
		description = "Upack V0.3X -> Dwing"
	strings:
		$0 = {60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E}
	condition:
		$0 at entrypoint
}
rule _ILUCRYPT_v4015_exe_
{
	meta:
		description = "ILUCRYPT v4.015 [exe]"
	strings:
		$0 = {8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7}
	condition:
		$0 at entrypoint
}
rule _kkrunchy_v017__F_Giesen_
{
	meta:
		description = "kkrunchy v0.17 -> F. Giesen"
	strings:
		$0 = {FC FF 4D 08 31 D2 8D 7D 30 BE}
	condition:
		$0
}
rule _PseudoSigner_02_Watcom_CCpp_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Watcom C/C++ DLL] --> Anorganix"
	strings:
		$0 = {53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1}
		$1 = {53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ENIGMA_Protector__Sukhov_Vladimir_
{
	meta:
		description = "ENIGMA Protector -> Sukhov Vladimir"
	strings:
		$0 = {45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31}
	condition:
		$0
}
rule _PE_Packer_
{
	meta:
		description = "PE Packer"
	strings:
		$0 = {FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10}
	condition:
		$0 at entrypoint
}
rule _VcasmProtector_10_
{
	meta:
		description = "Vcasm-Protector 1.0"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83}
	condition:
		$0 at entrypoint
}
rule _Escargot_V01__ppMeat_
{
	meta:
		description = "Escargot V0.1 -> ++Meat"
	strings:
		$0 = {EB 04 40 30 2E 31 60 68 61}
	condition:
		$0 at entrypoint
}
rule _DotFix_Nice_Protect_21__GPcH_Soft_
{
	meta:
		description = "DotFix Nice Protect 2.1 -> GPcH Soft"
	strings:
		$0 = {E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 B8 ?? ?? ?? ?? 03 C5 50 B8 ?? ?? ?? ?? 03 C5 FF 10 BB ?? ?? ?? ?? 03 DD 83 C3 0C 53 50 B8 ?? ?? ?? ?? 03 C5 FF 10 6A 40 68 00 10 00 00 FF 74 24 2C 6A 00 FF D0 89 44 24 1C 61 C3}
	condition:
		$0
}
rule _Microsoft_Visual_Cpp_vxx_DLL_
{
	meta:
		description = "Microsoft Visual C++ vx.x DLL"
	strings:
		$0 = {00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68}
	condition:
		$0 at entrypoint
}
rule _Unknown_Packer__Northfox_
{
	meta:
		description = "Unknown Packer -> Northfox"
	strings:
		$0 = {54 59 68 61 7A 79}
	condition:
		$0 at entrypoint
}
rule _Obsidium_1200__Obsidium_Software_
{
	meta:
		description = "Obsidium 1.2.0.0 -> Obsidium Software"
	strings:
		$0 = {EB 02 ?? ?? E8 3F 1E 00 00}
	condition:
		$0 at entrypoint
}
rule _BeRo_Tiny_Pascal__BeRo__Farbrausch_
{
	meta:
		description = "BeRo Tiny Pascal -> BeRo / Farbrausch"
	strings:
		$0 = {E9 ?? ?? ?? ?? 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20}
	condition:
		$0 at entrypoint
}
rule _WinKript_v10__Mr_Crimson_h_
{
	meta:
		description = "WinKript v1.0 -> Mr. Crimson (h)"
	strings:
		$0 = {33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 83 C0 08 EB D5 61 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _Free_Pascal_09910_
{
	meta:
		description = "Free Pascal 0.99.10"
	strings:
		$0 = {E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29}
	condition:
		$0
}
rule _ACProtect_V13X__risco_
{
	meta:
		description = "ACProtect V1.3X -> risco"
	strings:
		$0 = {60 50 E8 01 00 00 00 75 83}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_71_
{
	meta:
		description = "Microsoft Visual C++ 7.1"
	strings:
		$0 = {8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 39 75 0C 0F 84 ?? ?? ?? ?? 33 C0 40 5E 5D C2 0C 00}
		$1 = {8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3}
		$2 = {8B FF 55 8B EC 56 33 F6 39 75 0C 75 0E 39 35 ?? ?? ?? ?? 7E 2D FF 0D ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 75 3D 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 75 04 33 C0 EB 67 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68}
	condition:
		$0 or $1 or $2
}
rule _PseudoSigner_01_NorthStar_PE_Shrinker_13__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [NorthStar PE Shrinker 1.3] --> Anorganix"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9}
		$1 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_01_PEtite_2x_level_0__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PEtite 2.x (level 0)] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 B8 00 90 90 00 6A 00 68 90 90 90 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68}
		$1 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 B8 00 90 90 00 6A 00 68 90 90 90 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_com_
{
	meta:
		description = "UPX [com]"
	strings:
		$0 = {B9 ?? ?? BE ?? ?? BF C0 FF FD}
	condition:
		$0 at entrypoint
}
rule _vprotector_12__vcasm_
{
	meta:
		description = "vprotector 1.2 -> vcasm"
	strings:
		$0 = {EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00}
	condition:
		$0 at entrypoint
}
rule _ASPack_v108_
{
	meta:
		description = "ASPack v1.08"
	strings:
		$0 = {90 75 01 FF E9}
		$1 = {90 90 90 75 01 FF E9}
		$2 = {90 90 75 01 FF E9}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _SimplePack_V1X_Method1__bagie_
{
	meta:
		description = "SimplePack V1.X (Method1) -> bagie"
	strings:
		$0 = {60 E8 00 00 00 00 5B 8D 5B FA BD ?? ?? ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0}
	condition:
		$0 at entrypoint
}
rule _PE_Protect_v09_
{
	meta:
		description = "PE Protect v0.9"
	strings:
		$0 = {E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F}
		$1 = {52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3}
	condition:
		$0 or $1 at entrypoint
}
rule _FSG_v120_Eng__dulekxt__Microsoft_Visual_Cpp_60__70_
{
	meta:
		description = "FSG v1.20 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)"
	strings:
		$0 = {EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA}
		$1 = {EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MSLRH_v031a_
{
	meta:
		description = "[MSLRH] v0.31a"
	strings:
		$0 = {60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F}
	condition:
		$0
}
rule _nPack_V111502006Beta__NEOxuinC_
{
	meta:
		description = "nPack V1.1.150.2006.Beta -> NEOx/[uinC]"
	strings:
		$0 = {83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 56 57 68 54 ?? ?? ?? FF 15 00 ?? ?? ?? 8B 35 08 ?? ?? ?? 8B F8 68 44 ?? ?? ?? 57 FF D6 68 38 ?? ?? ?? 57 A3 38 ?? ?? ?? FF D6 5F A3 34 ?? ?? ?? 5E C3}
		$1 = {83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FreeBASIC_v011_
{
	meta:
		description = "FreeBASIC v0.11"
	strings:
		$0 = {E8 ?? ?? 00 00 E8 01 00 00 00 C3 55 89 E5}
	condition:
		$0 at entrypoint
}
rule _Shegerd_Dongle_V478__MSCo_
{
	meta:
		description = "Shegerd Dongle V4.78 -> MS.Co."
	strings:
		$0 = {E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_DLL_
{
	meta:
		description = "Microsoft Visual C++ DLL"
	strings:
		$0 = {53 B8 01 00 00 00 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0}
		$1 = {53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14}
		$2 = {55 8B EC 56 57 BF 01 00 00 00 8B 75 0C}
		$3 = {53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _eXPressor_v13__CGSoftLabs_
{
	meta:
		description = "eXPressor v1.3 -> CGSoftLabs"
	strings:
		$0 = {45 78 50 72 2D 76 2E 31 2E 33 2E}
	condition:
		$0
}
rule _PE_Lock_NT_v202c_
{
	meta:
		description = "PE Lock NT v2.02c"
	strings:
		$0 = {EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD}
	condition:
		$0 at entrypoint
}
rule _JDPack_
{
	meta:
		description = "JDPack"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD 45}
	condition:
		$0 at entrypoint
}
rule _FSG_v131_Eng__dulekxt_
{
	meta:
		description = "FSG v1.31 (Eng) -> dulek/xt"
	strings:
		$0 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB}
		$1 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _DBPE_v153_
{
	meta:
		description = "DBPE v1.53"
	strings:
		$0 = {9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA}
	condition:
		$0 at entrypoint
}
rule _Vx_VirusConstructorIVPbased_
{
	meta:
		description = "Vx: VirusConstructor(IVP).based"
	strings:
		$0 = {E9 ?? ?? E8 ?? ?? 5D ?? ?? ?? ?? ?? 81 ED ?? ?? ?? ?? ?? ?? E8 ?? ?? 81 FC ?? ?? ?? ?? 8D ?? ?? ?? BF ?? ?? 57 A4 A5}
	condition:
		$0 at entrypoint
}
rule _Petite_v21_2_
{
	meta:
		description = "Petite v2.1 (2)"
	strings:
		$0 = {B8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50}
	condition:
		$0 at entrypoint
}
rule _Metrowerks_CodeWarrior_v20_Console_
{
	meta:
		description = "Metrowerks CodeWarrior v2.0 (Console)"
	strings:
		$0 = {55 89 E5 55 B8 FF FF FF FF 50 50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8}
	condition:
		$0
}
rule _Anticrack_Software_Protector_v109_ACProtect_
{
	meta:
		description = "Anticrack Software Protector v1.09 (ACProtect)"
	strings:
		$0 = {60 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01}
		$1 = {60 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 C3 ?? ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _aPack_v062_
{
	meta:
		description = "aPack v0.62"
	strings:
		$0 = {1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_VBOX_43_MTE__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [VBOX 4.3 MTE] --> Anorganix"
	strings:
		$0 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9}
		$1 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Obsidium_v13037__Obsidium_Software_h_
{
	meta:
		description = "Obsidium v1.3.0.37 -> Obsidium Software (h)"
	strings:
		$0 = {EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27}
	condition:
		$0 at entrypoint
}
rule _Vx_GRUNT2Family_
{
	meta:
		description = "Vx: GRUNT.2.Family"
	strings:
		$0 = {48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3}
	condition:
		$0 at entrypoint
}
rule _Upack_024_beta__Dwing_
{
	meta:
		description = "Upack 0.24 beta -> Dwing"
	strings:
		$0 = {BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0}
	condition:
		$0 at entrypoint
}
rule _PECompact_v094_
{
	meta:
		description = "PECompact v0.94"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02}
	condition:
		$0 at entrypoint
}
rule _Hide_PE_101__BGCorp_
{
	meta:
		description = "Hide PE 1.01 -> BGCorp"
	strings:
		$0 = {BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D}
		$1 = {BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PolyCrypt_PE__214b215__JLab_Software_Creations_hsigned_
{
	meta:
		description = "PolyCrypt PE - 2.1.4b/2.1.5 -> JLab Software Creations (h-signed)"
	strings:
		$0 = {50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45}
	condition:
		$0
}
rule _EXECryptor_2x__SoftComplete_Developement_
{
	meta:
		description = "EXECryptor 2.x -> SoftComplete Developement"
	strings:
		$0 = {A4 ?? ?? 00 00 00 00 00 FF FF FF FF 3C ?? ?? 00 94 ?? ?? 00 D8 ?? ?? 00 00 00 00 00 FF FF FF FF}
	condition:
		$0
}
rule _DrWeb_VirusFinding_Engine__InSoft_EDVSysteme_
{
	meta:
		description = "Dr.Web Virus-Finding Engine -> InSoft EDV-Systeme"
	strings:
		$0 = {B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04}
	condition:
		$0 at entrypoint
}
rule _eXpressor_v145__CGSoftLabs_
{
	meta:
		description = "eXpressor v1.4.5 -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C}
		$1 = {55 8B EC 83 EC ?? 53 56 57 83 65 DC 00 F3 EB 0C}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _AINEXE_v230_
{
	meta:
		description = "AINEXE v2.30"
	strings:
		$0 = {0E 07 B9 ?? ?? BE ?? ?? 33 FF FC F3 A4 A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8}
	condition:
		$0 at entrypoint
}
rule _PKZIPSFX_v11_198990_
{
	meta:
		description = "PKZIP-SFX v1.1 1989-90"
	strings:
		$0 = {FC 2E 8C 0E ?? ?? A1 ?? ?? 8C CB 81 C3 ?? ?? 3B C3 72 ?? 2D ?? ?? 2D ?? ?? FA BC ?? ?? 8E D0 FB}
	condition:
		$0 at entrypoint
}
rule _Petite_21_
{
	meta:
		description = "Petite 2.1"
	strings:
		$0 = {64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8}
	condition:
		$0
}
rule _ASPack_v103b_
{
	meta:
		description = "ASPack v1.03b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Obsidium_V1300__Obsidium_Software_
{
	meta:
		description = "Obsidium V1.3.0.0 -> Obsidium Software"
	strings:
		$0 = {EB 04 ?? ?? ?? ?? E8 ?? 00 00 00}
		$1 = {EB 04 ?? ?? ?? ?? E8 29 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _NoodleCrypt_v200_Eng__NoodleSpa_
{
	meta:
		description = "NoodleCrypt v2.00 (Eng) -> NoodleSpa"
	strings:
		$0 = {EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02}
	condition:
		$0 at entrypoint
}
rule _EXE_Stealth_v11_
{
	meta:
		description = "EXE Stealth v1.1"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC}
	condition:
		$0 at entrypoint
}
rule _aPack_v098b_exe_
{
	meta:
		description = "aPack v0.98b [exe]"
	strings:
		$0 = {93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA}
	condition:
		$0
}
rule _iLUCRYPT_v4018_exe_
{
	meta:
		description = "iLUCRYPT v4.018 [exe]"
	strings:
		$0 = {8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81}
	condition:
		$0 at entrypoint
}
rule _PEPACK_099_
{
	meta:
		description = "PE-PACK 0.99"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ED 06 80 BD E0 04 00 00 01 0F 84 F2}
	condition:
		$0 at entrypoint
}
rule _TPACK_v05c_m2_
{
	meta:
		description = "T-PACK v0.5c -m2"
	strings:
		$0 = {68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD}
	condition:
		$0 at entrypoint
}
rule _RAZOR_1911_encruptor_
{
	meta:
		description = "RAZOR 1911 encruptor"
	strings:
		$0 = {E8 ?? ?? BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b5_
{
	meta:
		description = "PECompact v1.10b5"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49}
	condition:
		$0 at entrypoint
}
rule _PeStubOEP_v1x_
{
	meta:
		description = "PeStubOEP v1.x"
	strings:
		$0 = {E8 05 00 00 00 33 C0 40 48 C3 E8 05}
		$1 = {90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF}
		$2 = {B8 ?? ?? ?? 00 FF E0}
	condition:
		$0 or $1 or $2
}
rule _PE_Lock_v106_
{
	meta:
		description = "PE Lock v1.06"
	strings:
		$0 = {00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45}
	condition:
		$0 at entrypoint
}
rule _VProtector_V10A__vcasm_
{
	meta:
		description = "VProtector V1.0A -> vcasm"
	strings:
		$0 = {55 8B EC 6A FF 68 8A 8E 40 00 68 C6 8E 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50}
	condition:
		$0 at entrypoint
}
rule _PEiDBundle_v102__BoB__BobSoft_
{
	meta:
		description = "PEiD-Bundle v1.02 --> BoB / BobSoft"
	strings:
		$0 = {60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44}
	condition:
		$0 at entrypoint
}
rule _Unpacked_BSSFX_Archive_v19_
{
	meta:
		description = "Unpacked BS-SFX Archive v1.9"
	strings:
		$0 = {1E 33 C0 50 B8 ?? ?? 8E D8 FA 8E D0 BC ?? ?? FB B8 ?? ?? CD 21 3C 03 73}
	condition:
		$0 at entrypoint
}
rule _VBOX_v42_MTE_
{
	meta:
		description = "VBOX v4.2 MTE"
	strings:
		$0 = {8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5}
	condition:
		$0 at entrypoint
}
rule _Yodas_Protector_v1032_Beta2__Ashkbiz_Danehkar_
{
	meta:
		description = "Yoda's Protector v1.03.2 Beta2 -> Ashkbiz Danehkar"
	strings:
		$0 = {E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PECompact_V2X_Bitsum_Technologies_
{
	meta:
		description = "PECompact V2.X-> Bitsum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43}
	condition:
		$0 at entrypoint
}
rule _PEiDBundle_v100__BoB__BobSoft_
{
	meta:
		description = "PEiD-Bundle v1.00 --> BoB / BobSoft"
	strings:
		$0 = {60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A}
	condition:
		$0 at entrypoint
}
rule _Packman_V10__Brandon_LaCombe_
{
	meta:
		description = "Packman V1.0 -> Brandon LaCombe"
	strings:
		$0 = {60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA}
	condition:
		$0 at entrypoint
}
rule _eXPressor_V10__CGSoftLabs_
{
	meta:
		description = "eXPressor V1.0 -> CGSoftLabs"
	strings:
		$0 = {E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00}
		$1 = {E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_02_DEF_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [DEF 1.0] --> Anorganix"
	strings:
		$0 = {BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01}
		$1 = {BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PESpin_v07__Cyberbob_h_
{
	meta:
		description = "PESpin v0.7 -> Cyberbob (h)"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF}
	condition:
		$0 at entrypoint
}
rule _Thinstall_24x__25x__Jitit_Software_
{
	meta:
		description = "Thinstall 2.4x - 2.5x -> Jitit Software"
	strings:
		$0 = {55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? BD ?? ?? ?? ?? 03 E8}
	condition:
		$0 at entrypoint
}
rule _Stones_PE_Encryptor_v113_
{
	meta:
		description = "Stone's PE Encryptor v1.13"
	strings:
		$0 = {55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28}
	condition:
		$0 at entrypoint
}
rule _tElock_099__10_private__tE_
{
	meta:
		description = "tElock 0.99 - 1.0 private -> tE!"
	strings:
		$0 = {E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _EEXE_Version_112_
{
	meta:
		description = "EEXE Version 1.12"
	strings:
		$0 = {B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21}
	condition:
		$0 at entrypoint
}
rule _TAV_
{
	meta:
		description = "TAV"
	strings:
		$0 = {E8 ?? ?? 4D 5A CB}
	condition:
		$0 at entrypoint
}
rule _DOS16M_DOS_Extender_c_Tenberry_Software_Inc_19871995_
{
	meta:
		description = "DOS/16M DOS Extender (c) Tenberry Software Inc 1987-1995"
	strings:
		$0 = {BF ?? ?? 8E C7 8E D7 BC ?? ?? 36 ?? ?? ?? ?? FF ?? ?? ?? 36 ?? ?? ?? ?? BE ?? ?? AC 8A D8 B7 00 ?? ?? 8B ?? ?? ?? 4F 8E C7}
	condition:
		$0 at entrypoint
}
rule _SVKProtector_v111_
{
	meta:
		description = "SVK-Protector v1.11"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23}
	condition:
		$0 at entrypoint
}
rule _FACRYPT_v10_
{
	meta:
		description = "FACRYPT v1.0"
	strings:
		$0 = {B9 ?? ?? B3 ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3}
	condition:
		$0 at entrypoint
}
rule _RCryptor_v13b__Vaska_
{
	meta:
		description = "RCryptor v1.3b --> Vaska"
	strings:
		$0 = {61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at entrypoint
}
rule _ASPR_Stripper_v2x_unpacked_
{
	meta:
		description = "ASPR Stripper v2.x unpacked"
	strings:
		$0 = {BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 9C FC BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 AA 9D 61 C3 55 8B EC}
	condition:
		$0 at entrypoint
}
rule _Obsidium_V125__Obsidium_Software_
{
	meta:
		description = "Obsidium V1.25 -> Obsidium Software"
	strings:
		$0 = {E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3}
	condition:
		$0 at entrypoint
}
rule _RLPack_V112V114_aPlib_043__ap0x_
{
	meta:
		description = "RLPack V1.12-V1.14 (aPlib 0.43) -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB}
	condition:
		$0 at entrypoint
}
rule __Protector_v1111_DDeMPE_Engine_v09_DDeMCI_v092_
{
	meta:
		description = "*** Protector v1.1.11 (DDeM->PE Engine v0.9, DDeM->CI v0.9.2)"
	strings:
		$0 = {53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04}
		$1 = {53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Vx_KBDflags1024_
{
	meta:
		description = "Vx: KBDflags.1024"
	strings:
		$0 = {8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22}
	condition:
		$0 at entrypoint
}
rule _Vx_Slowload_
{
	meta:
		description = "Vx: Slowload"
	strings:
		$0 = {03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01}
	condition:
		$0 at entrypoint
}
rule _PECompact_v25_Retail_Slim_Loader__Bitsum_Technologies_
{
	meta:
		description = "PECompact v2.5 Retail (Slim Loader) -> Bitsum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00}
	condition:
		$0 at entrypoint
}
rule _Vx_Eddiebased1745_
{
	meta:
		description = "Vx: Eddie.based.1745"
	strings:
		$0 = {E8 ?? ?? 5E 81 EE ?? ?? FC ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA ?? 8B E6 81 ?? ?? ?? FB ?? 3B ?? ?? ?? ?? ?? 50 06 ?? 56 1E 8B FE 33 C0 ?? 50 8E D8}
	condition:
		$0 at entrypoint
}
rule _MS_RunTime_Library_1992_13_
{
	meta:
		description = "MS Run-Time Library 1992 (13)"
	strings:
		$0 = {BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB 33 DB B8 ?? ?? CD 21}
	condition:
		$0 at entrypoint
}
rule _UPX_Inliner_v10_by_GPcH_
{
	meta:
		description = "UPX Inliner v1.0 by GPcH"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01}
	condition:
		$0
}
rule _Upack_Unknown_DLL___Sign_by_hot_UNP_
{
	meta:
		description = "Upack_Unknown (DLL ???) -> Sign by hot_UNP"
	strings:
		$0 = {60 E8 09 00 00 00 17 CD 00 00 E9 06 02}
	condition:
		$0 at entrypoint
}
rule _PESHiELD_v0251_
{
	meta:
		description = "PESHiELD v0.251"
	strings:
		$0 = {5D 83 ED 06 EB 02 EA 04 8D}
	condition:
		$0 at entrypoint
}
rule _yC_v13_by_Ashkbiz_Danehkar_
{
	meta:
		description = "yC v1.3 by Ashkbiz Danehkar"
	strings:
		$0 = {55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC}
	condition:
		$0
}
rule _Turbo_Cpp_30_1990_
{
	meta:
		description = "Turbo C++ 3.0 1990"
	strings:
		$0 = {8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B ?? ?? ?? 8E DA A3 ?? ?? 8C 06}
	condition:
		$0 at entrypoint
}
rule _DIET_v102b_v110a_v120_
{
	meta:
		description = "DIET v1.02b, v1.10a, v1.20"
	strings:
		$0 = {BE ?? ?? BF ?? ?? B9 ?? ?? 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC}
	condition:
		$0 at entrypoint
}
rule _NsPacK_V36__LiuXingPing_
{
	meta:
		description = "NsPacK V3.6 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00}
	condition:
		$0 at entrypoint
}
rule _Private_Personal_Packer_PPP_v102__ConquestOfTroycom_
{
	meta:
		description = "Private Personal Packer (PPP) v1.0.2 --> ConquestOfTroy.com"
	strings:
		$0 = {E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00}
	condition:
		$0 at entrypoint
}
rule _PEtite_v20_
{
	meta:
		description = "PEtite v2.0"
	strings:
		$0 = {B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68}
	condition:
		$0 at entrypoint
}
rule _PESpin_v03_Eng__cyberbob_
{
	meta:
		description = "PESpin v0.3 (Eng) -> cyberbob"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF}
		$1 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PseudoSigner_02_CodeLock__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Code-Lock] --> Anorganix"
	strings:
		$0 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B}
		$1 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Armadillo_v190a_
{
	meta:
		description = "Armadillo v1.90a"
	strings:
		$0 = {55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PKLITE_v200c_
{
	meta:
		description = "PKLITE v2.00c"
	strings:
		$0 = {50 B8 ?? ?? BA ?? ?? 3B C4 73 ?? 8B C4 2D ?? ?? 25 ?? ?? 8B F8 B9 ?? ?? BE ?? ?? FC}
	condition:
		$0 at entrypoint
}
rule _VMProtect_V1X__PolyTech_
{
	meta:
		description = "VMProtect V1.X -> PolyTech"
	strings:
		$0 = {9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8}
	condition:
		$0
}
rule _Special_EXE_Password_Protector_v10_
{
	meta:
		description = "Special EXE Password Protector v1.0"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77}
	condition:
		$0 at entrypoint
}
rule _NsPack_V2X__LiuXingPing_
{
	meta:
		description = "NsPack V2.X -> LiuXingPing"
	strings:
		$0 = {6E 73 70 61 63 6B 24 40}
	condition:
		$0
}
rule _Obsidium_v1250__Obsidium_Software_h_
{
	meta:
		description = "Obsidium v1.2.5.0 -> Obsidium Software (h)"
	strings:
		$0 = {E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00}
		$1 = {E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ARM_Protector_v01_by_SMoKE_
{
	meta:
		description = "ARM Protector v0.1 by SMoKE"
	strings:
		$0 = {E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0}
		$1 = {E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0}
	condition:
		$0 or $1
}
rule _PEtite_v21_
{
	meta:
		description = "PEtite v2.1"
	strings:
		$0 = {B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50}
	condition:
		$0 at entrypoint
}
rule _RCryptor_v15_Private__Vaska_
{
	meta:
		description = "RCryptor v1.5 (Private) --> Vaska"
	strings:
		$0 = {83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at entrypoint
}
rule _Upack_v032_Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.32 Beta -> Sign by hot_UNP"
	strings:
		$0 = {BE 88 01 ?? ?? AD 50 ?? AD 91 ?? F3 A5}
		$1 = {BE 88 01 ?? ?? AD 50 ?? ?? AD 91 F3 A5}
	condition:
		$0 or $1
}
rule _E_language_
{
	meta:
		description = "E language"
	strings:
		$0 = {E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF}
	condition:
		$0 at entrypoint
}
rule _Vx_Caz1204_
{
	meta:
		description = "Vx: Caz.1204"
	strings:
		$0 = {E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10}
	condition:
		$0 at entrypoint
}
rule _PUNiSHER_V15_Demo_FEUERRADER_
{
	meta:
		description = "PUNiSHER V1.5 Demo-> FEUERRADER"
	strings:
		$0 = {EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _UG2002_Cruncher_v03b3_
{
	meta:
		description = "UG2002 Cruncher v0.3b3"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58}
	condition:
		$0 at entrypoint
}
rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cppx_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)x"
	strings:
		$0 = {1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00}
	condition:
		$0 at entrypoint
}
rule _Vx_Uddy2617_
{
	meta:
		description = "Vx: Uddy.2617"
	strings:
		$0 = {2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? 8C C8 8E D8 8C ?? ?? ?? 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? 8C C8 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? B8 AB 9C CD 2F 3D 76 98}
	condition:
		$0 at entrypoint
}
rule _PEPaCK_v10__C_Copyright_1998_by_ANAKiN_h_
{
	meta:
		description = "PE-PaCK v1.0 -> (C) Copyright 1998 by ANAKiN (h)"
	strings:
		$0 = {C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 2D 3D FE 20 50 45 2D 50 41 43 4B 20 76 31 2E 30 20 2D FE 2D 20 28 43 29 20 43 6F 70}
	condition:
		$0
}
rule _Shrinker_v33_
{
	meta:
		description = "Shrinker v3.3"
	strings:
		$0 = {83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8}
	condition:
		$0 at entrypoint
}
rule _Vx_Noon1163_
{
	meta:
		description = "Vx: Noon.1163"
	strings:
		$0 = {E8 ?? ?? 5B 50 56 B4 CB CD 21 3C 07 ?? ?? 81 ?? ?? ?? 2E ?? ?? 4D 5A ?? ?? BF 00 01 89 DE FC}
	condition:
		$0 at entrypoint
}
rule _WebCops_DLL__LINK_Data_Security_
{
	meta:
		description = "WebCops [DLL] -> LINK Data Security"
	strings:
		$0 = {A8 BE 58 DC D6 CC C4 63 4A 0F E0 02 BB CE F3 5C 50 23 FB 62 E7 3D 2B}
	condition:
		$0 at entrypoint
}
rule _PeX_099__bartCrackPl_
{
	meta:
		description = "PeX 0.99 -> bart^CrackPl"
	strings:
		$0 = {E9 F5 ?? ?? ?? 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4}
	condition:
		$0 at entrypoint
}
rule _PROTECT_EXECOM_v50_
{
	meta:
		description = "PROTECT! EXE/COM v5.0"
	strings:
		$0 = {1E 0E 0E 1F 07}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v250_
{
	meta:
		description = "Armadillo v2.50"
	strings:
		$0 = {55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0}
		$1 = {55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASProtect_133__21_Registered__Alexey_Solodovnikov_
{
	meta:
		description = "ASProtect 1.33 - 2.1 Registered -> Alexey Solodovnikov"
	strings:
		$0 = {68 01 ?? ?? ?? E8 01 00 00 00 C3 C3}
	condition:
		$0 at entrypoint
}
rule _PKLITE_v150_1_
{
	meta:
		description = "PKLITE v1.50 (1)"
	strings:
		$0 = {50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21}
	condition:
		$0 at entrypoint
}
rule _HACKSTOP_v100_
{
	meta:
		description = "HACKSTOP v1.00"
	strings:
		$0 = {FA BD ?? ?? FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_V22X__softcompletecom_
{
	meta:
		description = "EXECryptor V2.2X -> softcomplete.com"
	strings:
		$0 = {FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00}
	condition:
		$0
}
rule _MS_RunTime_Library_1990_10_
{
	meta:
		description = "MS Run-Time Library 1990 (10)"
	strings:
		$0 = {E8 ?? ?? 2E FF 2E ?? ?? BB ?? ?? E8 ?? ?? CB}
	condition:
		$0 at entrypoint
}
rule _tElock_099__tE_
{
	meta:
		description = "tElock 0.99 -> tE!"
	strings:
		$0 = {E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v60_DLL_
{
	meta:
		description = "Microsoft Visual Basic v6.0 DLL"
	strings:
		$0 = {5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_XCR_011__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [XCR 0.11] --> Anorganix"
	strings:
		$0 = {60 8B F0 33 DB 83 C3 01 83 C0 01 E9}
		$1 = {60 8B F0 33 DB 83 C3 01 83 C0 01 E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _BJFnt_v11b_
{
	meta:
		description = ".BJFnt v1.1b"
	strings:
		$0 = {EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56}
	condition:
		$0 at entrypoint
}
rule _PC_Guard_for_Win32_v500__SofProBlagoje_Ceklic_h_
{
	meta:
		description = "PC Guard for Win32 v5.00 -> SofPro/Blagoje Ceklic (h)"
	strings:
		$0 = {FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 ?? ?? ?? 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C}
	condition:
		$0 at entrypoint
}
rule _PseudoSigner_01_Borland_Delphi_30__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Borland Delphi 3.0] --> Anorganix"
	strings:
		$0 = {55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 E9}
		$1 = {55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
		$2 = {55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _DEF_v100_Eng__bartxt_
{
	meta:
		description = "DEF v1.00 (Eng) -> bart/xt"
	strings:
		$0 = {BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$1 = {BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_70_Custom_
{
	meta:
		description = "Microsoft Visual C++ 7.0 Custom"
	strings:
		$0 = {60 BE 00 B0 44 00 8D BE 00 60 FB FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v2xx_CopyMem_II_
{
	meta:
		description = "Armadillo v2.xx (CopyMem II)"
	strings:
		$0 = {6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_224__StrongbitSoftComplete_Development_h2_
{
	meta:
		description = "EXECryptor 2.2.4 -> Strongbit/SoftComplete Development (h2)"
	strings:
		$0 = {E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 ?? 00 00 00}
	condition:
		$0 at entrypoint
}
rule _CryptCom_v11_
{
	meta:
		description = "CryptCom v1.1"
	strings:
		$0 = {BF ?? ?? 57 BE ?? ?? ?? B9 ?? ?? F3 A4 C3 8B ?? ?? ?? 8B ?? ?? ?? BF ?? ?? 57 BE ?? ?? ?? AD 33 C2 AB E2 ?? C3}
	condition:
		$0 at entrypoint
}
rule _PCPEC_alpha_
{
	meta:
		description = "PCPEC [alpha]"
	strings:
		$0 = {53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ?? ?? ?? ?? ?? 2B ?? ?? ?? ?? ?? 83}
	condition:
		$0 at entrypoint
}
rule _nSpack_V23__LiuXingPing_
{
	meta:
		description = "nSpack V2.3 -> LiuXingPing"
	strings:
		$0 = {9C 60 70 61 63 6B 24 40}
	condition:
		$0
}
rule _Armadillo_v190_
{
	meta:
		description = "Armadillo v1.90"
	strings:
		$0 = {55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _TXT2COM_
{
	meta:
		description = "TXT2COM"
	strings:
		$0 = {E8 ?? ?? CD 20}
	condition:
		$0 at entrypoint
}
rule _SoftWrap_
{
	meta:
		description = "SoftWrap"
	strings:
		$0 = {52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 ?? ?? ?? E8 ?? 01 ?? ?? 60 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F}
	condition:
		$0 at entrypoint
}
rule _MingWin32__Dev_Cpp_v4x_h_
{
	meta:
		description = "MingWin32 - Dev C++ v4.x (h)"
	strings:
		$0 = {55 89 E5 83 EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 55 89 E5 83 EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? 00}
	condition:
		$0 at entrypoint
}
rule _UPXHiT_v001_
{
	meta:
		description = "UPX$HiT v0.0.1"
	strings:
		$0 = {94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61}
	condition:
		$0
}
rule _PESHiELD_02_
{
	meta:
		description = "PE-SHiELD 0.2"
	strings:
		$0 = {60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04}
	condition:
		$0 at entrypoint
}
rule _ASPack_v107b_DLL_
{
	meta:
		description = "ASPack v1.07b (DLL)"
	strings:
		$0 = {60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5}
	condition:
		$0 at entrypoint
}
rule _NTKrnlPacker__Ashkbiz_Danehkar_
{
	meta:
		description = "NTKrnlPacker -> Ashkbiz Danehkar"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74}
	condition:
		$0
}
rule _WARNING__TROJAN__HuiGeZi_
{
	meta:
		description = "WARNING -> TROJAN -> HuiGeZi"
	strings:
		$0 = {55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF}
	condition:
		$0 at entrypoint
}
rule _CauseWay_DOS_Extender_v325_
{
	meta:
		description = "CauseWay DOS Extender v3.25"
	strings:
		$0 = {FA 16 1F 26 ?? ?? ?? 83 ?? ?? 8E D0 FB 06 16 07 BE ?? ?? 8B FE B9 ?? ?? F3 A4 07}
	condition:
		$0 at entrypoint
}
rule _CrunchPE_v20xx_
{
	meta:
		description = "Crunch/PE v2.0.x.x"
	strings:
		$0 = {55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 55 BB ?? ?? ?? ?? 03 DD 53 64 67 FF 36 ?? ?? 64 67 89 26}
	condition:
		$0 at entrypoint
}
rule _VIRUS__IWormHybris_
{
	meta:
		description = "VIRUS - I-Worm.Hybris"
	strings:
		$0 = {EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15}
	condition:
		$0
}
rule _VIRUS__IWormBagle_
{
	meta:
		description = "VIRUS - I-Worm.Bagle"
	strings:
		$0 = {6A 00 E8 95 01 00 00 E8 9F E6 FF FF 83 3D 03 50 40 00 00 75 14 68 C8 AF 00 00 E8 01 E1 FF FF 05 88 13 00 00 A3 03 50 40 00 68 5C 57 40 00 68 F6 30 40 00 FF 35 03 50 40 00 E8 B0 EA FF FF E8 3A FC FF FF 83 3D 54 57 40 00 00 74 05 E8 F3 FA FF FF 68 E8 03 00}
	condition:
		$0
}
rule _ACProtect_v135__risco_software_Inc__Anticrack_Software_h_
{
	meta:
		description = "ACProtect v1.35 -> risco software Inc. & Anticrack Software (h)"
	strings:
		$0 = {4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 53 45 52 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 47 65 74 50 72 6F 63}
	condition:
		$0
}
rule _IMPostor_Pack_10__Mahdi_Hezavehi_
{
	meta:
		description = "IMPostor Pack 1.0 -> Mahdi Hezavehi"
	strings:
		$0 = {BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00}
	condition:
		$0 at entrypoint
}
rule _PKLITE_v150_Device_driver_compression_
{
	meta:
		description = "PKLITE v1.50 (Device driver compression)"
	strings:
		$0 = {B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB}
	condition:
		$0 at entrypoint
}
rule _EXE2COM_regular_
{
	meta:
		description = "EXE2COM (regular)"
	strings:
		$0 = {E9 8C CA 81 C3 ?? ?? 3B 16 ?? ?? 76 ?? BA ?? ?? B4 09 CD 21 CD 20 0D}
	condition:
		$0 at entrypoint
}
rule _Turbo_Basic_v10_1987_
{
	meta:
		description = "Turbo Basic v1.0 1987"
	strings:
		$0 = {2E 8C ?? ?? ?? 2E C7}
	condition:
		$0 at entrypoint
}
rule _Microsoft_CAB_SFX_module_
{
	meta:
		description = "Microsoft CAB SFX module"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20}
	condition:
		$0 at entrypoint
}
rule _EXE_Stealth_v273_
{
	meta:
		description = "EXE Stealth v2.73"
	strings:
		$0 = {EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02}
		$1 = {EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02}
	condition:
		$0 or $1
}
rule _RLPack_V10beta__ap0x_
{
	meta:
		description = "RLPack V1.0.beta -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB}
	condition:
		$0 at entrypoint
}
rule _WWPACK_v300_v301_Extractable_
{
	meta:
		description = "WWPACK v3.00, v3.01 (Extractable)"
	strings:
		$0 = {B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC}
	condition:
		$0 at entrypoint
}
rule _Armadillo_v190b4_
{
	meta:
		description = "Armadillo v1.90b4"
	strings:
		$0 = {55 8B EC 6A FF 68 08 E2 40 00 68 B4 96 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
		$1 = {55 8B EC 6A FF 68 08 E2 40 00 68 B4 96 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FSG_v110_Eng__bartxt__Watcom_CCpp_EXE_
{
	meta:
		description = "FSG v1.10 (Eng) -> bart/xt -> (Watcom C/C++ EXE)"
	strings:
		$0 = {EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02}
	condition:
		$0 at entrypoint
}
rule _Petite_v21_1_
{
	meta:
		description = "Petite v2.1 (1)"
	strings:
		$0 = {B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50}
	condition:
		$0 at entrypoint
}
rule _kkrunchy__Ryd_
{
	meta:
		description = "kkrunchy -> Ryd"
	strings:
		$0 = {BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10}
	condition:
		$0 at entrypoint
}
rule _StarForce_V3X_DLL__StarForce_Copy_Protection_System_
{
	meta:
		description = "StarForce V3.X DLL -> StarForce Copy Protection System"
	strings:
		$0 = {E8 ?? ?? ?? ?? 00 00 00 00 00 00}
	condition:
		$0 at entrypoint
}
rule _PECompact_v122_
{
	meta:
		description = "PECompact v1.22"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v12x_
{
	meta:
		description = "ASProtect v1.2x"
	strings:
		$0 = {00 00 68 01 ?? ?? ?? C3 AA}
	condition:
		$0 at entrypoint
}
rule _Thinstall_vxx_
{
	meta:
		description = "Thinstall vx.x"
	strings:
		$0 = {B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v71_DLL_
{
	meta:
		description = "Microsoft Visual C++ v7.1 DLL"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 E4 53 56 57 89 65 E8 C7 45 E4 01 00 00 00 C7 45 FC}
		$1 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? 40 00 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1}
		$2 = {83 7C 24 08 01 75 ?? ?? ?? 24 04 50 A3 ?? ?? ?? 50 FF 15 00 10 ?? 50 33 C0 40 C2 0C 00}
		$3 = {6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _tElock_v080_
{
	meta:
		description = "tElock v0.80"
	strings:
		$0 = {60 E8 F9 11 00 00 C3 83}
	condition:
		$0 at entrypoint
}
rule _PKLITE_v200b_
{
	meta:
		description = "PKLITE v2.00b"
	strings:
		$0 = {50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 2D ?? ?? 8E D0 51 2D ?? ?? 8E C0 50 B9}
	condition:
		$0 at entrypoint
}
rule _XPack_152__164_
{
	meta:
		description = "XPack 1.52 - 1.64"
	strings:
		$0 = {8B EC FA 33 C0 8E D0 BC ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? EB}
	condition:
		$0 at entrypoint
}
rule _EXE_Stealth_v274__WebToolMaster_
{
	meta:
		description = "EXE Stealth v2.74 -> WebToolMaster"
	strings:
		$0 = {EB 00 EB 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 90 E8 00 00 00 00 5D}
	condition:
		$0 at entrypoint
}
rule _vfpexeNc_v600__Wang_JianGuo_
{
	meta:
		description = "vfp&exeNc v6.00 -> Wang JianGuo"
	strings:
		$0 = {60 E8 01 00 00 00 63 58 E8 01 00 00 00 7A 58 2D 0D 10 40 00 8D 90 C1 10 40 00 52 50 8D 80 49 10 40 00 5D 50 8D 85 65 10 40 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC}
	condition:
		$0 at entrypoint
}
rule _WATCOM_CCpp_DLL_
{
	meta:
		description = "WATCOM C/C++ DLL"
	strings:
		$0 = {53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87}
	condition:
		$0 at entrypoint
}
rule _PECompact_v099_
{
	meta:
		description = "PECompact v0.99"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85}
	condition:
		$0 at entrypoint
}
rule _Vx_XPEH4768_
{
	meta:
		description = "Vx: XPEH.4768"
	strings:
		$0 = {E8 ?? ?? 5B 81 ?? ?? ?? 50 56 57 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B8 01 00 50 B8 ?? ?? 50 E8}
	condition:
		$0 at entrypoint
}
rule _Vx_ACME_Clonewar_Mutant_
{
	meta:
		description = "Vx: ACME (Clonewar Mutant)"
	strings:
		$0 = {FC AD 3D FF FF 74 20 E6 42 8A C4 E6 42 E4 61 0C 03 E6 61 AD B9 40 1F E2 FE}
	condition:
		$0 at entrypoint
}
rule _PCGuard_v500d_
{
	meta:
		description = "PC-Guard v5.00d"
	strings:
		$0 = {FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C}
	condition:
		$0 at entrypoint
}
rule _aPack_v098b_com_
{
	meta:
		description = "aPack v0.98b [com]"
	strings:
		$0 = {BE ?? ?? BF ?? ?? 8B CF FC 57 F3 A4 C3 BF ?? ?? 57 57 BE ?? ?? B2 ?? BD ?? ?? 50 A4}
	condition:
		$0
}
rule _SLR_OPTLINK_1_
{
	meta:
		description = "SLR (OPTLINK) (1)"
	strings:
		$0 = {87 C0 EB ?? 71 ?? 02 D8}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v50__v60_
{
	meta:
		description = "Microsoft Visual Basic v5.0 - v6.0"
	strings:
		$0 = {FF 25 ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF}
		$1 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 ?? 00 00 00 30 ?? 00}
	condition:
		$0 or $1
}
rule _eXPressor_v15x__CGSoftLabs_h_
{
	meta:
		description = "eXPressor v1.5x -> CGSoftLabs (h)"
	strings:
		$0 = {55 8B EC 81 EC 58 02 00 00 53 56 57 83 A5 CC FD FF FF 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C 01 75 23}
	condition:
		$0 at entrypoint
}
