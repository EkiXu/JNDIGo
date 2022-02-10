package gadget

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

//refer to https://github.com/4ra1n/Gososerial/blob/master/ysoserial/gadget/base.go
func GenerateTCSTRING(str string) string {
	finalCmd := bytes.Buffer{}
	finalCmd.WriteString("74")
	cmdLenByte := make([]byte, 2)
	binary.BigEndian.PutUint16(cmdLenByte, uint16(len(str)))
	cmdLenStr := strings.ToUpper(hex.EncodeToString(cmdLenByte))
	data := strings.ToUpper(hex.EncodeToString([]byte(str)))
	finalCmd.WriteString(cmdLenStr)
	finalCmd.WriteString(data)
	return finalCmd.String()
}
