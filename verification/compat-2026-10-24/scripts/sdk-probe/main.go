// Command sdkprobe verifies that the pinned Go toolchain can build against the
// Moby client module and negotiate the Engine API version.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/moby/moby/client"
)

type report struct {
	GoVersion        string `json:"go_version"`
	GoOS             string `json:"go_os"`
	GoArch           string `json:"go_arch"`
	ClientModule     string `json:"client_module"`
	ClientModuleVer  string `json:"client_module_version"`
	ClientMaxAPI     string `json:"client_max_api"`
	ClientMinAPI     string `json:"client_min_api"`
	NegotiatedAPI    string `json:"negotiated_api"`
	PingAPIVersion   string `json:"ping_api_version"`
	ServerVersion    string `json:"server_version"`
	ServerAPIVersion string `json:"server_api_version"`
	ServerMinAPI     string `json:"server_min_api_version"`
	ServerOS         string `json:"server_os"`
	ServerArch       string `json:"server_arch"`
	Platform         string `json:"platform"`
	Containers       int    `json:"containers_total"`
	Error            string `json:"error,omitempty"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out := report{
		GoVersion:    runtime.Version(),
		GoOS:         runtime.GOOS,
		GoArch:       runtime.GOARCH,
		ClientMaxAPI: client.MaxAPIVersion,
		ClientMinAPI: client.MinAPIVersion,
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/moby/moby/client" {
				out.ClientModule = dep.Path
				out.ClientModuleVer = dep.Version
			}
		}
	}

	encode := func(err error) int {
		if err != nil {
			out.Error = err.Error()
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		if err != nil {
			return 1
		}
		return 0
	}

	cli, err := client.New(client.FromEnv)
	if err != nil {
		os.Exit(encode(err))
	}
	defer cli.Close()

	ping, err := cli.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	if err != nil {
		os.Exit(encode(err))
	}
	out.PingAPIVersion = ping.APIVersion
	out.NegotiatedAPI = cli.ClientVersion()

	version, err := cli.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		os.Exit(encode(err))
	}
	out.ServerVersion = version.Version
	out.ServerAPIVersion = version.APIVersion
	out.ServerMinAPI = version.MinAPIVersion
	out.ServerOS = version.Os
	out.ServerArch = version.Arch
	out.Platform = version.Platform.Name

	containers, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		os.Exit(encode(err))
	}
	out.Containers = len(containers.Items)

	os.Exit(encode(nil))
}
