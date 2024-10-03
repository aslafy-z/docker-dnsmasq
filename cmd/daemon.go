// Copyright © 2016 defektive <sirbradleyd@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
)

var (
	docker            *client.Client
	updated           = true
	dockerSocketPath  string
	dnsmasqConfigPath string
	dnsmasqRestartCmd string
	domainSuffix      string
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Update dnsmasq config when containers start and stop.",
	Long: `Listen to docker events. Add/remove dnsmasq entries when containers
	start or stop. Then restart dnsmasq.`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		// Initialize Docker client
		cli, err := client.NewClientWithOpts(
			client.WithHost(dockerSocketPath),
			client.WithAPIVersionNegotiation(),
		)
		if err != nil {
			log.Fatalf("Failed to create Docker client: %v", err)
		}
		docker = cli
		defer docker.Close()

		updateDNSMasq(ctx)

		// Start event monitoring
		eventChan, errChan := docker.Events(ctx, events.ListOptions{})
		go func() {
			for {
				select {
				case event := <-eventChan:
					if event.Type == "container" {
						if event.Action == "start" || event.Action == "die" {
							updated = true
						}
					}
				case err := <-errChan:
					log.Printf("Error receiving Docker events: %v", err)
				}
			}
		}()

		// Periodic update check
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		go func() {
			for {
				select {
				case <-ticker.C:
					if updated {
						updateDNSMasq(ctx)
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		waitForInterrupt()
	},
}

func init() {
	RootCmd.AddCommand(daemonCmd)
	daemonCmd.PersistentFlags().StringVarP(&dockerSocketPath, "docker-socket", "d", "unix:///var/run/docker.sock", "path to docker socket")
	daemonCmd.PersistentFlags().StringVarP(&dnsmasqConfigPath, "dnsmasq-config", "c", "/etc/dnsmasq.d/docker.conf", "path to dnsmasq config file")
	daemonCmd.PersistentFlags().StringVarP(&dnsmasqRestartCmd, "daemon-restart", "r", "systemctl restart dnsmasq", "command to restart dnsmasq")
	daemonCmd.PersistentFlags().StringVarP(&domainSuffix, "domain-suffix", "s", ".docker", "domain suffix")
}

func updateDNSMasq(ctx context.Context) {
	containers, err := docker.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Printf("Failed to list containers: %v", err)
		return
	}

	f, err := os.OpenFile(dnsmasqConfigPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Failed to open dnsmasq config: %v", err)
		return
	}
	defer f.Close()

	for _, c := range containers {
		config := dnsmasqConfig(ctx, c)
		if config != "" {
			if _, err := f.WriteString(config); err != nil {
				log.Printf("Failed to write config: %v", err)
			}
		}
	}

	restartDNS()
}

func containerDomain(ctx context.Context, container types.Container) string {
	inspect, err := docker.ContainerInspect(ctx, container.ID)
	if err != nil {
		log.Printf("Failed to inspect container: %v", err)
		return ""
	}

	return strings.TrimPrefix(inspect.Name, "/") + domainSuffix
}

func containerIP(container types.Container) string {
	for _, network := range container.NetworkSettings.Networks {
		return network.IPAddress
	}
	return ""
}

func dnsmasqConfig(ctx context.Context, container types.Container) string {
	ip := containerIP(container)
	domain := containerDomain(ctx, container)

	if ip != "" && domain != "" {
		return fmt.Sprintf("address=/%s/%s\n", domain, ip)
	}
	return ""
}

func restartDNS() {
	cmd := exec.Command("/bin/sh", "-c", dnsmasqRestartCmd)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to restart DNSMasq: %v", err)
		return
	}
	log.Println("Restarted DNSMasq")
	updated = false
}

func waitForInterrupt() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	<-sigChan
}
