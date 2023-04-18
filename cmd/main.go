package main

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/Ullaakut/nmap/v3"
	"github.com/gofiber/fiber/v2"
)

type PortScanRequest struct {
	HostName []string `json:"hostname"`
}

type Result struct {
	HostName  string  `json:"hostname"`
	ListPorts []Ports `json:"Ports"`
}

type Ports struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`

	Service    string `xml:"service" json:"service"`
	State      string `xml:"state" json:"state"`
	LastStatus string `xml:"lastStatus" json:"lastStatus"`
}

func startPortScan(c *fiber.Ctx) error {

	var data = new(PortScanRequest)
	err := c.BodyParser(data)
	if err != nil {
		c.Status(400).JSON(&fiber.Map{
			"success": false,
			"message": err,
			"data":    nil,
		})
		return err
	}

	r, _ := nmapProcessor(data.HostName)

	c.Status(200).JSON(&fiber.Map{
		"success": true,
		"message": "",
		"data":    r,
	})

	return nil
}

func nmapProcessor(input []string) ([]Result, error) {
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5-minute timeout.
	s, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets(input...),
		nmap.WithPorts("80,443,843"),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	// Executes asynchronously, allowing results to be streamed in real time.
	done := make(chan error)
	result, warnings, err := s.Async(done).Run()
	if err != nil {
		log.Fatal(err)
	}

	// Blocks main until the scan has completed.
	if err := <-done; err != nil {
		if len(*warnings) > 0 {
			log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
		}
		log.Fatal(err)
	}
	var res []Result

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		var r Result
		fmt.Printf("Host %q:\n", host.Addresses[0])

		r.HostName = host.Addresses[0].Addr

		for _, port := range host.Ports {
			var p Ports
			p.ID = strconv.FormatUint(uint64(port.ID), 10)
			p.Protocol = port.Protocol
			p.State = port.State.String()
			p.Service = port.Service.Name
			r.ListPorts = append(r.ListPorts, p)

			//fmt.Printf("\tPort %d/%s %s %s\n", p.ID, r.Protocol, r.State, r.Service)
		}
		res = append(res, r)
	}

	return res, nil
}

func setupRoutes(app *fiber.App) {
	app.Get("/", startPortScan)

	app.Post("/api/v1/scan", startPortScan)

}

func main() {
	app := fiber.New()

	setupRoutes(app)
	app.Listen(":3000")
}
