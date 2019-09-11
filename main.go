package main

import (
	"context"
	"flag"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/henderiw/kubemon2/lib/logutils"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func createDockerBridge() {
	cmd := exec.Command("docker", "network", "ls")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	log.Info("combined out:\n%s\n", string(out))
	if strings.Contains(string(out), "srlinux-mgmt2") == false {
		log.Info("Docker management brdige does not exist, will create one:", testDockerNet)

		cmd := exec.Command("docker", "network", "create", "-d", "bridge", "--subnet", testDockerNetIPv4Subnet, "--ipv6", "--subnet", testDockerNetIPv6Subnet, "--opt", "com.docker.network.bridge.name="+testDockerNet, testDockerNet)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("cmd.Run() failed with %s\n", err)
		}
		log.Info("combined out:\n%s\n", string(out))
	}
}

type topologyConfig struct {
	Version  string `yaml:"version"`
	Driver   string `yaml:"driver"`
	Prefix   string `yaml:"prefix"`
	NodeType string `yaml:"nodetype"`
	Image    string `yaml:"image"`
	Base     int    `yaml:"base"`
	Links    []struct {
		EndPoints []string `yaml:"endpoints"`
	} `yaml:"links"`
}

func (c *topologyConfig) Parse(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}
	//we can add some checks here
	return nil
}

type volume struct {
	source      string
	destination string
	readOnly    bool
}

type device struct {
	Name           string
	Type           string
	Image          string
	Version        string
	Command        string
	Environment    []string
	Pid            string
	Sandbox        string
	DefaultNetwork string
	StartMode      string
	Sysctls        map[string]string //  {'net.ipv4.ip_forward': 1}
	EntryCmd       string            //'docker exec -it {} sh'.format(self.name)
	Interfaces     map[string]link
	Volumes        map[string]volume
	Labels         map[string]string
	Ports          struct {
	}
	Container string
	User      string
	Detach    bool // true
}

func (d *device) init(name, t string, config topologyConfig) {
	log.Info("Device Initialization")
	// SRLINUX defaults
	d.Name = config.Prefix + "_" + name
	d.Type = "srlinux"
	d.Image = config.Image
	v := strings.Split(config.Image, ":")
	d.Version = v[1]
	d.User = "root"
	d.Detach = false
	d.Sysctls = make(map[string]string)
	d.Sysctls["net.ipv4.ip_forward"] = "0"
	d.Sysctls["net.ipv6.conf.all.disable_ipv6"] = "0"
	d.Sysctls["net.ipv6.conf.all.accept_dad"] = "0"
	d.Sysctls["net.ipv6.conf.default.accept_dad"] = "0"
	d.Sysctls["net.ipv6.conf.all.autoconf"] = "0"
	d.Sysctls["net.ipv6.conf.default.autoconf"] = "0"
	d.Command = "sudo /opt/srlinux/bin/sr_linux"
	d.DefaultNetwork = testDockerNet
	d.Environment = []string{"SRLINUX=1"}
	d.EntryCmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@$(docker inspect {} --format '.format(self.name) + '\"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}\")"
	// Setting up extra variables
	d.Interfaces = make(map[string]link)
	d.Volumes = make(map[string]volume)
	d.Labels = make(map[string]string)
	d.Labels[config.Prefix] = d.Name
	// Pointer to docker SDK object
	d.Container = ""
	d.User = ""
	d.Detach = true

	d.getConfig(t, config)

}

func (d *device) getConfig(t string, config topologyConfig) {
	log.Info("Device Get Configuration")
	license := path.Join(path.Dir(t), configDir+"license.txt")
	startup := path.Join(path.Dir(t), configDir+config.Prefix+"nodeName-X")
	topologyYAML := path.Join(path.Dir(t), configDir+config.Prefix+"nodeName-X")
	envConf := path.Join(path.Dir(t), configDir+"srlinux.conf")
	log.Info(path.IsAbs(license))
	log.Info(path.IsAbs(startup))
	log.Info(path.IsAbs(topologyYAML))
	log.Info(path.IsAbs(envConf))

	var v volume
	v.source = license
	v.destination = "/opt/srlinux/etc/license.key"
	v.readOnly = true
	d.Volumes["license"] = v
	v.source = startup
	v.destination = "/etc/opt/srlinux/config.json"
	v.readOnly = false
	d.Volumes["startup"] = v
	v.source = topologyYAML
	v.destination = "/tmp/topology.yml"
	v.readOnly = true
	d.Volumes["topologyYAML"] = v
	v.source = envConf
	v.destination = "/home/admin/.srlinux.conf"
	v.readOnly = false
	d.Volumes["envConf"] = v

}

func (d *device) connect(intName string, l link) {
	log.Info("Creating a pointer to network '%s' for interface '%s'", l.Name, intName)
	d.Interfaces[intName] = l
	//log.Info("Interfaces:", d.Interfaces)

	d.updateStartMode(intName, l)
}

func (d *device) updateStartMode(intName string, link link) {
	var newStartMode string
	if link.Driver == "veth" {
		newStartMode = "manual"
	} else {
		newStartMode = "auto"
	}
	log.Info("Updating start_mode from '%s' to '%s'", d.StartMode, newStartMode)
	d.StartMode = newStartMode

}

func (d *device) getOrCreate() {

}

func (d *device) update() {

}

func (d *device) create() {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error(err)
	}
	/*
		reader, err := cli.ImagePull(ctx, "docker.io/library/alpine", types.ImagePullOptions{})
		if err != nil {
			log.Error(err)
		}
		io.Copy(os.Stdout, reader)
	*/

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:    d.Image,
		Cmd:      strings.Fields(d.Container),
		Env:      d.Environment,
		Hostname: d.Name,
		Tty:      true,
		User:     d.User,
		Labels:   d.Labels,
	}, &container.HostConfig{

		Sysctls:    d.Sysctls,
		Privileged: true,
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   d.Volumes["license"].source,
				Target:   d.Volumes["license"].destination,
				ReadOnly: d.Volumes["license"].readOnly,
			},
			{
				Type:     mount.TypeBind,
				Source:   d.Volumes["startup"].source,
				Target:   d.Volumes["startup"].destination,
				ReadOnly: d.Volumes["startup"].readOnly,
			},
			{
				Type:     mount.TypeBind,
				Source:   d.Volumes["topologyYAML"].source,
				Target:   d.Volumes["topologyYAML"].destination,
				ReadOnly: d.Volumes["topologyYAML"].readOnly,
			},
			{
				Type:     mount.TypeBind,
				Source:   d.Volumes["envConf"].source,
				Target:   d.Volumes["envConf"].destination,
				ReadOnly: d.Volumes["envConf"].readOnly,
			},
		},
	}, nil, "")
	if err != nil {
		log.Error(err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		log.Error(err)
	}

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			log.Error(err)
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		log.Error(err)
	}

	stdcopy.StdCopy(os.Stdout, os.Stderr, out)
}

func (d *device) get() {

}

func (d *device) start() {
	if d.Container == "" {
		d.getOrCreate()
	}
}

func (d *device) attach() {

}

func (d *device) kill() {

}

type link struct {
	Name     string
	LinkType string
	Network  string
	Opts     string
	Driver   string
}

func (l *link) init(linkType, name, driver string, config topologyConfig) {
	log.Info("Initializing a '%s' link with name '%s' and driver '%s': ", linkType, name, driver)
	l.Name = config.Prefix + "_" + name
	l.LinkType = linkType
	l.Network = ""
	l.Opts = ""
	l.Driver = driver

	l.getOrCreate()

}

func (l *link) getOrCreate() {
	log.Info("Obtaining a pointer to network: ", l.Name)
	l.Network = l.get()
}

func (l *link) get() (network string) {
	log.Info("Trying to find an existing network with name:", l.Name)
	var veth veth
	return veth.init(l.Name)

}

type veth struct {
	Name  string
	sideA string
	sideB string
}

func (v *veth) init(name string) (network string) {
	log.Info("Initializing a veth pair: ", name)
	v.Name = name
	v.sideA = name + "-a"
	v.sideB = name + "-b"

	return network

}

func parseEndpoints(endpoints []string, link link, config topologyConfig) {
	for _, endpoint := range endpoints {
		log.Info("Parsing Endpoints:  ", endpoint)
		var device device
		ep := strings.Split(endpoint, ":")
		//log.Info("EP:  ", ep)
		deviceName := ep[0]
		//log.Info("DEVICE NAME:  ", deviceName)
		intName := ep[1]
		//log.Info("INTERFACE NAME:  ", intName)

		found := false
		//log.Info("parseEndpoints Devices before for loop with found :", devices)
		for _, d := range devices {
			//log.Info("parseEndpoints Device in for loop", d)
			dn := config.Prefix + "_" + deviceName
			if d.Name == dn {
				found = true
				device = d
				break
			}
		}
		//log.Info("FOUND:", found)
		if found == false {
			device.init(deviceName, t, config)
			//log.Info("parseEndpoints Device init:", device)
		}

		device.connect(intName, link)
		//log.Info("parseEndpoints Device connect:", device)

		if found == false {
			devices = append(devices, device)
		}

		//log.Info("parseEndpoints Devices :", devices)
	}
}

func parseTopology(t string, config topologyConfig) {
	for idx, endpoint := range config.Links {
		log.Info("Parsing Link:  ", endpoint)
		linkDriver := config.Driver
		if endpoint.EndPoints[0] == "" {
			log.Error("Missing endpoints definition")
		} else {
			log.Info("Parsing Endpoints: ", endpoint.EndPoints)
		}
		var linkType string
		if len(endpoint.EndPoints) <= 2 {
			linkType = "p2p"
		} else {
			linkType = "mpoint"
		}
		//log.Info("Parsing Endpoint 0:", endpoint.EndPoints[0])
		//log.Info("Parsing Endpoint 1:", endpoint.EndPoints[1])
		//log.Info("Linkdriver:", linkDriver)
		//log.Info("linkType:", linkType)

		var link link
		link.init(linkType, "net-"+strconv.Itoa(idx), linkDriver, config)
		links = append(links, link)
		//log.Info("Links", links)
		parseEndpoints(endpoint.EndPoints, link, config)

	}
}

func parseArgs() (operation, topology string) {
	flag.StringVar(&topology, "t", "/Users/henderiw/go/src/github.com/henderiw/dockertopo/3-node.yaml", "topology file")
	flag.StringVar(&operation, "o", "create", "Operation: create or destroy")

	flag.Parse()
	return
}

var config topologyConfig
var t string
var links []link
var devices []device

const configDir = "./config/"
const testDockerNet = "srlinux-mgmt2"
const testDockerNetIPv4Subnet = "172.19.19.0/24"
const testDockerNetIPv6Subnet = "2001:172:19:19::1/80"

func main() {
	// Configure log formatting.
	log.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	log.AddHook(&logutils.ContextHook{})
	// Parse arguments
	o, t := parseArgs()

	log.Info("Operation: '%s' ", o)
	log.Info("Topology file: '%s' ", t)

	data, err := ioutil.ReadFile(t)
	if err != nil {
		log.Fatal(err)
	}
	if err := config.Parse(data); err != nil {
		log.Fatal(err)
	}

	parseTopology(t, config)

	//log.Info("Devices:", devices)
	for i, device := range devices {
		log.Info("/n########## Device ############/n")
		log.Info("Device:", i, device)
		log.Info("/n########## Device ############/n")
	}
	//log.Info("Links:", links)
	for i, link := range links {
		log.Info("/n########## Link ############/n")
		log.Info("Link:", i, link)
		log.Info("/n########## Link ############/n")
	}

	if runtime.GOOS == "windows" {
		log.Error("Can't Execute this on a windows machine")
	} else {
		createDockerBridge()
	}

	for _, device := range devices {
		device.create()
	}

}
