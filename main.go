package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/henderiw/kubemon2/lib/logutils"
	"github.com/vishvananda/netlink"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func createDockerBridge() {
	out, err := exec.Command("/usr/bin/echo", "$PATH").Output()
	if err != nil {
		log.Error("%s", err)
	}

	out, err = exec.Command("/usr/bin/docker", "network ls | grep srlinux-mgmt").Output()
	if err != nil {
		log.Error("%s", err)
	}

	log.Info("Command Successfully Executed")
	output := string(out[:])
	log.Info("Output:", output)
}

/*
func createLinuxBridge() {
	// RETRIEVE EXISTING BRIDGE
	//br, err := tenus.BridgeFromName(testNet)
	//if err != nil {
	//	log.Fatal(err)
	//}

	// CREATE BRIDGE AND BRING IT UP
	br, err := tenus.NewBridgeWithName(testNet)
	if err != nil {
		log.Fatal(err)
	}

	brIP, brIPNet, err := net.ParseCIDR(testNetIPv4Subnet)
	if err != nil {
		log.Fatal(err)
	}

	if err := br.SetLinkIp(brIP, brIPNet); err != nil {
		fmt.Println(err)
	}

	brIP, brIPNet, err = net.ParseCIDR(testNetIPv6Subnet)
	if err != nil {
		log.Fatal(err)
	}

	if err := br.SetLinkIp(brIP, brIPNet); err != nil {
		fmt.Println(err)
	}

	if err = br.SetLinkUp(); err != nil {
		fmt.Println(err)
	}
	log.Info("Bridge:", br)
}
*/

func createDockerBridge2() {
	la := netlink.NewLinkAttrs()
	la.Name = testNet
	mybridge := &netlink.Bridge{LinkAttrs: la}
	err := netlink.LinkAdd(mybridge)
	if err != nil {
		log.Info("could not add %s: %v\n", la.Name, err)
	}
	log.Info("Bridge:", mybridge)
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

type device struct {
	Name        string
	Type        string
	Image       string
	Version     string
	Command     string
	Environment struct {
	}
	Pid            string
	Sandbox        string
	DefaultNetwork string
	StartMode      string
	Sysctls        string //  {'net.ipv4.ip_forward': 1}
	EntryCmd       string //'docker exec -it {} sh'.format(self.name)
	Interfaces     map[string]link
	Volumes        struct {
		License         string
		LicenseCmd      string
		Startup         string
		StartupCmd      string
		TopologyYAML    string
		TopologyYAMLCmd string
		EnvConf         string
		EnvConfCmd      string
	}
	Ports struct {
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
	d.Sysctls = `{'net.ipv4.ip_forward': 0,
						'net.ipv6.conf.all.disable_ipv6':0,
						'net.ipv6.conf.all.accept_dad':0,
						'net.ipv6.conf.default.accept_dad':0,
						'net.ipv6.conf.all.autoconf':0,
						'net.ipv6.conf.default.autoconf':0,
   						}`
	d.Command = "sudo /opt/srlinux/bin/sr_linux"
	d.DefaultNetwork = "srlinux-mgmt"
	d.Interfaces = make(map[string]link)
}

func (d *device) getConfig(t string, config topologyConfig) {
	log.Info("Device Get Configuration")
	d.Volumes.License = path.Join(path.Dir(t), configDir+"license.txt")
	d.Volumes.Startup = path.Join(path.Dir(t), configDir+config.Prefix+"nodeName-X")
	d.Volumes.TopologyYAML = path.Join(path.Dir(t), configDir+config.Prefix+"nodeName-X")
	d.Volumes.EnvConf = path.Join(path.Dir(t), configDir+"srlinux.conf")

	d.Volumes.LicenseCmd = `{'bind': '/opt/srlinux/etc/license.key', 'mode': 'ro'}`
	d.Volumes.StartupCmd = `{'bind': '/etc/opt/srlinux/config.json', 'mode': 'rw'}`
	d.Volumes.TopologyYAMLCmd = `{'bind': '/tmp/topology.yml', 'mode': 'ro'}`
	d.Volumes.EnvConfCmd = `{'bind': '/home/admin/.srlinux.conf', 'mode': 'rw'}`

}

func (d *device) connect(intName string, l link) {
	log.Info("Creating a pointer to network '%s' for interface '%s'", l.Name, intName)
	//d.Interfaces = make(map[string]link)
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
const testNet = "srlinux-mgmt2"
const testNetIPv4Subnet = "172.19.19.0/24"
const testNetIPv6Subnet = "2001:172:19:19::1/80"

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
	log.Info("%#v", config)
	log.Info("Version:", config.Version)
	log.Info("Driver:", config.Driver)
	log.Info("Prefix:", config.Prefix)
	log.Info("NodeType:", config.NodeType)
	log.Info("Image:", config.Image)
	log.Info("Base:", config.Base)
	log.Info("Links:", config.Links)

	//srlinux.init(t, config)
	//srlinux.getConfig(t, config)
	//log.Info("SRLINUX:", srlinux)

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
		fmt.Println("Can't Execute this on a windows machine")
	} else {
		createDockerBridge()
	}

	/*
		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}

		containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
		if err != nil {
			panic(err)
		}

		for _, container := range containers {
			fmt.Println(container.ID)
			fmt.Println(container.Names)
			fmt.Println(container.Image)
			fmt.Println(container.ImageID)
			fmt.Println("@@@@@@@@@@@@")
		}
	*/
}
