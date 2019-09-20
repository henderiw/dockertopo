package main

import (
	"context"
	"flag"
	"io/ioutil"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
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
	if strings.Contains(string(out), testDockerNet) == false {
		log.Info("Docker management brdige does not exist, will create one:", testDockerNet)

		cmd := exec.Command("docker", "network", "create", "-d", "bridge", "--subnet", testDockerNetIPv4Subnet, "--ipv6", "--subnet", testDockerNetIPv6Subnet, "--opt", "com.docker.network.bridge.name="+testDockerNet, testDockerNet)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("cmd.Run() failed with %s\n", err)
		}
		log.Info("combined out:\n%s\n", string(out))
	}
}

func deleteDockerBridge() {
	cmd := exec.Command("docker", "network", "ls")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	log.Info("combined out:\n%s\n", string(out))
	if strings.Contains(string(out), testDockerNet) == false {
		log.Info("Docker management brdige does not exist, will create one:", testDockerNet)

		cmd := exec.Command("docker", "network", "rm", testDockerNet)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("cmd.Run() failed with %s\n", err)
		}
		log.Info("combined out:\n%s\n", string(out))
	}
}

func disableCheckSumoffload(bridge string) {
	log.Info("Disable checksum offload on bridge: %s", bridge)
	cmd := exec.Command("ethtool", "--offload", bridge, "rx", "off", "tx", "off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	log.Info("combined out:\n%s\n", string(out))
}

func disableRPFCheck() {
	log.Info("Disable RPF check on host")
	cmd := exec.Command("echo", "0", ">", "/proc/sys/net/ipv4/conf/default/rp_filter")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	log.Info("combined out:\n%s\n", string(out))
	cmd = exec.Command("echo", "0", ">", "/proc/sys/net/ipv4/conf/all/rp_filter")
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	log.Info("combined out:\n%s\n", string(out))
}

func enableLLDP() {
	log.Info("Enable LLDP")

}

func getContainerPid(containerID string) string {
	log.Info("getting container PID: ", containerID)
	cmd := exec.Command("docker", "inspect", "--format", `'{{.State.Pid}}'`, containerID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	log.Info("combined out: \n", string(out))
	return string(out)
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
	Mounts         map[string]volume
	Volumes        map[string]struct{}
	Binds          []string
	Labels         map[string]string
	Ports          struct {
	}
	Container       string
	ContainerStatus string
	User            string
	Detach          bool // true
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
	d.Mounts = make(map[string]volume)
	d.Volumes = make(map[string]struct{})
	d.Binds = make([]string, 5)
	d.Labels = make(map[string]string)
	d.Labels[config.Prefix] = d.Name
	// Pointer to docker SDK object
	d.Container = ""
	d.ContainerStatus = ""

	d.getConfig(t, config)

}

func (d *device) getConfig(t string, config topologyConfig) {
	log.Info("Device Get Configuration")
	license := path.Join(path.Dir(t), configDir+"license.txt")
	startup := path.Join(path.Dir(t), configDir+d.Name)
	topologyYAML := path.Join(path.Dir(t), configDir+d.Name+"_card_info.yml")
	envConf := path.Join(path.Dir(t), configDir+"srlinux.conf")
	checkPoint := path.Join(path.Dir(t), configDir+configJSONDir+d.Name)

	license, err := filepath.Abs(license)
	if err == nil {
		log.Info("Absolute license path:", license)
	}
	startup, err = filepath.Abs(startup)
	if err == nil {
		log.Info("Absolute startup path:", startup)
	}
	topologyYAML, err = filepath.Abs(topologyYAML)
	if err == nil {
		log.Info("Absolute topologyYAML path:", topologyYAML)
	}
	envConf, err = filepath.Abs(envConf)
	if err == nil {
		log.Info("Absolute envConf path:", envConf)
	}
	checkPoint, err = filepath.Abs(checkPoint)
	if err == nil {
		log.Info("Absolute checkPoint path:", checkPoint)
	}
	log.Info(path.IsAbs(license))
	log.Info(path.IsAbs(startup))
	log.Info(path.IsAbs(topologyYAML))
	log.Info(path.IsAbs(envConf))
	log.Info(path.IsAbs(checkPoint))

	var v volume
	v.source = license
	v.destination = "/opt/srlinux/etc/license.key"
	v.readOnly = true
	d.Mounts["license"] = v
	v.source = startup
	v.destination = "/etc/opt/srlinux/config.json"
	v.readOnly = false
	d.Mounts["startup"] = v
	v.source = topologyYAML
	v.destination = "/tmp/topology.yml"
	v.readOnly = true
	d.Mounts["topologyYAML"] = v
	v.source = envConf
	v.destination = "/home/admin/.srlinux.conf"
	v.readOnly = false
	d.Mounts["envConf"] = v
	v.source = checkPoint
	v.destination = "/etc/opt/srlinux/checkpoint/"
	v.readOnly = false
	d.Mounts["checkPoint"] = v

	d.Volumes = map[string]struct{}{
		d.Mounts["license"].destination:      struct{}{},
		d.Mounts["startup"].destination:      struct{}{},
		d.Mounts["topologyYAML"].destination: struct{}{},
		d.Mounts["envConf"].destination:      struct{}{},
		d.Mounts["checkPoint"].destination:   struct{}{},
	}

	bindLicense := d.Mounts["license"].source + ":" + d.Mounts["license"].destination + ":" + "ro"
	bindStartup := d.Mounts["startup"].source + ":" + d.Mounts["startup"].destination + ":" + "rw"
	bindTopologyYAML := d.Mounts["topologyYAML"].source + ":" + d.Mounts["topologyYAML"].destination + ":" + "ro"
	bindEnvConf := d.Mounts["envConf"].source + ":" + d.Mounts["envConf"].destination + ":" + "rw"
	bindCheckPoint := d.Mounts["checkPoint"].source + ":" + d.Mounts["checkPoint"].destination + ":" + "rw"

	d.Binds = []string{bindLicense, bindStartup, bindTopologyYAML, bindEnvConf, bindCheckPoint}

}

func (d *device) connect(intName string, l link) {
	log.Info("Creating a pointer to network '%s' for interface '%s'", l.Name, intName)
	d.Interfaces[intName] = l
	//log.Info("Interfaces:", d.Interfaces)

	d.updateStartMode(intName, l)
}

func (d *device) attach() {
	for name, link := range d.Interfaces {
		log.Info("Attaching container {} interface {} to its link: ", name, link)
	}
}

func (d *device) updateStartMode(intName string, link link) {
	log.Info("Update start Mode with driver: ", link.Driver)
	var newStartMode string
	if link.Driver == "veth" {
		newStartMode = "manual"
	} else {
		newStartMode = "auto"
	}
	log.Info("Updating start_mode from '%s' to '%s'", d.StartMode, newStartMode)
	d.StartMode = newStartMode

}

func (d *device) getOrCreate(o string) {
	log.Info("Obtaining a pointer to container: ", d.Name)
	d.Container, d.ContainerStatus = d.get(o)
	log.Info("Container info after get procedure:", d.Container)
	if d.Container == "" {
		log.Info("Container info after get procedure:", d.Container)
		d.create()
		d.Container, d.ContainerStatus = d.get(o)
	}

}

func (d *device) get(o string) (string, string) {
	log.Info("Get device")
	log.Info("Container Name:", d.Name)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	var containers []types.Container

	if o == "create" || o == "update" {
		// list create containers
		containers, err = cli.ContainerList(ctx, types.ContainerListOptions{
			All: true,
		})
	} else {
		// list running containers
		containers, err = cli.ContainerList(ctx, types.ContainerListOptions{})
	}
	if err != nil {
		panic(err)
	}

	for _, container := range containers {
		log.Info("Containers :", container.ID, container.Names, container.Labels)
		log.Info("Container Name from docker api: ", container.Names[0])
		log.Info("Container Name from device config: ", d.Name)

		if container.Names[0] == "/"+d.Name {
			log.Info("Container is already created or running: ", container.ID)
			log.Info("Container status: ", container.Status)
			return container.ID, container.Status
		}
	}
	return "", ""

}

func (d *device) update() {
	log.Info("Update device information")
	d.Container, d.ContainerStatus = d.get("update")
}

func (d *device) create() {
	log.Info("Container create")
	log.Info("Container Name:", d.Name)
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
		Image:        d.Image,
		Cmd:          strings.Fields(d.Command),
		Env:          d.Environment,
		AttachStdout: true,
		AttachStderr: true,
		Hostname:     d.Name,
		Volumes:      d.Volumes,
		Tty:          true,
		User:         d.User,
		Labels:       d.Labels,
	}, &container.HostConfig{
		Binds:       d.Binds,
		Sysctls:     d.Sysctls,
		Privileged:  true,
		NetworkMode: container.NetworkMode(d.DefaultNetwork),
		/*
			Mounts: []mount.Mount{
				{
					Type:     mount.TypeBind,
					Source:   d.Mounts["license"].source,
					Target:   d.Mounts["license"].destination,
					ReadOnly: d.Mounts["license"].readOnly,
				},
				{
					Type:     mount.TypeBind,
					Source:   d.Mounts["startup"].source,
					Target:   d.Mounts["startup"].destination,
					ReadOnly: d.Mounts["startup"].readOnly,
				},
				{
					Type:     mount.TypeBind,
					Source:   d.Mounts["topologyYAML"].source,
					Target:   d.Mounts["topologyYAML"].destination,
					ReadOnly: d.Mounts["topologyYAML"].readOnly,
				},
				{
					Type:     mount.TypeBind,
					Source:   d.Mounts["envConf"].source,
					Target:   d.Mounts["envConf"].destination,
					ReadOnly: d.Mounts["envConf"].readOnly,
				},
				{
					Type:     mount.TypeBind,
					Source:   d.Mounts["checkPoint"].source,
					Target:   d.Mounts["checkPoint"].destination,
					ReadOnly: d.Mounts["checkPoint"].readOnly,
				},
			},
		*/
	}, nil, d.Name)
	if err != nil {
		log.Error(err)
	}

	log.Info("Container Create Response: %#v", resp)
	//return resp.ID

	/*
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
	*/
}

func (d *device) containerStart() {
	log.Info("Container Start")
	log.Info("Container Name:", d.Name)
	log.Info("Container ID:", d.Container)

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error(err)
	}

	err = cli.ContainerStart(ctx, d.Container, types.ContainerStartOptions{})
	if err != nil {
		log.Error(err)
	}
}

func (d *device) containerStop() {
	log.Info("Container Stop")
	log.Info("Container Name:", d.Name)

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error(err)
	}

	err = cli.ContainerStop(ctx, d.Container, nil)
	if err != nil {
		log.Error(err)
	}
}

func (d *device) containerDestroy() {
	log.Info("Container Destroy")
	log.Info("Container Name:", d.Name)

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error(err)
	}

	err = cli.ContainerRemove(ctx, d.Container, types.ContainerRemoveOptions{})
	if err != nil {
		log.Error(err)
	}
}

func (d *device) containerPause() {
	log.Info("Container Pause")
	log.Info("Container Name:", d.Name)

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error(err)
	}

	err = cli.ContainerPause(ctx, d.Container)
	if err != nil {
		log.Error(err)
	}
}

func (d *device) containerUnpause() {
	log.Info("Container Unpause")
	log.Info("Container Name:", d.Name)

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error(err)
	}

	err = cli.ContainerUnpause(ctx, d.Container)
	if err != nil {
		log.Error(err)
	}
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if c := s[len(s)-1]; s[0] == c && (c == '"' || c == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func (d *device) start() {
	log.Info("Device Start")
	log.Info("Device Container: ", d.Container)
	if d.Container == "" {
		d.getOrCreate("create")
	}
	if d.ContainerStatus == "running" {
		log.Info("Container %s already running", d.Name)
	}

	if d.StartMode == "manual" {
		log.Info("Container %s to be started", d.Name)
		d.containerStart()
		d.Pid = getContainerPid(d.Container)
		log.Info("Container PID: ", d.Pid)
		//d.Pid, _ = strconv.Unquote(d.Pid)
		//d.Pid = trimQuotes(d.Pid)
		d.Pid = strings.TrimSuffix(d.Pid, `'`)
		d.Pid = strings.TrimPrefix(d.Pid, `'`)
		for i := 1; i < len(d.Pid); i++ {
			log.Info("Container PID: ", d.Pid[i])
		}
		log.Info("Container PID after quote trim: ", d.Pid)
	} else {
		log.Info("Unsupported container start mode %s", d.StartMode)
	}
	d.update()
	d.containerPause()
	d.attach()
	d.containerUnpause()

}

func (d *device) destroy() {
	log.Info("Device Destroy with destroying the container")
	log.Info("Device Container: ", d.Container)
	if d.Container == "" {
		d.getOrCreate("destroy")
	} else {
		log.Info("Destroying exisitng container: ", d.Container)
	}
	d.containerStop()
	d.containerDestroy()
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
const configJSONDir = "json_config/"
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
		panic("can't run on windows")
	}

	switch o {
	case "create":
		log.Println("create Workflow")
		createDockerBridge()

		for _, device := range devices {
			device.start()
		}

		//disable chacksum offload on docker0, sr-linux bridge
		disableCheckSumoffload(testDockerNet)

		//enable LLDP

		//disable rpk check
		disableRPFCheck()

		break
	case "destroy":
		log.Println("destroy Workflow")
		for _, device := range devices {
			device.destroy()
		}

		deleteDockerBridge()
		break

	default:
		log.Fatalln("Wrong Operation Input (create or destroy)")

	}

}
