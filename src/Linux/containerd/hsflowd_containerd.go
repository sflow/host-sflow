/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"math/rand"
	"os"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"
)

import (
	v1 "github.com/containerd/cgroups/stats/v1"
	v2 "github.com/containerd/cgroups/v2/stats"
	"github.com/containerd/containerd"
	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/namespaces"
	_ "github.com/containerd/containerd/runtime"
	"github.com/containerd/typeurl"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type VirDomainState uint32

const (
	vir_noState VirDomainState = iota
	vir_running
	vir_blocked
	vir_paused
	vir_shutdown
	vir_shutoff
	vir_crashed
)

func stateForStatus(status containerd.Status) VirDomainState {
	switch {
	case status.Status == containerd.Running:
		return vir_running
	case status.Status == containerd.Created:
		return vir_paused
	case status.Status == containerd.Stopped:
		return vir_shutoff
	case status.Status == containerd.Paused:
		return vir_paused
	case status.Status == containerd.Pausing:
		return vir_paused
	case status.Status == containerd.Unknown:
		return vir_noState
	default:
		return vir_noState
	}
}

type SFlowContainer struct {
	Namespace        string
	Id               string
	Env              []string
	Pid              uint32
	metricsCountdown int
	mark             bool
	pollNow          bool
	Metrics          struct {
		Names struct {
			Image            string
			Hostname         string
			ContainerName    string
			ContainerType    string
			SandboxName      string
			SandboxNamespace string
			ImageName        string
			CgroupsPath      string
		}
		Cpu struct {
			VirDomainState uint32
			CpuTime        uint32
			CpuCount       uint32
		}
		Mem struct {
			Memory    uint64
			MaxMemory uint64
		}
		Dsk struct {
			Capacity   uint64
			Allocation uint64
			Avalilable uint64
			Rd_req     uint32
			Rd_bytes   uint64
			Wr_req     uint32
			Wr_bytes   uint64
			Errs       uint32
		}
		Nio struct {
			Bytes_in  uint64
			Pkts_in   uint32
			Errs_in   uint32
			Drops_in  uint32
			Bytes_out uint64
			Pkts_out  uint32
			Errs_out  uint32
			Drops_out uint32
		}
	}
}

type CMonitor struct {
	sfcontainers map[string]*SFlowContainer
	polling      int
	dbg          int
	dbgLogger    *log.Logger
	dataLogger   *log.Logger
}

func main() {
	memprofile := flag.String("memprofile", "", "write memory profile to this file")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	debugLevel := flag.Int("debugLevel", 0, "set debug level")
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	cm := CMonitor{
		sfcontainers: make(map[string]*SFlowContainer),
		polling:      30,
		dbg:          *debugLevel,
		dbgLogger:    log.New(os.Stdout, "debug>", log.Ldate|log.Ltime|log.Lshortfile),
		dataLogger:   log.New(os.Stdout, "data>", 0),
	}

	if err := cm.readConfig("/etc/hsflowd.auto"); err != nil {
		cm.fatal(err)
	}
	if err := cm.monitorContainers(context.Background()); err != nil {
		cm.fatal(err)
	}

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			cm.fatal(err)
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			println("writeHeapProfile error: ", err)
			cm.fatal(err)
		}
		f.Close()
		return
	}
}

func (cm CMonitor) log(level int, v ...interface{}) {
	if cm.dbg >= level {
		cm.dbgLogger.Println(v)
	}
}

func (cm CMonitor) fatal(err error) {
	debug.PrintStack()
	cm.dbgLogger.Fatal(err)
}

func (cm CMonitor) dataLog(msg string) {
	cm.dataLogger.Println(msg)
}
func (cm *CMonitor) readConfig(path string) error {
	auto, err := os.Open(path)
	if err != nil {
		cm.log(0, err)
		return err
	}
	defer auto.Close()
	scanner := bufio.NewScanner(auto)
	for scanner.Scan() {
		toks := strings.SplitN(scanner.Text(), "=", 2)
		if len(toks) == 2 {
			autovar := strings.TrimSpace(toks[0])
			autoval := strings.TrimSpace(toks[1])
			//cm.log(0, "path=", path, "var=", autovar, "val=", autoval)
			switch {
			case autovar == "polling":
				cm.polling, err = strconv.Atoi(autoval)
			}
		}
	}
	return err
}

func (cm CMonitor) sFlowContainerKey(nsname string, cont containerd.Container) string {
	return nsname + "." + cont.ID()
}

func (cm CMonitor) loadContainer(nsctx context.Context, nsname string, cont containerd.Container) error {
	info, err := cont.Info(nsctx, containerd.WithoutRefreshedMetadata)
	if err != nil {
		return err
	}

	tsk, err := cont.Task(nsctx, nil)
	// TODO: should be able to do something like this to get the namespace from the context
	// nsname := nsctx.Value(namespaces.TTRPCHeader).(string)
	if err == nil {
		cm.log(1, "container namespace=", nsname, " ID = ", cont.ID(), " image = ", info.Image)
		key := cm.sFlowContainerKey(nsname, cont)
		sfc, ok := cm.sfcontainers[key]
		if ok {
			sfc.mark = false
		} else {
			sfc = &SFlowContainer{
				Namespace:        nsname,
				Id:               cont.ID(),
				Pid:              tsk.Pid(),
				metricsCountdown: 1 + rand.Intn(cm.polling),
				pollNow:          true,
				mark:             false,
			}
			cm.sfcontainers[key] = sfc
		}
		// We can ask for status and it will go and get it from the task.Process object:
		tstatus, err := tsk.Status(nsctx)
		cm.log(2, "task status = ", tstatus)
		// info has stuff like env, mountpoints and capabilities
		// (might need it for, e.g. NVIDIA GPU assignments)
		v, err := typeurl.UnmarshalAny(info.Spec)
		if err != nil {
			return err
		}
		sfc.Metrics.Names.Image = info.Image
		switch v.(type) {
		case *specs.Spec:
			sp := v.(*specs.Spec)
			sfc.Metrics.Names.Hostname = sp.Hostname
			sfc.Metrics.Names.CgroupsPath = sp.Linux.CgroupsPath
			sfc.Metrics.Names.ContainerName = sp.Annotations["io.kubernetes.cri.container-name"]
			sfc.Metrics.Names.ContainerType = sp.Annotations["io.kubernetes.cri.container-type"]
			sfc.Metrics.Names.SandboxName = sp.Annotations["io.kubernetes.cri.sandbox-name"]
			sfc.Metrics.Names.SandboxNamespace = sp.Annotations["io.kubernetes.cri.sandbox-namespace"]
			sfc.Metrics.Names.ImageName = sp.Annotations["io.kubernetes.cri.image-name"]
			sfc.Env = sp.Process.Env
		}

		if cm.dbg >= 2 {
			mjson, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return err
			}
			cm.log(0, string(mjson))
		}
	}

	return nil
}

func (cm CMonitor) loadContainers(ctx context.Context, client *containerd.Client) error {
	cm.log(0, "loadContainers() sfcontainers size=", len(cm.sfcontainers))
	nsclient := client.NamespaceService()
	nslist, err := nsclient.List(ctx)
	if err != nil {
		return err
	}

	for _, sft := range cm.sfcontainers {
		sft.mark = true
	}

	for _, nsname := range nslist {
		nsctx := namespaces.WithNamespace(ctx, nsname)

		containers, err := client.Containers(nsctx)
		if err != nil {
			return err
		}
		for _, cont := range containers {
			err := cm.loadContainer(nsctx, nsname, cont)
			if err != nil {
				return err
			}
		}
	}
	for k, sft := range cm.sfcontainers {
		if sft.mark {
			// TODO: announce? Maybe we missed an event?
			cm.log(1, "delete task on mark and sweep: ", k)
			delete(cm.sfcontainers, k)
		}
	}
	return nil
}

func (cm CMonitor) pollMetrics(ctx context.Context, client *containerd.Client, sfc *SFlowContainer) error {
	cm.log(1, "pollmetrics: ", sfc.Id)
	myctx := namespaces.WithNamespace(ctx, sfc.Namespace)
	container, err := client.LoadContainer(myctx, sfc.Id)
	if err != nil {
		return err
	}
	task, err := container.Task(myctx, nil)
	if err != nil {
		return err
	}
	status, err := task.Status(myctx)
	if err != nil {
		return err
	}
	sfc.Metrics.Cpu.VirDomainState = uint32(stateForStatus(status))

	metrics, err := task.Metrics(myctx)
	if err != nil {
		return err
	}
	mdata, err := typeurl.UnmarshalAny(metrics.Data)
	if err != nil {
		return err
	}

	var data *v1.Metrics
	var data2 *v2.Metrics

	switch v := mdata.(type) {
	case *v1.Metrics:
		data = v
		cm.log(1, data)
		// extract metrics into export struct
		sfc.Metrics.Cpu.CpuCount = uint32(len(data.CPU.Usage.PerCPU))
		// cpu units are in nS - see github containerd/metrics/cgrops/v1
		// hsflowd mod_containerd expects nS, so we can use directly.
		sfc.Metrics.Cpu.CpuTime = uint32(data.CPU.Usage.Total)
		sfc.Metrics.Mem.Memory = data.Memory.Usage.Usage
		sfc.Metrics.Mem.MaxMemory = data.Memory.Usage.Max
		for _, ioentry := range data.Blkio.IoServiceBytesRecursive {
			//cm.log(0, "ioentry=", ioentry)
			switch ioentry.Op {
			case "Read":
				sfc.Metrics.Dsk.Rd_bytes += ioentry.Value
			case "Write":
				sfc.Metrics.Dsk.Wr_bytes += ioentry.Value
			case "Discard":
			case "Sync":
			case "Async":
			case "Total":
			}
		}
		for _, ioentry := range data.Blkio.IoServicedRecursive {
			//cm.log(0, "ioentry=", ioentry)
			switch ioentry.Op {
			case "Read":
				sfc.Metrics.Dsk.Rd_req += uint32(ioentry.Value)
			case "Write":
				sfc.Metrics.Dsk.Wr_req += uint32(ioentry.Value)
			case "Discard":
				sfc.Metrics.Dsk.Errs += uint32(ioentry.Value)
			case "Sync":
			case "Async":
			case "Total":
			}
		}
		//mjson, err := json.MarshalIndent(data, "", "   ")
		//if err != nil {
		//	return err
		//}
		//cm.log(0, string(mjson))
	case *v2.Metrics:
		data2 = v
		cm.log(1, data2)
		sfc.Metrics.Cpu.CpuCount = 1
		sfc.Metrics.Cpu.CpuTime = uint32(data2.CPU.UsageUsec) // nS (see for v1 above)
		sfc.Metrics.Mem.Memory = data2.Memory.Usage
		sfc.Metrics.Mem.MaxMemory = data2.Memory.UsageLimit
		for _, ioentry := range data2.Io.Usage {
			sfc.Metrics.Dsk.Rd_bytes += ioentry.Rbytes
			sfc.Metrics.Dsk.Wr_bytes += ioentry.Wbytes
			sfc.Metrics.Dsk.Rd_req += uint32(ioentry.Rios)
			sfc.Metrics.Dsk.Wr_req += uint32(ioentry.Wios)
		}
		//mjson, err := json.MarshalIndent(data2, "", "   ")
		//if err != nil {
		//	return err
		//}
		//cm.log(0, string(mjson))
	default:
		return errors.New("unexpected metrics type")
	}

	mjson, err := json.Marshal(sfc)
	if err != nil {
		return err
	}
	cm.dataLog(string(mjson))
	if cm.dbg >= 1 {
		// also pretty-print
		mjson, err = json.MarshalIndent(sfc, "", "   ")
		cm.log(0, string(mjson))
	}
	return nil
}

func (cm *CMonitor) metricTick(ctx context.Context, client *containerd.Client) error {
	for _, sfc := range cm.sfcontainers {
		if sfc.pollNow {
			// extra poll at beginning or end of lifecycle
			sfc.pollNow = false
			err := cm.pollMetrics(ctx, client, sfc)
			if err != nil {
				return err
			}
		}
		sfc.metricsCountdown--
		// TODO: don't poll if not in state running
		if sfc.metricsCountdown <= 0 {
			sfc.metricsCountdown = cm.polling
			err := cm.pollMetrics(ctx, client, sfc)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (cm CMonitor) pollContainer(ctx context.Context, client *containerd.Client, nsname string, id string) error {
	nsctx := namespaces.WithNamespace(ctx, nsname)
	cont, err := client.LoadContainer(nsctx, id)
	if err != nil {
		return err
	}
	key := cm.sFlowContainerKey(nsname, cont)
	sfc, ok := cm.sfcontainers[key]
	if !ok {
		err := cm.loadContainer(nsctx, nsname, cont)
		if err != nil {
			return err
		}
		sfc, ok = cm.sfcontainers[key]
	}
	if ok {
		// We don't seem to be able to get the last metrics on a "TaskExit" event
		// so there is no need to rush this.  And by just setting the flag here we
		// avoid polling metrics in quick succession if two triggering events are seen.
		sfc.pollNow = true
		// cm.pollMetrics(ctx, client, sfc)
	}
	return nil
}

func (cm CMonitor) monitorContainers(ctx context.Context) error {
	cm.log(1, "monitorContainers polling=", cm.polling)
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return err
	}
	defer client.Close()
	eventsClient := client.EventService()
	eventsCh, errCh := eventsClient.Subscribe(ctx)
	firstTime := true
	var tload time.Time = time.Now()
	var ttick time.Time = time.Now()
	for {
		if firstTime || time.Since(tload) >= (time.Second*time.Duration(cm.polling)) { // TODO: can check less often once we react to events
			firstTime = false
			err := cm.loadContainers(ctx, client)
			if err != nil {
				cm.log(0, "error in loadContainers:", err)
			}
			tload = time.Now()
		}

		var e *events.Envelope
		select {
		case e = <-eventsCh:
		case err := <-errCh:
			return err
		case <-time.After(time.Millisecond * 100):
			break
		}

		if e != nil {
			var out []byte
			if e.Event != nil {
				v, err := typeurl.UnmarshalAny(e.Event)
				if err != nil {
					cm.log(1, "cannot unmarshall event: ", err)
				} else {
					out, err = json.Marshal(v)
					if err != nil {
						cm.log(1, "cannot marshal into JSON: ", err)
					} else {
						cm.log(1,
							"timestamp: ",
							e.Timestamp,
							" Namespace: ",
							e.Namespace,
							" Topic: ",
							e.Topic,
							" JSON: ",
							string(out),
						)
					}
				}

				var pollIt string = ""
				switch v.(type) {
				case *apievents.TaskCreate:
					evt := v.(*apievents.TaskCreate)
					cm.log(1, "type=TaskCreate containerID=", evt.ContainerID)
				case *apievents.TaskStart:
					evt := v.(*apievents.TaskStart)
					cm.log(1, "type=TaskStart containerID=", evt.ContainerID)
					pollIt = evt.ContainerID
				case *apievents.TaskOOM:
					evt := v.(*apievents.TaskOOM)
					cm.log(1, "type=TaskOOM containerID=", evt.ContainerID)
				case *apievents.TaskExit:
					evt := v.(*apievents.TaskExit)
					cm.log(1, "type=TaskExit containerID=", evt.ContainerID)
					pollIt = evt.ContainerID
				case *apievents.TaskDelete:
					evt := v.(*apievents.TaskDelete)
					cm.log(1, "type=TaskDelete id=", evt.ID, "containerID=", evt.ContainerID)
				case *apievents.TaskExecAdded:
					evt := v.(*apievents.TaskExecAdded)
					cm.log(1, "type=TaskExecAdded containerID=", evt.ContainerID)
				case *apievents.TaskExecStarted:
					evt := v.(*apievents.TaskExecStarted)
					cm.log(1, "type=TaskExecStarted containerID=", evt.ContainerID)
				case *apievents.TaskPaused:
					evt := v.(*apievents.TaskPaused)
					cm.log(1, "type=TaskPaused containerID=", evt.ContainerID)
					pollIt = evt.ContainerID
				case *apievents.TaskResumed:
					evt := v.(*apievents.TaskResumed)
					cm.log(1, "type=TaskResumed containerID=", evt.ContainerID)
					pollIt = evt.ContainerID
				case *apievents.TaskCheckpointed:
					evt := v.(*apievents.TaskCheckpointed)
					cm.log(1, "type=TaskCheckpointed containerID=", evt.ContainerID)
				case *apievents.ImageCreate:
					evt := v.(*apievents.ImageCreate)
					cm.log(1, "type=ImageCreate name=", evt.Name)
				case *apievents.ImageDelete:
					evt := v.(*apievents.ImageDelete)
					cm.log(1, "type=ImageDelete name=", evt.Name)
				case *apievents.ImageUpdate:
					evt := v.(*apievents.ImageUpdate)
					cm.log(1, "type=ImageUpdate name=", evt.Name)
				case *apievents.ContainerCreate:
					evt := v.(*apievents.ContainerCreate)
					cm.log(1, "type=ContainerCreate ID=", evt.ID)
				case *apievents.ContainerCreate_Runtime:
					evt := v.(*apievents.ContainerCreate_Runtime)
					cm.log(1, "type=ContainerCreate_Runtime name=", evt.Name)
				case *apievents.ContainerUpdate:
					evt := v.(*apievents.ContainerUpdate)
					cm.log(1, "type=ContainerUpdate ID=", evt.ID)
				case *apievents.ContainerDelete:
					evt := v.(*apievents.ContainerDelete)
					cm.log(1, "type=ContainerDelete ID=", evt.ID)
				case *apievents.NamespaceCreate:
					evt := v.(*apievents.NamespaceCreate)
					cm.log(1, "type=NamespaceCreate name=", evt.Name)
				case *apievents.NamespaceUpdate:
					evt := v.(*apievents.NamespaceUpdate)
					cm.log(1, "type=NamespaceUpdate name=", evt.Name)
				case *apievents.NamespaceDelete:
					evt := v.(*apievents.NamespaceDelete)
					cm.log(1, "type=NamespaceDelete name=", evt.Name)
				case *apievents.SnapshotPrepare:
					evt := v.(*apievents.SnapshotPrepare)
					cm.log(1, "type=SnapshotPrepare key=", evt.Key, " parent=", evt.Parent)
				case *apievents.SnapshotCommit:
					evt := v.(*apievents.SnapshotCommit)
					cm.log(1, "type=SnapshotCommit key=", evt.Key)
				case *apievents.SnapshotRemove:
					evt := v.(*apievents.SnapshotRemove)
					cm.log(1, "type=SnapshotRemove key=", evt.Key)
				}
				if pollIt != "" {
					err := cm.pollContainer(ctx, client, e.Namespace, pollIt)
					if err != nil {
						cm.log(0, "error polling container: ", pollIt, err)
					}
				}
			}
		}

		if time.Since(ttick) >= (time.Second * 1) {
			err := cm.metricTick(ctx, client)
			if err != nil {
				cm.log(0, "error in metricTick:", err)
			}
			ttick = time.Now()
		}
	}
}
