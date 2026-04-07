// Package modbus provides Modbus TCP/RTU register scanning and type inference.
//
// Extracted from go-modbus-scanner. Used by go-modbus-scanner, go-edge-gateway,
// and go-ot-security for protocol probing.
package modbus

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/goburrow/modbus"
)

// ScanRequest is the input for a scan job.
type ScanRequest struct {
	// Connection mode: "tcp" (default) or "rtu"
	Mode string `json:"mode"`

	// TCP mode fields
	Host string `json:"host"`
	Port int    `json:"port"`

	// RTU mode fields
	SerialPort string `json:"serial_port"`
	BaudRate   int    `json:"baud_rate"`
	DataBits   int    `json:"data_bits"`
	StopBits   int    `json:"stop_bits"`
	Parity     string `json:"parity"` // "N", "E", "O"

	// Common fields
	UnitID           uint8    `json:"unit_id"`
	ScanTypes        []string `json:"scan_types"`         // holding, input, coil, discrete
	AddressStart     uint16   `json:"address_start"`
	AddressEnd       uint16   `json:"address_end"`
	BatchSize        uint16   `json:"batch_size"`
	Samples          int      `json:"samples"`            // multi-sample count
	SampleIntervalMs int      `json:"sample_interval_ms"`
	TimeoutMs        int      `json:"timeout_ms"`
	DelayMs          int      `json:"delay_ms"`           // delay between batches
}

// ApplyDefaults fills zero-value fields with sensible defaults.
func (r *ScanRequest) ApplyDefaults() {
	if r.Mode == "" {
		r.Mode = "tcp"
	}
	if r.Port == 0 {
		r.Port = 502
	}
	if r.BaudRate == 0 {
		r.BaudRate = 9600
	}
	if r.DataBits == 0 {
		r.DataBits = 8
	}
	if r.StopBits == 0 {
		r.StopBits = 1
	}
	if r.Parity == "" {
		r.Parity = "N"
	}
	if r.UnitID == 0 {
		r.UnitID = 1
	}
	if len(r.ScanTypes) == 0 {
		r.ScanTypes = []string{"holding"}
	}
	if r.AddressEnd == 0 {
		r.AddressEnd = 9999
	}
	if r.BatchSize == 0 {
		r.BatchSize = 125
	}
	if r.Samples == 0 {
		r.Samples = 3
	}
	if r.SampleIntervalMs == 0 {
		r.SampleIntervalMs = 1000
	}
	if r.TimeoutMs == 0 {
		r.TimeoutMs = 500
	}
	if r.DelayMs == 0 {
		r.DelayMs = 10
	}
}

// RawRegister holds the raw scan result for one address.
type RawRegister struct {
	Address   uint16   `json:"address"`
	Type      string   `json:"type"` // holding, input, coil, discrete
	RawValues []uint16 `json:"raw_values"`
}

// ScanResult is the output of a complete scan.
type ScanResult struct {
	Device     string             `json:"device"`
	UnitID     uint8              `json:"unit_id"`
	DurationMs int64              `json:"scan_duration_ms"`
	Summary    ScanSummary        `json:"summary"`
	Registers  []AnalyzedRegister `json:"registers"`
}

// ScanSummary holds aggregate scan statistics.
type ScanSummary struct {
	TotalScanned int `json:"total_scanned"`
	Responsive   int `json:"responsive"`
	Dynamic      int `json:"dynamic"`
	Static       int `json:"static"`
}

// ClientConn wraps a modbus.Client with its closer and device label.
type ClientConn struct {
	Client modbus.Client
	Close  func()
	Device string
}

// NewClient creates a Modbus client (TCP or RTU) based on the request mode.
func NewClient(req ScanRequest) (*ClientConn, error) {
	switch req.Mode {
	case "rtu":
		if req.SerialPort == "" {
			return nil, fmt.Errorf("serial_port is required for RTU mode")
		}
		handler := modbus.NewRTUClientHandler(req.SerialPort)
		handler.BaudRate = req.BaudRate
		handler.DataBits = req.DataBits
		handler.StopBits = req.StopBits
		handler.Parity = req.Parity
		handler.SlaveId = req.UnitID
		handler.Timeout = time.Duration(req.TimeoutMs) * time.Millisecond

		if err := handler.Connect(); err != nil {
			return nil, fmt.Errorf("connect serial %s: %w", req.SerialPort, err)
		}
		return &ClientConn{
			Client: modbus.NewClient(handler),
			Close:  func() { handler.Close() },
			Device: fmt.Sprintf("rtu:%s@%d", req.SerialPort, req.BaudRate),
		}, nil

	default: // tcp
		addr := fmt.Sprintf("%s:%d", req.Host, req.Port)
		handler := modbus.NewTCPClientHandler(addr)
		handler.Timeout = time.Duration(req.TimeoutMs) * time.Millisecond
		handler.SlaveId = req.UnitID

		if err := handler.Connect(); err != nil {
			return nil, fmt.Errorf("connect %s: %w", addr, err)
		}
		return &ClientConn{
			Client: modbus.NewClient(handler),
			Close:  func() { handler.Close() },
			Device: addr,
		}, nil
	}
}

// Scan runs a full scan against a Modbus device (TCP or RTU).
func Scan(req ScanRequest) (*ScanResult, error) {
	req.ApplyDefaults()
	start := time.Now()

	conn, err := NewClient(req)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := conn.Client

	var allRaw []RawRegister
	totalScanned := 0

	for _, scanType := range req.ScanTypes {
		raws, scanned := scanRegisters(client, scanType, req.AddressStart, req.AddressEnd, req.BatchSize, req.DelayMs)
		allRaw = append(allRaw, raws...)
		totalScanned += scanned
		slog.Info("scan phase complete",
			"type", scanType,
			"responsive", len(raws),
			"scanned", scanned,
		)
	}

	if req.Samples > 1 && len(allRaw) > 0 {
		for s := 1; s < req.Samples; s++ {
			time.Sleep(time.Duration(req.SampleIntervalMs) * time.Millisecond)
			resample(client, allRaw, req.DelayMs)
			slog.Info("resample complete", "sample", s+1, "of", req.Samples)
		}
	}

	analyzed := Analyze(allRaw)

	dynamic := 0
	static := 0
	for _, a := range analyzed {
		if a.IsDynamic {
			dynamic++
		} else {
			static++
		}
	}

	return &ScanResult{
		Device:     conn.Device,
		UnitID:     req.UnitID,
		DurationMs: time.Since(start).Milliseconds(),
		Summary: ScanSummary{
			TotalScanned: totalScanned,
			Responsive:   len(analyzed),
			Dynamic:      dynamic,
			Static:       static,
		},
		Registers: analyzed,
	}, nil
}

func scanRegisters(client modbus.Client, regType string, start, end, batchSize uint16, delayMs int) ([]RawRegister, int) {
	var results []RawRegister
	scanned := 0

	for addr := start; addr <= end; {
		count := batchSize
		if addr+count-1 > end {
			count = end - addr + 1
		}

		data, err := ReadBatch(client, regType, addr, count)
		scanned += int(count)

		if err == nil && len(data) > 0 {
			values := BytesToUint16(data)
			for i, v := range values {
				results = append(results, RawRegister{
					Address:   addr + uint16(i),
					Type:      regType,
					RawValues: []uint16{v},
				})
			}
		}

		addr += count
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}

	return results, scanned
}

func resample(client modbus.Client, registers []RawRegister, delayMs int) {
	for i := range registers {
		reg := &registers[i]
		data, err := ReadBatch(client, reg.Type, reg.Address, 1)
		if err == nil && len(data) >= 2 {
			val := binary.BigEndian.Uint16(data[:2])
			reg.RawValues = append(reg.RawValues, val)
		}
		if delayMs > 0 && i%50 == 49 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}
}

// ReadBatch reads a batch of registers by type.
func ReadBatch(client modbus.Client, regType string, addr, count uint16) ([]byte, error) {
	switch regType {
	case "holding":
		return client.ReadHoldingRegisters(addr, count)
	case "input":
		return client.ReadInputRegisters(addr, count)
	case "coil":
		return client.ReadCoils(addr, count)
	case "discrete":
		return client.ReadDiscreteInputs(addr, count)
	default:
		return nil, fmt.Errorf("unknown register type: %s", regType)
	}
}

// BytesToUint16 converts raw bytes to uint16 slice (big-endian).
func BytesToUint16(data []byte) []uint16 {
	n := len(data) / 2
	values := make([]uint16, n)
	for i := 0; i < n; i++ {
		values[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
	}
	return values
}

// Float32FromPair converts two consecutive uint16 registers to float32 (big-endian).
func Float32FromPair(hi, lo uint16) float32 {
	bits := uint32(hi)<<16 | uint32(lo)
	return math.Float32frombits(bits)
}

// ListSerialPorts returns available serial port paths for the current OS.
func ListSerialPorts() []string {
	var patterns []string
	switch runtime.GOOS {
	case "darwin":
		patterns = []string{"/dev/cu.usb*", "/dev/cu.wchusbserial*", "/dev/tty.usb*", "/dev/tty.wchusbserial*"}
	case "linux":
		patterns = []string{"/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*"}
	default:
		patterns = []string{}
	}

	var ports []string
	seen := make(map[string]bool)
	for _, p := range patterns {
		matches, _ := filepath.Glob(p)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				ports = append(ports, m)
			}
		}
	}

	if runtime.GOOS == "linux" {
		var filtered []string
		for _, p := range ports {
			if strings.HasPrefix(p, "/dev/ttyS") {
				if info, err := os.Stat(p); err == nil && info.Mode()&os.ModeCharDevice != 0 {
					filtered = append(filtered, p)
				}
			} else {
				filtered = append(filtered, p)
			}
		}
		ports = filtered
	}

	if ports == nil {
		ports = []string{}
	}
	return ports
}
