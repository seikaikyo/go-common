package modbus

import (
	"fmt"
	"math"
)

// AnalyzedRegister is a register with inferred type and usage guess.
type AnalyzedRegister struct {
	Address      uint16   `json:"address"`
	Type         string   `json:"type"`
	RawValues    []uint16 `json:"raw_values"`
	InferredType string   `json:"inferred_type"`
	IsDynamic    bool     `json:"is_dynamic"`
	ValueRange   Range    `json:"value_range"`
	Float32Value *float64 `json:"float32_value,omitempty"`
	PairedAddr   *uint16  `json:"paired_address,omitempty"`
	Guess        *Guess   `json:"guess,omitempty"`
}

// Range holds min/max of sampled values.
type Range struct {
	Min uint16 `json:"min"`
	Max uint16 `json:"max"`
}

// Guess is a heuristic category inference for a register.
type Guess struct {
	Category string `json:"category"`
	Reason   string `json:"reason"`
}

// Analyze takes raw scan data and produces analyzed registers.
func Analyze(raws []RawRegister) []AnalyzedRegister {
	addrMap := make(map[uint16]int)
	for i, r := range raws {
		addrMap[r.Address] = i
	}

	analyzed := make([]AnalyzedRegister, 0, len(raws))
	skipNext := make(map[uint16]bool)

	for _, raw := range raws {
		if skipNext[raw.Address] {
			continue
		}

		a := AnalyzedRegister{
			Address:   raw.Address,
			Type:      raw.Type,
			RawValues: raw.RawValues,
		}

		a.ValueRange = calcRange(raw.RawValues)
		a.IsDynamic = isDynamic(raw.RawValues)

		nextAddr := raw.Address + 1
		if nextIdx, ok := addrMap[nextAddr]; ok && raw.Type == "holding" || raw.Type == "input" {
			if tryFloat32Pair(&a, raw, raws[nextIdx]) {
				skipNext[nextAddr] = true
			}
		}

		if a.InferredType == "" {
			a.InferredType = inferType(raw)
		}

		a.Guess = guessCategory(a)

		analyzed = append(analyzed, a)
	}

	return analyzed
}

func calcRange(values []uint16) Range {
	if len(values) == 0 {
		return Range{}
	}
	mn, mx := values[0], values[0]
	for _, v := range values[1:] {
		if v < mn {
			mn = v
		}
		if v > mx {
			mx = v
		}
	}
	return Range{Min: mn, Max: mx}
}

func isDynamic(values []uint16) bool {
	if len(values) < 2 {
		return false
	}
	first := values[0]
	for _, v := range values[1:] {
		if v != first {
			return true
		}
	}
	return false
}

func tryFloat32Pair(a *AnalyzedRegister, hi, lo RawRegister) bool {
	if len(hi.RawValues) == 0 || len(lo.RawValues) == 0 {
		return false
	}

	f := Float32FromPair(hi.RawValues[0], lo.RawValues[0])

	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	absF := math.Abs(float64(f))
	if absF < 0.001 && f != 0 {
		return false
	}
	if absF > 1e7 {
		return false
	}

	fVal := math.Round(float64(f)*100) / 100
	a.InferredType = "float32_hi"
	a.Float32Value = &fVal
	paired := lo.Address
	a.PairedAddr = &paired

	if len(hi.RawValues) >= 2 && len(lo.RawValues) >= 2 {
		for i := 1; i < len(hi.RawValues) && i < len(lo.RawValues); i++ {
			f2 := Float32FromPair(hi.RawValues[i], lo.RawValues[i])
			if f2 != f {
				a.IsDynamic = true
				break
			}
		}
	}

	return true
}

func inferType(raw RawRegister) string {
	if raw.Type == "coil" || raw.Type == "discrete" {
		return "bool"
	}

	for _, v := range raw.RawValues {
		if v > 32767 {
			return "int16"
		}
	}
	return "uint16"
}

func guessCategory(a AnalyzedRegister) *Guess {
	if a.InferredType == "bool" {
		if a.IsDynamic {
			return &Guess{Category: "on-off status", Reason: "boolean, dynamic"}
		}
		return &Guess{Category: "config flag", Reason: "boolean, static"}
	}

	if a.InferredType == "float32_hi" && a.Float32Value != nil {
		return guessFromFloat(*a.Float32Value, a.IsDynamic)
	}

	r := a.ValueRange

	if a.IsDynamic && isMonotonic(a.RawValues) {
		return &Guess{Category: "counter", Reason: "monotonically increasing"}
	}

	if a.IsDynamic {
		return guessFromRange(r)
	}

	if r.Max <= 10 {
		return &Guess{Category: "config/mode", Reason: "static, small integer"}
	}
	return &Guess{Category: "parameter", Reason: "static value"}
}

func guessFromFloat(f float64, dynamic bool) *Guess {
	abs := math.Abs(f)
	suffix := "static"
	if dynamic {
		suffix = "dynamic"
	}

	switch {
	case abs >= -40 && abs <= 200:
		return &Guess{
			Category: "temperature",
			Reason:   fmt.Sprintf("float32 value %.2f, range fits temperature, %s", f, suffix),
		}
	case abs >= 0 && abs <= 100:
		return &Guess{
			Category: "percentage",
			Reason:   fmt.Sprintf("float32 value %.2f, range fits percentage, %s", f, suffix),
		}
	case abs >= 0 && abs <= 2000:
		return &Guess{
			Category: "pressure",
			Reason:   fmt.Sprintf("float32 value %.2f, range fits pressure, %s", f, suffix),
		}
	default:
		return &Guess{
			Category: "measurement",
			Reason:   fmt.Sprintf("float32 value %.2f, %s", f, suffix),
		}
	}
}

func guessFromRange(r Range) *Guess {
	scaledMin := float64(r.Min) / 10.0
	scaledMax := float64(r.Max) / 10.0

	switch {
	case scaledMax <= 200 && scaledMin >= -40:
		return &Guess{
			Category: "temperature",
			Reason:   fmt.Sprintf("range %.1f-%.1f after /10 scaling, dynamic", scaledMin, scaledMax),
		}
	case r.Max <= 100:
		return &Guess{
			Category: "percentage",
			Reason:   fmt.Sprintf("range %d-%d fits 0-100%%, dynamic", r.Min, r.Max),
		}
	case r.Max <= 1000:
		return &Guess{
			Category: "pressure/level",
			Reason:   fmt.Sprintf("range %d-%d, dynamic", r.Min, r.Max),
		}
	case r.Max <= 30000:
		return &Guess{
			Category: "rpm/speed",
			Reason:   fmt.Sprintf("range %d-%d, dynamic", r.Min, r.Max),
		}
	default:
		return &Guess{
			Category: "measurement",
			Reason:   fmt.Sprintf("range %d-%d, dynamic", r.Min, r.Max),
		}
	}
}

func isMonotonic(values []uint16) bool {
	if len(values) < 3 {
		return false
	}
	for i := 1; i < len(values); i++ {
		if values[i] < values[i-1] {
			return false
		}
	}
	return values[len(values)-1] > values[0]
}
