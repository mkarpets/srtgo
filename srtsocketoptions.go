package srtgo

// #cgo LDFLAGS: -lsrt
// #include <srt/srt.h>
import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	transTypeLive = 0
	transTypeFile = 1
)

const (
	tInteger32 = 0
	tInteger64 = 1
	tString    = 2
	tBoolean   = 3
	tTransType = 4

	SRTO_TRANSTYPE          = C.SRTO_TRANSTYPE
	SRTO_MAXBW              = C.SRTO_MAXBW
	SRTO_PBKEYLEN           = C.SRTO_PBKEYLEN
	SRTO_PASSPHRASE         = C.SRTO_PASSPHRASE
	SRTO_MSS                = C.SRTO_MSS
	SRTO_FC                 = C.SRTO_FC
	SRTO_SNDBUF             = C.SRTO_SNDBUF
	SRTO_RCVBUF             = C.SRTO_RCVBUF
	SRTO_IPTTL              = C.SRTO_IPTTL
	SRTO_IPTOS              = C.SRTO_IPTOS
	SRTO_INPUTBW            = C.SRTO_INPUTBW
	SRTO_OHEADBW            = C.SRTO_OHEADBW
	SRTO_LATENCY            = C.SRTO_LATENCY
	SRTO_TSBPDMODE          = C.SRTO_TSBPDMODE
	SRTO_TLPKTDROP          = C.SRTO_TLPKTDROP
	SRTO_SNDDROPDELAY       = C.SRTO_SNDDROPDELAY
	SRTO_NAKREPORT          = C.SRTO_NAKREPORT
	SRTO_CONNTIMEO          = C.SRTO_CONNTIMEO
	SRTO_LOSSMAXTTL         = C.SRTO_LOSSMAXTTL
	SRTO_RCVLATENCY         = C.SRTO_RCVLATENCY
	SRTO_PEERLATENCY        = C.SRTO_PEERLATENCY
	SRTO_MINVERSION         = C.SRTO_MINVERSION
	SRTO_STREAMID           = C.SRTO_STREAMID
	SRTO_CONGESTION         = C.SRTO_CONGESTION
	SRTO_MESSAGEAPI         = C.SRTO_MESSAGEAPI
	SRTO_PAYLOADSIZE        = C.SRTO_PAYLOADSIZE
	SRTO_KMREFRESHRATE      = C.SRTO_KMREFRESHRATE
	SRTO_KMPREANNOUNCE      = C.SRTO_KMPREANNOUNCE
	SRTO_ENFORCEDENCRYPTION = C.SRTO_ENFORCEDENCRYPTION
	SRTO_PEERIDLETIMEO      = C.SRTO_PEERIDLETIMEO
	SRTO_PACKETFILTER       = C.SRTO_PACKETFILTER
	SRTO_STATE              = C.SRTO_STATE
	SRTO_UDP_RCVBUF         = C.SRTO_UDP_RCVBUF
	SRTO_UDP_SNDBUF         = C.SRTO_UDP_SNDBUF
	SRTO_MININPUTBW         = C.SRTO_MININPUTBW
	SRTO_SENDER             = C.SRTO_SENDER
	SRTO_REUSEADDR          = C.SRTO_REUSEADDR
)

type socketOption struct {
	name      string
	level     int
	option    int
	lifecycle SrtOptionLifecycle // EXPLICIT lifecycle property - single source of truth
	dataType  int
}

// Name returns the option name (accessor for external use)
func (so socketOption) Name() string {
	return so.name
}

// Lifecycle returns the option lifecycle stage (accessor for external use)
func (so socketOption) Lifecycle() SrtOptionLifecycle {
	return so.lifecycle
}

// CanSetAt checks if this option can be set at the given lifecycle stage
// This encapsulates the lifecycle compatibility logic
func (so socketOption) CanSetAt(stage SrtOptionLifecycle) bool {
	// PREBIND options can ONLY be set before bind
	if so.lifecycle == LifecyclePrebind {
		return stage == LifecyclePrebind
	}
	// PRE options can be set at prebind OR pre stages
	if so.lifecycle == LifecyclePre {
		return stage == LifecyclePrebind || stage == LifecyclePre
	}
	// POST options can be set at ANY stage
	return true
}

// List of possible srt socket options
// Each option explicitly declares its lifecycle requirement
var SocketOptions = []socketOption{
	// ===== PREBIND OPTIONS (SRTO_R_PREBIND) =====
	// These affect buffer allocation and binding behavior
	{"mss", 0, SRTO_MSS, LifecyclePrebind, tInteger32},
	{"sndbuf", 0, SRTO_SNDBUF, LifecyclePrebind, tInteger32},
	{"rcvbuf", 0, SRTO_RCVBUF, LifecyclePrebind, tInteger32},
	{"udp_sndbuf", 0, SRTO_UDP_SNDBUF, LifecyclePrebind, tInteger32},
	{"udp_rcvbuf", 0, SRTO_UDP_RCVBUF, LifecyclePrebind, tInteger32},
	{"ipttl", 0, SRTO_IPTTL, LifecyclePrebind, tInteger32},
	{"iptos", 0, SRTO_IPTOS, LifecyclePrebind, tInteger32},
	{"reuseaddr", 0, SRTO_REUSEADDR, LifecyclePrebind, tBoolean},
	{"transtype", 0, SRTO_TRANSTYPE, LifecyclePrebind, tTransType},

	// ===== PRE OPTIONS (SRTO_R_PRE) =====
	// These affect handshake, encryption, connection negotiation
	{"fc", 0, SRTO_FC, LifecyclePre, tInteger32},
	{"sender", 0, SRTO_SENDER, LifecyclePre, tBoolean},
	{"tsbpdmode", 0, SRTO_TSBPDMODE, LifecyclePre, tBoolean},
	{"latency", 0, SRTO_LATENCY, LifecyclePre, tInteger32},
	{"rcvlatency", 0, SRTO_RCVLATENCY, LifecyclePre, tInteger32},
	{"peerlatency", 0, SRTO_PEERLATENCY, LifecyclePre, tInteger32},
	{"passphrase", 0, SRTO_PASSPHRASE, LifecyclePre, tString},
	{"pbkeylen", 0, SRTO_PBKEYLEN, LifecyclePre, tInteger32},
	{"tlpktdrop", 0, SRTO_TLPKTDROP, LifecyclePre, tBoolean},
	{"nakreport", 0, SRTO_NAKREPORT, LifecyclePre, tBoolean},
	{"conntimeo", 0, SRTO_CONNTIMEO, LifecyclePre, tInteger32},
	{"streamid", 0, SRTO_STREAMID, LifecyclePre, tString},
	{"payloadsize", 0, SRTO_PAYLOADSIZE, LifecyclePre, tInteger32},
	{"messageapi", 0, SRTO_MESSAGEAPI, LifecyclePre, tBoolean},
	{"minversion", 0, SRTO_MINVERSION, LifecyclePre, tInteger32},
	{"enforcedencryption", 0, SRTO_ENFORCEDENCRYPTION, LifecyclePre, tBoolean},
	{"peeridletimeo", 0, SRTO_PEERIDLETIMEO, LifecyclePre, tInteger32},
	{"packetfilter", 0, SRTO_PACKETFILTER, LifecyclePre, tString},
	{"congestion", 0, SRTO_CONGESTION, LifecyclePre, tString},
	{"kmrefreshrate", 0, SRTO_KMREFRESHRATE, LifecyclePre, tInteger32},
	{"kmpreannounce", 0, SRTO_KMPREANNOUNCE, LifecyclePre, tInteger32},

	// ===== POST OPTIONS (no restriction flags) =====
	// These can be adjusted anytime - bandwidth, loss handling, timeouts
	{"maxbw", 0, SRTO_MAXBW, LifecyclePost, tInteger64},
	{"inputbw", 0, SRTO_INPUTBW, LifecyclePost, tInteger64},
	{"mininputbw", 0, SRTO_MININPUTBW, LifecyclePost, tInteger64},
	{"oheadbw", 0, SRTO_OHEADBW, LifecyclePost, tInteger32},
	{"snddropdelay", 0, SRTO_SNDDROPDELAY, LifecyclePost, tInteger32},
	{"lossmaxttl", 0, SRTO_LOSSMAXTTL, LifecyclePost, tInteger32},
}

func setSocketLingerOption(s C.int, li int32) error {
	var lin syscall.Linger
	lin.Linger = li
	if lin.Linger > 0 {
		lin.Onoff = 1
	} else {
		lin.Onoff = 0
	}
	res := C.srt_setsockopt(s, bindingPre, C.SRTO_LINGER, unsafe.Pointer(&lin), C.int(unsafe.Sizeof(lin)))
	if res == SRT_ERROR {
		return errors.New("failed to set linger")
	}
	return nil
}

func getSocketLingerOption(s *SrtSocket) (int32, error) {
	var lin syscall.Linger
	size := int(unsafe.Sizeof(lin))
	err := s.getSockOpt(C.SRTO_LINGER, unsafe.Pointer(&lin), &size)
	if err != nil {
		return 0, err
	}
	if lin.Onoff == 0 {
		return 0, nil
	}
	return lin.Linger, nil
}

// setSocketOption sets a single socket option based on its data type
func setSocketOption(socket C.int, optDef *socketOption, val string) error {
	switch optDef.dataType {
	case tInteger32:
		v, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("invalid integer value: %w", err)
		}
		v32 := int32(v)
		result := C.srt_setsockflag(socket, C.SRT_SOCKOPT(optDef.option), unsafe.Pointer(&v32), C.int32_t(unsafe.Sizeof(v32)))
		if result == -1 {
			return srtGetAndClearError()
		}

	case tInteger64:
		v, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer64 value: %w", err)
		}
		result := C.srt_setsockflag(socket, C.SRT_SOCKOPT(optDef.option), unsafe.Pointer(&v), C.int32_t(unsafe.Sizeof(v)))
		if result == -1 {
			return srtGetAndClearError()
		}

	case tString:
		sval := C.CString(val)
		defer C.free(unsafe.Pointer(sval))
		result := C.srt_setsockflag(socket, C.SRT_SOCKOPT(optDef.option), unsafe.Pointer(sval), C.int32_t(len(val)))
		if result == -1 {
			return srtGetAndClearError()
		}

	case tBoolean:
		var v C.char
		if val == "1" || val == "true" {
			v = C.char(1)
		} else if val == "0" || val == "false" {
			v = C.char(0)
		} else {
			return fmt.Errorf("invalid boolean value: %s", val)
		}
		result := C.srt_setsockflag(socket, C.SRT_SOCKOPT(optDef.option), unsafe.Pointer(&v), C.int32_t(unsafe.Sizeof(v)))
		if result == -1 {
			return srtGetAndClearError()
		}

	case tTransType:
		var v int32
		if val == "live" {
			v = C.SRTT_LIVE
		} else if val == "file" {
			v = C.SRTT_FILE
		} else {
			return fmt.Errorf("invalid transtype value: %s (must be 'live' or 'file')", val)
		}
		result := C.srt_setsockflag(socket, C.SRT_SOCKOPT(optDef.option), unsafe.Pointer(&v), C.int32_t(unsafe.Sizeof(v)))
		if result == -1 {
			return srtGetAndClearError()
		}

	default:
		return fmt.Errorf("unsupported data type %d", optDef.dataType)
	}

	return nil
}

// setSocketOptionsForLifecycle sets options appropriate for the lifecycle stage
// It validates each option against its declared lifecycle before setting
func setSocketOptionsForLifecycle(socket C.int, stage SrtOptionLifecycle, options map[string]string) error {
	var errors []string

	for name, val := range options {
		// Find option definition in registry
		var optDef *socketOption
		for i := range SocketOptions {
			if SocketOptions[i].Name() == name {
				optDef = &SocketOptions[i]
				break
			}
		}

		if optDef == nil {
			errors = append(errors, fmt.Sprintf("unknown option: %s", name))
			continue
		}

		// Verify option can be set at this lifecycle stage
		if !optDef.CanSetAt(stage) {
			errors = append(errors, fmt.Sprintf("option '%s' cannot be set at %s stage (requires %s)",
				name, stage.String(), optDef.Lifecycle().String()))
			continue
		}

		// Set the option
		if err := setSocketOption(socket, optDef, val); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("socket option errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// FindSocketOption looks up an option by name in the SocketOptions registry
// Returns nil if the option is not found
func FindSocketOption(name string) *socketOption {
	for i := range SocketOptions {
		if SocketOptions[i].Name() == name {
			return &SocketOptions[i]
		}
	}
	return nil
}

// ValidateSocketOptionsForLifecycle validates that options can be set at the given lifecycle stage
// Returns an error describing any invalid options, without actually setting them
func ValidateSocketOptionsForLifecycle(stage SrtOptionLifecycle, options map[string]string) error {
	var errors []string

	for name := range options {
		optDef := FindSocketOption(name)
		if optDef == nil {
			errors = append(errors, fmt.Sprintf("unknown option: %s", name))
			continue
		}

		if !optDef.CanSetAt(stage) {
			errors = append(errors, fmt.Sprintf("option '%s' cannot be set at %s stage (requires %s)",
				name, stage.String(), optDef.Lifecycle().String()))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("socket option validation errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// SetSocketOptionsForLifecycle wraps setSocketOptionsForLifecycle for external use
func SetSocketOptionsForLifecycle(socket C.int, stage SrtOptionLifecycle, options map[string]string) error {
	return setSocketOptionsForLifecycle(socket, stage, options)
}

// Deprecated: setSocketOptions kept for backwards compatibility
// Use setSocketOptionsForLifecycle instead
func setSocketOptions(s C.int, binding int, options map[string]string) error {
	// Convert old binding to lifecycle
	var stage SrtOptionLifecycle
	if binding == bindingPre {
		stage = LifecyclePre
	} else {
		stage = LifecyclePost
	}
	return setSocketOptionsForLifecycle(s, stage, options)
}
