package srtgo

/*
#cgo LDFLAGS: -lsrt
#include <srt/srt.h>
extern void srtLogCB(void* opaque, int level, const char* file, int line, const char* area, const char* message);
*/
import "C"

import (
	"sync"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type LogCallBackFunc func(level SrtLogLevel, file string, line int, area, message string)

type SrtLogLevel int

const (
	//	SrtLogLevelEmerg = int(C.LOG_EMERG)
	//	SrtLogLevelAlert = int(C.LOG_ALERT)
	SrtLogLevelCrit    SrtLogLevel = SrtLogLevel(C.LOG_CRIT)
	SrtLogLevelErr     SrtLogLevel = SrtLogLevel(C.LOG_ERR)
	SrtLogLevelWarning SrtLogLevel = SrtLogLevel(C.LOG_WARNING)
	SrtLogLevelNotice  SrtLogLevel = SrtLogLevel(C.LOG_NOTICE)
	SrtLogLevelInfo    SrtLogLevel = SrtLogLevel(C.LOG_INFO)
	SrtLogLevelDebug   SrtLogLevel = SrtLogLevel(C.LOG_DEBUG)
	SrtLogLevelTrace   SrtLogLevel = SrtLogLevel(8)
)

type SrtLogFA int

const (
	SrtLogFAGeneral   SrtLogFA = 0
	SrtLogFASockMgmt  SrtLogFA = 1
	SrtLogFAConn      SrtLogFA = 2
	SrtLogFAXTimer    SrtLogFA = 3
	SrtLogFATsbpd     SrtLogFA = 4
	SrtLogFARsrc      SrtLogFA = 5
	SrtLogFAHaiCrypt  SrtLogFA = 6
	SrtLogFACongest   SrtLogFA = 7
	SrtLogFAPFilter   SrtLogFA = 8
	SrtLogFAAppLog    SrtLogFA = 10
	SrtLogFAAPICtrl   SrtLogFA = 11
	SrtLogFAQueCtrl   SrtLogFA = 13
	SrtLogFAEPollUpd  SrtLogFA = 16
	SrtLogFAAPIRecv   SrtLogFA = 21
	SrtLogFABufRecv   SrtLogFA = 22
	SrtLogFAQueRecv   SrtLogFA = 23
	SrtLogFAChnRecv   SrtLogFA = 24
	SrtLogFAGrpRecv   SrtLogFA = 25
	SrtLogFAAPISend   SrtLogFA = 31
	SrtLogFABufSend   SrtLogFA = 32
	SrtLogFAQueSend   SrtLogFA = 33
	SrtLogFAChnSend   SrtLogFA = 34
	SrtLogFAGrpSend   SrtLogFA = 35
	SrtLogFAInternal  SrtLogFA = 41
	SrtLogFAQueMgmt   SrtLogFA = 43
	SrtLogFAChnMgmt   SrtLogFA = 44
	SrtLogFAGrpMgmt   SrtLogFA = 45
	SrtLogFAEPollAPI  SrtLogFA = 46
)

var (
	logCBPtr     unsafe.Pointer = nil
	logCBPtrLock sync.Mutex
)

//export srtLogCBWrapper
func srtLogCBWrapper(arg unsafe.Pointer, level C.int, file *C.char, line C.int, area, message *C.char) {
	userCB := gopointer.Restore(arg).(LogCallBackFunc)
	// Call directly instead of creating a new goroutine to reduce overhead
	// The user callback should handle any necessary async processing
	userCB(SrtLogLevel(level), C.GoString(file), int(line), C.GoString(area), C.GoString(message))
}

func SrtSetLogLevel(level SrtLogLevel) {
	C.srt_setloglevel(C.int(level))
}

func SrtSetLogHandler(cb LogCallBackFunc) {
	ptr := gopointer.Save(cb)
	C.srt_setloghandler(ptr, (*C.SRT_LOG_HANDLER_FN)(C.srtLogCB))
	storeLogCBPtr(ptr)
}

func SrtUnsetLogHandler() {
	C.srt_setloghandler(nil, nil)
	storeLogCBPtr(nil)
}

func storeLogCBPtr(ptr unsafe.Pointer) {
	logCBPtrLock.Lock()
	defer logCBPtrLock.Unlock()
	if logCBPtr != nil {
		gopointer.Unref(logCBPtr)
	}
	logCBPtr = ptr
}

func SrtAddLogFA(fa SrtLogFA) {
	C.srt_addlogfa(C.int(fa))
}

func SrtDelLogFA(fa SrtLogFA) {
	C.srt_dellogfa(C.int(fa))
}

func SrtResetLogFA(falist []SrtLogFA) {
	if len(falist) == 0 {
		C.srt_resetlogfa(nil, 0)
		return
	}

	cArray := make([]C.int, len(falist))
	for i, fa := range falist {
		cArray[i] = C.int(fa)
	}
	C.srt_resetlogfa(&cArray[0], C.size_t(len(cArray)))
}
