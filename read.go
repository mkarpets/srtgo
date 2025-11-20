package srtgo

/*
#cgo LDFLAGS: -lsrt
#include <srt/srt.h>

int srt_recvmsg2_wrapped(SRTSOCKET u, char* buf, int len, SRT_MSGCTRL *mctrl, int *srterror, int *syserror)
{
	int ret = srt_recvmsg2(u, buf, len, mctrl);
	if (ret < 0) {
		*srterror = srt_getlasterror(syserror);
	}
	return ret;
}

*/
import "C"
import (
	"errors"
	"syscall"
	"unsafe"
)

func srtRecvMsg2Impl(u C.SRTSOCKET, buf []byte, msgctrl *C.SRT_MSGCTRL) (n int, err error) {
	srterr := C.int(0)
	syserr := C.int(0)
	n = int(C.srt_recvmsg2_wrapped(u, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)), msgctrl, &srterr, &syserr))
	if n < 0 {
		srterror := SRTErrno(srterr)
		if syserr < 0 {
			srterror.wrapSysErr(syscall.Errno(syserr))
		}
		err = srterror
		n = 0
	}
	return
}

// Read data from the SRT socket
func (s SrtSocket) Read(b []byte) (n int, err error) {
	// Fast path: try reading immediately
	n, err = srtRecvMsg2Impl(s.socket, b, nil)

	// If successful or blocking mode, return immediately
	if err == nil || s.blocking || !errors.Is(err, error(EAsyncRCV)) {
		return
	}

	// Non-blocking mode: wait for data to be available
	if !s.blocking {
		s.pd.reset(ModeRead)
		if waitErr := s.pd.wait(ModeRead); waitErr != nil {
			return 0, waitErr
		}
		// Try reading again after waiting
		n, err = srtRecvMsg2Impl(s.socket, b, nil)
	}

	return
}

// ReadBatch attempts to read multiple packets in a batched manner to reduce syscall overhead
// It tries to read up to maxPackets into the provided buffer slice
// Returns the number of packets successfully read
// This is useful for high-throughput scenarios where reducing syscall overhead is critical
func (s SrtSocket) ReadBatch(buffer []byte, maxPackets int) (packetsRead int, totalBytes int, err error) {
	if maxPackets <= 0 || len(buffer) == 0 {
		return 0, 0, nil
	}

	offset := 0
	for packetsRead = 0; packetsRead < maxPackets && offset < len(buffer); packetsRead++ {
		// Try to read a packet
		n, readErr := srtRecvMsg2Impl(s.socket, buffer[offset:], nil)

		if readErr != nil {
			// If this is the first packet and we got ASYNCRCV, wait for data
			if packetsRead == 0 && !s.blocking && errors.Is(readErr, error(EAsyncRCV)) {
				s.pd.reset(ModeRead)
				if waitErr := s.pd.wait(ModeRead); waitErr != nil {
					return 0, 0, waitErr
				}
				// Try one more time after waiting
				n, readErr = srtRecvMsg2Impl(s.socket, buffer[offset:], nil)
			}

			if readErr != nil {
				// If we've read at least one packet successfully, return those
				// Otherwise return the error
				if packetsRead > 0 {
					return packetsRead, totalBytes, nil
				}
				return 0, 0, readErr
			}
		}

		if n == 0 {
			// No more data available
			break
		}

		offset += n
		totalBytes += n
	}

	return packetsRead, totalBytes, nil
}
