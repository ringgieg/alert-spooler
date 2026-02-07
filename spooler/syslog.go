package spooler

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type SyslogSender interface {
	SendRFC5424Timeout(appName string, structuredData string, message string, timeout time.Duration) error
}

type SyslogClient struct {
	addr string
}

func NewSyslogClient(addr string) *SyslogClient {
	return &SyslogClient{addr: addr}
}

func (c *SyslogClient) SendRFC5424(appName string, structuredData string, message string) error {
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}

	pri := 134 // local0.info
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if appName == "" {
		appName = "alert-spooler"
	}

	line := fmt.Sprintf("<%d>1 %s %s %s - - %s %s\n", pri, ts, sanitizeSyslogToken(host), sanitizeSyslogToken(appName), structuredData, strings.TrimSpace(message))

	w := bufio.NewWriter(conn)
	if _, err := w.WriteString(line); err != nil {
		return err
	}
	return w.Flush()
}

func (c *SyslogClient) SendRFC5424Timeout(appName string, structuredData string, message string, timeout time.Duration) error {
	if timeout <= 0 {
		return c.SendRFC5424(appName, structuredData, message)
	}

	conn, err := net.DialTimeout("tcp", c.addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}

	pri := 134 // local0.info
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if appName == "" {
		appName = "alert-spooler"
	}

	line := fmt.Sprintf("<%d>1 %s %s %s - - %s %s\n", pri, ts, sanitizeSyslogToken(host), sanitizeSyslogToken(appName), structuredData, strings.TrimSpace(message))

	w := bufio.NewWriter(conn)
	if _, err := w.WriteString(line); err != nil {
		return err
	}
	return w.Flush()
}

func sanitizeSyslogToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	s = strings.ReplaceAll(s, " ", "_")
	return s
}
