package cmd

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ropnop/gokrb5/v8/iana/errorcode"
	"github.com/ropnop/gokrb5/v8/iana/nametype"
	"github.com/ropnop/gokrb5/v8/messages"
	"github.com/ropnop/gokrb5/v8/types"
)

// mockKDC is a minimal Kerberos KDC used for testing. It answers every AS-REQ
// with a KRB_ERROR: KDC_ERR_PREAUTH_REQUIRED for usernames in the valid set
// (i.e. the user exists) and KDC_ERR_C_PRINCIPAL_UNKNOWN for everyone else.
type mockKDC struct {
	realm string
	valid map[string]bool

	tcpListener net.Listener
	udpConn     *net.UDPConn
	done        chan struct{}
	wg          sync.WaitGroup
}

func newMockKDC(realm string, valid map[string]bool) (*mockKDC, error) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		tcpListener.Close()
		return nil, err
	}
	m := &mockKDC{
		realm:       realm,
		valid:       valid,
		tcpListener: tcpListener,
		udpConn:     udpConn,
		done:        make(chan struct{}),
	}
	m.wg.Add(2)
	go m.serveTCP()
	go m.serveUDP()
	return m, nil
}

func (m *mockKDC) addr() string {
	return m.tcpListener.Addr().String()
}

func (m *mockKDC) close() {
	close(m.done)
	m.tcpListener.Close()
	m.udpConn.Close()
	m.wg.Wait()
}

func (m *mockKDC) serveTCP() {
	defer m.wg.Done()
	for {
		conn, err := m.tcpListener.Accept()
		if err != nil {
			return
		}
		go m.handleTCPConn(conn)
	}
}

func (m *mockKDC) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	payload := make([]byte, binary.BigEndian.Uint32(header))
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}
	resp := m.handleASReq(payload)
	if resp == nil {
		return
	}
	binary.BigEndian.PutUint32(header, uint32(len(resp)))
	conn.Write(append(header, resp...))
}

func (m *mockKDC) serveUDP() {
	defer m.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, addr, err := m.udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if resp := m.handleASReq(buf[:n]); resp != nil {
			m.udpConn.WriteToUDP(resp, addr)
		}
	}
}

func (m *mockKDC) handleASReq(b []byte) []byte {
	var asreq messages.ASReq
	if err := asreq.Unmarshal(b); err != nil {
		return nil
	}
	username := strings.ToLower(asreq.ReqBody.CName.PrincipalNameString())
	code := errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN
	if m.valid[username] {
		code = errorcode.KDC_ERR_PREAUTH_REQUIRED
	}
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+m.realm)
	krbErr := messages.NewKRBError(sname, m.realm, code, "mock KDC")
	resp, err := krbErr.Marshal()
	if err != nil {
		return nil
	}
	return resp
}

// setupEnumTest resets the package-level state, points kerbrute at the mock
// KDC and returns the paths of the generated wordlist and the log file.
func setupEnumTest(t *testing.T, kdc *mockKDC, totalUsers int, rate int) (wordlistPath, logPath string) {
	t.Helper()

	dir := t.TempDir()
	wordlistPath = filepath.Join(dir, "users.txt")
	logPath = filepath.Join(dir, "kerbrute.log")

	var wordlist strings.Builder
	for i := 0; i < totalUsers; i++ {
		fmt.Fprintf(&wordlist, "testuser%04d\n", i)
	}
	if err := os.WriteFile(wordlistPath, []byte(wordlist.String()), 0644); err != nil {
		t.Fatalf("could not write wordlist: %v", err)
	}

	domain = "contoso.com"
	domainController = kdc.addr()
	verbose = false
	safe = false
	downgrade = false
	hashFileName = ""
	logFileName = logPath
	threads = 10
	delay = 0
	rateLimit = rate
	atomic.StoreInt32(&counter, 0)
	atomic.StoreInt32(&successes, 0)
	ctx, cancel = context.WithCancel(context.Background())
	t.Cleanup(cancel)

	setupSession(nil, nil)
	return wordlistPath, logPath
}

// checkEnumOutput verifies the log output keeps the existing kerbrute format.
func checkEnumOutput(t *testing.T, logPath string, totalUsers, validUsers int) {
	t.Helper()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("could not read log file: %v", err)
	}
	output := string(content)

	validLine := regexp.MustCompile(`(?m)^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} >  \[\+] VALID USERNAME:\s+testuser\d{4}@contoso\.com$`)
	if matches := validLine.FindAllString(output, -1); len(matches) != validUsers {
		t.Errorf("expected %d '[+] VALID USERNAME:' lines, got %d", validUsers, len(matches))
	}

	summary := fmt.Sprintf("Done! Tested %d usernames (%d valid)", totalUsers, validUsers)
	if !strings.Contains(output, summary) {
		t.Errorf("expected summary line %q in output", summary)
	}
}

func validUserSet(every int, totalUsers int) map[string]bool {
	valid := make(map[string]bool)
	for i := 0; i < totalUsers; i++ {
		if i%every == 0 {
			valid[fmt.Sprintf("testuser%04d", i)] = true
		}
	}
	return valid
}

// TestUserEnum1000Users enumerates 1000 users against the mock KDC with no
// rate limit and verifies every valid user is found with compatible output.
func TestUserEnum1000Users(t *testing.T) {
	const totalUsers = 1000
	valid := validUserSet(10, totalUsers) // 100 valid users

	kdc, err := newMockKDC("CONTOSO.COM", valid)
	if err != nil {
		t.Fatalf("could not start mock KDC: %v", err)
	}
	defer kdc.close()

	wordlistPath, logPath := setupEnumTest(t, kdc, totalUsers, 0)

	userEnum(nil, []string{wordlistPath})

	if got := atomic.LoadInt32(&counter); got != totalUsers {
		t.Errorf("expected %d tested usernames, got %d", totalUsers, got)
	}
	if got := atomic.LoadInt32(&successes); got != int32(len(valid)) {
		t.Errorf("expected %d valid usernames, got %d", len(valid), got)
	}
	checkEnumOutput(t, logPath, totalUsers, len(valid))
}

// TestUserEnum1000UsersRateLimited enumerates the same 1000 users with
// --rate set and verifies the limiter actually paces the requests while
// producing identical results and output.
func TestUserEnum1000UsersRateLimited(t *testing.T) {
	const totalUsers = 1000
	const rate = 500 // requests/second -> ~2s minimum for 1000 users
	valid := validUserSet(10, totalUsers)

	kdc, err := newMockKDC("CONTOSO.COM", valid)
	if err != nil {
		t.Fatalf("could not start mock KDC: %v", err)
	}
	defer kdc.close()

	wordlistPath, logPath := setupEnumTest(t, kdc, totalUsers, rate)

	start := time.Now()
	userEnum(nil, []string{wordlistPath})
	elapsed := time.Since(start)

	if got := atomic.LoadInt32(&counter); got != totalUsers {
		t.Errorf("expected %d tested usernames, got %d", totalUsers, got)
	}
	if got := atomic.LoadInt32(&successes); got != int32(len(valid)) {
		t.Errorf("expected %d valid usernames, got %d", len(valid), got)
	}

	minDuration := time.Duration(float64(totalUsers) / float64(rate) * 0.75 * float64(time.Second))
	if elapsed < minDuration {
		t.Errorf("rate limit not enforced: %d users at %d req/s finished in %v, expected at least %v", totalUsers, rate, elapsed, minDuration)
	}

	checkEnumOutput(t, logPath, totalUsers, len(valid))
}
