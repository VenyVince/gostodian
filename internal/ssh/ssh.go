package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// StatusCommand는 게이트에 보내는 동사다. 경로나 셸 문자열로 조립하지 않는다.
const StatusCommand = "status"

// 접속 실패 종류. 재시도 없이 바로 반환.
var (
	// ErrAuthFailed는 키나 계정이 거부된 경우
	ErrAuthFailed = errors.New("auth_failed")
	// ErrHostUnreachable는 제한 시간 초과, 연결 거부, 그 밖의 망 문제
	ErrHostUnreachable = errors.New("host_unreachable")
	// ErrHostKeyMismatch는 known_hosts와 다른 호스트 키로 접속이 거부된 경우
	ErrHostKeyMismatch = errors.New("host_key_mismatch")
)

// Client는 접속에 필요한 값만 가짐. New에서는 접속하지 않음
type Client struct {
	host           string
	port           int
	user           string
	identityFile   string
	knownHostsFile string
	timeout        time.Duration
}

func New(host string, port int, user, identityFile, knownHostsFile string, timeout time.Duration) *Client {
	return &Client{
		host:           host,
		port:           port,
		user:           user,
		identityFile:   identityFile,
		knownHostsFile: knownHostsFile,
		timeout:        timeout,
	}
}

// Result는 명령 하나의 결과
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Run은 StatusCommand만 보내고 출력을 돌려준다. 호출자가 명령을 고르지 않는다.
// authorized_keys의 command=가 있으면 이 문자열은 SSH_ORIGINAL_COMMAND로만 전달되고, 실행 파일은 GatePath다.
func (c *Client) Run() (result Result, err error) {
	privateKey, err := os.ReadFile(c.identityFile)
	if err != nil {
		return Result{}, err
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return Result{}, err
	}

	hostKeyCallback, err := knownhosts.New(c.knownHostsFile)
	if err != nil {
		return Result{}, err
	}

	clientConfig := &ssh.ClientConfig{
		User:            c.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         c.timeout,
	}

	conn, err := ssh.Dial("tcp", c.address(), clientConfig)
	if err != nil {
		return Result{}, classifyDial(err)
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil && !errors.Is(cerr, io.EOF) && err == nil {
			err = cerr
		}
	}()

	session, err := conn.NewSession()
	if err != nil {
		return Result{}, classifyDial(err)
	}
	defer func() {
		if cerr := session.Close(); cerr != nil && !errors.Is(cerr, io.EOF) && err == nil {
			err = cerr
		}
	}()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	runErr := session.Run(StatusCommand)
	result = Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if runErr == nil {
		return result, nil
	}

	var exitErr *ssh.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitStatus()
		return result, nil
	}
	return result, classifyDial(runErr)
}

func (c *Client) address() string {
	return net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// classifyDial은 접속 에러를 auth_failed, host_unreachable, host_key_mismatch로 분류한다.
// 호스트 키가 다르면 검증을 끄지 않고 접속을 실패로 남긴다.
func classifyDial(err error) error {
	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) {
		return fmt.Errorf("%w: %w", ErrHostKeyMismatch, err)
	}

	if isAuthFailed(err) {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	if isHostUnreachable(err) {
		return fmt.Errorf("%w: %w", ErrHostUnreachable, err)
	}
	return err
}

func isAuthFailed(err error) bool {
	var authErr ssh.ServerAuthError
	if errors.As(err, &authErr) {
		return true
	}
	// 클라이언트는 ServerAuthError 대신 이 문장을 반환
	return strings.Contains(err.Error(), "unable to authenticate")
}

func isHostUnreachable(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	return false
}
