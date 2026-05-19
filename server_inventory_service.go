package main

import (
	"database/sql"
	"errors"
	"os"
	"sync"

	serverpkg "debian-updater/internal/servers"

	"golang.org/x/crypto/ssh"
)

type Server = serverpkg.Server
type ServerStatus = serverpkg.ServerStatus
type PendingUpdate = serverpkg.PendingUpdate
type ServerInventoryService = serverpkg.Service
type serverInventoryActionError = serverpkg.ActionError

//lint:ignore U1000 compatibility alias retained for transitional host-key call sites.
type serverHostKeyScanResult = serverpkg.HostKeyScanResult

//lint:ignore U1000 compatibility alias retained for transitional host-key call sites.
type serverHostKeyTrustResult = serverpkg.HostKeyTrustResult

//lint:ignore U1000 compatibility alias retained for transitional host-key call sites.
type serverHostKeyClearResult = serverpkg.HostKeyClearResult

var (
	errServerRequiredFields = serverpkg.ErrRequiredFields
	errInvalidSSHUsername   = serverpkg.ErrInvalidSSHUsername
	errServerNameExists     = serverpkg.ErrNameExists
	errServerHostExists     = serverpkg.ErrHostExists
	errServerNotFound       = serverpkg.ErrNotFound
	errActionInProgress     = serverpkg.ErrActionInProgress
	errFingerprintMismatch  = serverpkg.ErrFingerprintMismatch
)

func newServerState() *serverpkg.State {
	return serverpkg.NewState(&mu, &servers, &statusMap, statusInProgress)
}

func newServerInventoryService() *ServerInventoryService {
	return serverpkg.NewService(serverpkg.ServiceDeps{
		State: newServerState(),
		Repository: serverpkg.SQLiteRepository{
			DB:      getDB,
			Encrypt: encryptSecret,
			Decrypt: decryptSecret,
		},
		KnownHosts: serverpkg.KnownHostsDeps{
			DBPath:              dbPath,
			UserHomeDir:         os.UserHomeDir,
			Getenv:              os.Getenv,
			ScanHostKey:         func(host string, port int) (ssh.PublicKey, error) { return scanHostKeyFunc(host, port) },
			KnownHostsMu:        &knownHostsMu,
			SSHConnectTimeout:   sshConnectTimeout,
			ConstantTimeCompare: stringsEqualConstantTime,
		},
		PrunePolicyOverridesForServers: pruneUpdatePolicyOverridesForServersTx,
		RenamePolicyOverridesServer:    renameUpdatePolicyOverridesServerTx,
		RenamePolicyTargetServers:      renameUpdatePolicyTargetServersTx,
		RenameServerFacts:              renameServerFactsTx,
		DeleteServerFacts:              defaultServerFactsRepository().DeleteServerTx,
	})
}

var (
	servers                []Server
	statusMap              = make(map[string]*ServerStatus)
	mu                     sync.Mutex
	knownHostsMu           sync.Mutex
	scanHostKeyFunc        = scanHostKey
	serverState            = newServerState()
	serverInventoryService = newServerInventoryService()
)

func init() {
	serverInventoryService.SetLegacyImport(loadLegacyServers)
	serverInventoryService.SetSaveOverride(func() error { return saveServersFunc() })
}

func serverInventoryTxHook(txHook saveServersTxHook) serverpkg.TxHook {
	if txHook == nil {
		return nil
	}
	return func(tx *sql.Tx) error {
		return txHook(tx)
	}
}

//lint:ignore U1000 compatibility wrapper retained for transitional server inventory call sites.
func newIdleServerStatus(server Server) *ServerStatus {
	return serverpkg.NewIdleStatus(server)
}

//lint:ignore U1000 compatibility wrapper retained for transitional server inventory call sites.
func updateStatusFromServer(name string, server Server) {
	serverpkg.UpdateStatusFromServer(statusMap, name, server)
}

func serverInventoryActionStatus(err error) string {
	var actionErr serverInventoryActionError
	if errors.As(err, &actionErr) {
		return actionErr.Status
	}
	return ""
}

func parseTags(raw string) []string {
	return serverpkg.ParseTags(raw)
}

func joinTags(tags []string) string {
	return serverpkg.JoinTags(tags)
}

func normalizePort(port int) int {
	return serverpkg.NormalizePort(port)
}

//lint:ignore U1000 compatibility wrapper retained for transitional server inventory call sites.
func normalizeServerName(value string) string {
	return serverpkg.NormalizeServerName(value)
}

//lint:ignore U1000 compatibility wrapper retained for transitional server inventory call sites.
func normalizeServerHost(value string) string {
	return serverpkg.NormalizeServerHost(value)
}

func serverNameExistsLocked(name string, skipIndex int) bool {
	return serverpkg.ServerNameExists(servers, name, skipIndex)
}

func serverHostExistsLocked(host string, skipIndex int) bool {
	return serverpkg.ServerHostExists(servers, host, skipIndex)
}

func knownHostsPaths() []string {
	return serverpkg.KnownHostsPaths(defaultKnownHostsDeps())
}

//lint:ignore U1000 compatibility wrapper retained for transitional known_hosts call sites.
func knownHostsDefaultWritePath() string {
	return serverpkg.KnownHostsDefaultWritePath(defaultKnownHostsDeps())
}

func getHostKeyCallback() (ssh.HostKeyCallback, error) {
	return serverpkg.HostKeyCallback(defaultKnownHostsDeps())
}

func knownHostsWritePath() (string, error) {
	return serverpkg.KnownHostsWritePath(defaultKnownHostsDeps())
}

//lint:ignore U1000 compatibility wrapper retained for transitional known_hosts call sites.
func knownHostsHostToken(host string, port int) string {
	return serverpkg.KnownHostsHostToken(host, port)
}

func appendKnownHostLine(line string) (bool, error) {
	return serverpkg.AppendKnownHostLine(defaultKnownHostsDeps(), line)
}

func knownHostLineExists(line string) (bool, error) {
	return serverpkg.KnownHostLineExists(defaultKnownHostsDeps(), line)
}

func removeKnownHostEntries(host string, port int) (int, error) {
	return serverpkg.RemoveKnownHostEntries(defaultKnownHostsDeps(), host, port)
}

func scanHostKey(host string, port int) (ssh.PublicKey, error) {
	return serverpkg.ScanHostKey(host, port, sshConnectTimeout)
}

//lint:ignore U1000 compatibility wrapper retained for transitional known_hosts call sites.
func buildKnownHostsLine(host string, port int, key ssh.PublicKey) string {
	return serverpkg.BuildKnownHostsLine(host, port, key)
}

func trustHostKey(host string, port int, expectedFingerprint string) (string, string, bool, error) {
	return serverpkg.TrustHostKey(defaultKnownHostsDeps(), host, port, expectedFingerprint)
}

//lint:ignore U1000 compatibility wrapper retained for transitional server inventory call sites.
func isValidSSHUsername(username string) bool {
	return serverpkg.IsValidSSHUsername(username)
}

func buildAuthMethods(server Server) ([]ssh.AuthMethod, error) {
	return serverpkg.BuildAuthMethods(server, getGlobalKey)
}

//lint:ignore U1000 compatibility wrapper retained for transitional server inventory call sites.
func updateServerKey(name, key string) error {
	return serverInventoryService.UpdateServerKey(name, key)
}

func defaultKnownHostsDeps() serverpkg.KnownHostsDeps {
	return serverpkg.KnownHostsDeps{
		DBPath:              dbPath,
		UserHomeDir:         os.UserHomeDir,
		Getenv:              os.Getenv,
		ScanHostKey:         func(host string, port int) (ssh.PublicKey, error) { return scanHostKeyFunc(host, port) },
		KnownHostsMu:        &knownHostsMu,
		SSHConnectTimeout:   sshConnectTimeout,
		ConstantTimeCompare: stringsEqualConstantTime,
	}
}
