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
	var stateMu sync.Mutex
	stateServers := []Server{}
	stateStatusMap := map[string]*ServerStatus{}
	return serverpkg.NewState(&stateMu, &stateServers, &stateStatusMap, statusInProgress)
}

func newServerInventoryService() *ServerInventoryService {
	return newServerInventoryServiceWithStateAndDB(globalServerState(), getDB)
}

func globalServerState() *serverpkg.State {
	return serverpkg.NewState(&mu, &servers, &statusMap, statusInProgress)
}

func newServerInventoryServiceWithState(state *serverpkg.State) *ServerInventoryService {
	return newServerInventoryServiceWithStateAndDB(state, getDB)
}

func newServerInventoryServiceWithStateAndDB(state *serverpkg.State, dbProvider func() *sql.DB) *ServerInventoryService {
	return newServerInventoryServiceWithStateDBPath(state, dbProvider, dbPath)
}

func newServerInventoryServiceWithStateDBPath(state *serverpkg.State, dbProvider func() *sql.DB, dbPathProvider func() string) *ServerInventoryService {
	if state == nil {
		state = newServerState()
	}
	if dbProvider == nil {
		dbProvider = getDB
	}
	if dbPathProvider == nil {
		dbPathProvider = dbPath
	}
	var service *ServerInventoryService = serverpkg.NewService(serverpkg.ServiceDeps{
		State: state,
		Repository: serverpkg.SQLiteRepository{
			DB:      dbProvider,
			Encrypt: encryptSecret,
			Decrypt: decryptSecret,
		},
		KnownHosts:                     appKnownHostsDeps(dbPathProvider),
		PrunePolicyOverridesForServers: pruneUpdatePolicyOverridesForServersTx,
		RenamePolicyOverridesServer:    renameUpdatePolicyOverridesServerTx,
		RenamePolicyTargetServers:      renameUpdatePolicyTargetServersTx,
		RenameServerFacts:              renameServerFactsTx,
		DeleteServerFacts:              defaultServerFactsRepository().DeleteServerTx,
	})
	service.SetLegacyImport(func() bool {
		return loadLegacyServersIntoService(service, state)
	})
	return service
}

func appKnownHostsDeps(dbPathProvider func() string) serverpkg.KnownHostsDeps {
	if dbPathProvider == nil {
		dbPathProvider = dbPath
	}
	return serverpkg.KnownHostsDeps{
		DBPath:              dbPathProvider,
		UserHomeDir:         os.UserHomeDir,
		Getenv:              os.Getenv,
		ScanHostKey:         func(host string, port int) (ssh.PublicKey, error) { return scanHostKeyFunc(host, port) },
		KnownHostsMu:        &knownHostsMu,
		SSHConnectTimeout:   sshConnectTimeout,
		ConstantTimeCompare: stringsEqualConstantTime,
	}
}

func initializeServerStateStatuses(state *serverpkg.State) {
	if state == nil {
		return
	}
	state.Lock()
	defer state.Unlock()
	servers := state.Servers()
	statuses := make(map[string]*ServerStatus, len(servers))
	for _, server := range servers {
		statuses[server.Name] = serverpkg.NewIdleStatus(server)
	}
	state.SetStatusMap(statuses)
}

var (
	servers         []Server
	statusMap       = make(map[string]*ServerStatus)
	mu              sync.Mutex
	knownHostsMu    sync.Mutex
	scanHostKeyFunc = scanHostKey
)

func serverInventoryTxHook(txHook saveServersTxHook) serverpkg.TxHook {
	if txHook == nil {
		return nil
	}
	return func(tx *sql.Tx) error {
		return txHook(tx)
	}
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

func serverNameExistsLocked(name string, skipIndex int) bool {
	return serverpkg.ServerNameExists(servers, name, skipIndex)
}

func serverHostExistsLocked(host string, skipIndex int) bool {
	return serverpkg.ServerHostExists(servers, host, skipIndex)
}

func knownHostsPaths() []string {
	return serverpkg.KnownHostsPaths(defaultKnownHostsDeps())
}

func getHostKeyCallback() (ssh.HostKeyCallback, error) {
	return serverpkg.HostKeyCallback(defaultKnownHostsDeps())
}

func knownHostsWritePath() (string, error) {
	return serverpkg.KnownHostsWritePath(defaultKnownHostsDeps())
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

func trustHostKey(host string, port int, expectedFingerprint string) (string, string, bool, error) {
	return serverpkg.TrustHostKey(defaultKnownHostsDeps(), host, port, expectedFingerprint)
}

func buildAuthMethods(server Server) ([]ssh.AuthMethod, error) {
	return serverpkg.BuildAuthMethods(server, getGlobalKey)
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
