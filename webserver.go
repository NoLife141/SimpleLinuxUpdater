package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	_ "modernc.org/sqlite"
)

type Server struct {
	Name string   `json:"name"`
	Host string   `json:"host"`
	Port int      `json:"port"`
	User string   `json:"user"`
	Pass string   `json:"pass"`
	Key  string   `json:"-"`
	Tags []string `json:"tags"`
}

type ServerStatus struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	User        string   `json:"user"`
	Status      string   `json:"status"` // idle, updating, pending_approval, approved, cancelled, upgrading, autoremove, sudoers, done, error
	Logs        string   `json:"logs"`
	Upgradable  []string `json:"upgradable"`
	HasPassword bool     `json:"has_password"`
	HasKey      bool     `json:"has_key"`
	Tags        []string `json:"tags"`
}

var servers []Server
var statusMap = make(map[string]*ServerStatus)
var mu sync.Mutex

var db *sql.DB
var dbOnce sync.Once
var keyOnce sync.Once
var encryptionKey []byte
var globalKeyOnce sync.Once
var globalKey string
var knownHostsMu sync.Mutex
var scanHostKeyFunc = scanHostKey
var saveServersFunc = saveServers

const configFileName = "config.json"
const legacyServersFileName = "servers.json"
const globalKeySetting = "global_ssh_key"
const basicAuthUserEnv = "DEBIAN_UPDATER_BASIC_AUTH_USER"
const basicAuthPassEnv = "DEBIAN_UPDATER_BASIC_AUTH_PASS"
const maxUploadedKeyBytes = 64 * 1024
const sshConnectTimeout = 15 * time.Second

var errUploadedKeyTooLarge = errors.New("key file too large (max 64KB)")
var errUploadedKeyEmpty = errors.New("empty key")
var errActionInProgress = errors.New("action already in progress")
var errFingerprintMismatch = errors.New("host key fingerprint mismatch")

func dbPath() string {
	if p := strings.TrimSpace(os.Getenv("DEBIAN_UPDATER_DB_PATH")); p != "" {
		return p
	}
	if dirExists("/data") {
		return filepath.Join("/data", "servers.db")
	}
	return filepath.Join("data", "servers.db")
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func configPath() string {
	return filepath.Join(filepath.Dir(dbPath()), configFileName)
}

func getDB() *sql.DB {
	dbOnce.Do(func() {
		path := dbPath()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			log.Fatalf("Failed to create db directory: %v", err)
		}
		var err error
		db, err = sql.Open("sqlite", path)
		if err != nil {
			log.Fatalf("Failed to open sqlite db: %v", err)
		}
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS servers (
				name TEXT PRIMARY KEY,
				host TEXT NOT NULL,
				port INTEGER NOT NULL DEFAULT 22,
				user TEXT NOT NULL,
				pass_enc TEXT NOT NULL,
				key_enc TEXT NOT NULL DEFAULT '',
				key_path TEXT NOT NULL DEFAULT '',
				tags TEXT NOT NULL DEFAULT ''
			)
		`)
		if err != nil {
			log.Fatalf("Failed to initialize db schema: %v", err)
		}
		if err := ensureSchema(db); err != nil {
			log.Fatalf("Failed to migrate db schema: %v", err)
		}
	})
	return db
}

func getEncryptionKey() []byte {
	keyOnce.Do(func() {
		path := configPath()
		var cfg map[string]string
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, &cfg); err != nil {
				log.Fatalf("Failed to parse %s: %v", path, err)
			}
		} else if !os.IsNotExist(err) {
			log.Fatalf("Failed to read %s: %v", path, err)
		}

		keyStr := ""
		if cfg != nil {
			keyStr = strings.TrimSpace(cfg["encryption_key"])
		}

		if keyStr == "" {
			keyBytes := make([]byte, 32)
			if _, err := rand.Read(keyBytes); err != nil {
				log.Fatalf("Failed to generate encryption key: %v", err)
			}
			keyStr = base64.StdEncoding.EncodeToString(keyBytes)
			cfg = map[string]string{"encryption_key": keyStr}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				log.Fatalf("Failed to create config dir: %v", err)
			}
			data, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				log.Fatalf("Failed to serialize config: %v", err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				log.Fatalf("Failed to write %s: %v", path, err)
			}
		}

		keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil || len(keyBytes) != 32 {
			log.Fatalf("Invalid encryption_key in %s (must be base64 32 bytes)", path)
		}
		encryptionKey = keyBytes
	})
	return encryptionKey
}

func ensureSchema(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(servers)")
	if err != nil {
		return err
	}
	defer rows.Close()
	hasKeyPath := false
	hasKeyEnc := false
	hasTags := false
	hasPort := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "key_path" {
			hasKeyPath = true
		}
		if name == "key_enc" {
			hasKeyEnc = true
		}
		if name == "tags" {
			hasTags = true
		}
		if name == "port" {
			hasPort = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasKeyPath {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN key_path TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasKeyEnc {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN key_enc TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasTags {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN tags TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasPort {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN port INTEGER NOT NULL DEFAULT 22"); err != nil {
			return err
		}
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		return err
	}
	return nil
}

func encryptSecret(secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	block, err := aes.NewCipher(getEncryptionKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(nonce) + ":" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptSecret(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted value format")
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(getEncryptionKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func loadLegacyServers() bool {
	paths := []string{}
	if dirExists("/data") {
		paths = append(paths, filepath.Join("/data", legacyServersFileName))
	}
	paths = append(paths, legacyServersFileName)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var legacy []Server
		if err := json.Unmarshal(data, &legacy); err != nil {
			log.Printf("Failed to parse legacy %s: %v", path, err)
			continue
		}
		if len(legacy) == 0 {
			continue
		}
		servers = legacy
		if err := saveServersFunc(); err != nil {
			log.Printf("Failed to import legacy servers from %s: %v", path, err)
			continue
		}
		log.Printf("Imported legacy servers from %s", path)
		return true
	}
	return false
}

func loadServers() {
	db := getDB()
	rows, err := db.Query("SELECT name, host, port, user, pass_enc, key_enc, tags FROM servers ORDER BY name")
	if err != nil {
		log.Fatalf("Failed to load servers: %v", err)
	}
	defer rows.Close()

	servers = nil
	for rows.Next() {
		var name, host, user, passEnc, keyEnc, tags string
		var port int
		if err := rows.Scan(&name, &host, &port, &user, &passEnc, &keyEnc, &tags); err != nil {
			log.Fatalf("Failed to scan server row: %v", err)
		}
		pass, err := decryptSecret(passEnc)
		if err != nil {
			log.Fatalf("Failed to decrypt password for %s: %v", name, err)
		}
		key, err := decryptSecret(keyEnc)
		if err != nil {
			log.Fatalf("Failed to decrypt SSH key for %s: %v", name, err)
		}
		servers = append(servers, Server{
			Name: name,
			Host: host,
			Port: normalizePort(port),
			User: user,
			Pass: pass,
			Key:  key,
			Tags: parseTags(tags),
		})
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed to read servers: %v", err)
	}

	if len(servers) == 0 {
		if !loadLegacyServers() {
			servers = []Server{
				{Name: "server1", Host: "server1.example.com", Port: 22, User: "user", Pass: "pass"},
				{Name: "server2", Host: "server2.example.com", Port: 22, User: "user", Pass: "pass"},
				{Name: "server3", Host: "server3.example.com", Port: 22, User: "user", Pass: "pass"},
				{Name: "server4", Host: "server4.example.com", Port: 22, User: "user", Pass: "pass"},
				{Name: "server5", Host: "server5.example.com", Port: 22, User: "user", Pass: "pass"},
			}
			if err := saveServersFunc(); err != nil {
				log.Fatalf("Failed to save default servers: %v", err)
			}
		}
	}
}

func saveServers() error {
	db := getDB()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start db transaction: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM servers"); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("clear servers table: %w", err)
	}
	stmt, err := tx.Prepare("INSERT INTO servers (name, host, port, user, pass_enc, key_enc, tags) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()
	for _, server := range servers {
		enc, err := encryptSecret(server.Pass)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("encrypt password for %s: %w", server.Name, err)
		}
		keyEnc, err := encryptSecret(server.Key)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("encrypt SSH key for %s: %w", server.Name, err)
		}
		tags := joinTags(server.Tags)
		port := normalizePort(server.Port)
		if _, err := stmt.Exec(server.Name, server.Host, port, server.User, enc, keyEnc, tags); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert server %s: %w", server.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit servers: %w", err)
	}
	return nil
}

func saveServersOrRollbackLocked(prevServers []Server, prevStatusMap map[string]*ServerStatus) error {
	if err := saveServersFunc(); err != nil {
		servers = prevServers
		statusMap = prevStatusMap
		return err
	}
	return nil
}

func cloneServers(src []Server) []Server {
	if src == nil {
		return nil
	}
	dst := make([]Server, len(src))
	for i, server := range src {
		server.Tags = append([]string(nil), server.Tags...)
		dst[i] = server
	}
	return dst
}

func cloneStatusMap(src map[string]*ServerStatus) map[string]*ServerStatus {
	dst := make(map[string]*ServerStatus, len(src))
	for name, status := range src {
		if status == nil {
			dst[name] = nil
			continue
		}
		copyStatus := *status
		copyStatus.Upgradable = append([]string(nil), status.Upgradable...)
		copyStatus.Tags = append([]string(nil), status.Tags...)
		dst[name] = &copyStatus
	}
	return dst
}

func statusInProgress(status string) bool {
	return status == "updating" ||
		status == "pending_approval" ||
		status == "approved" ||
		status == "upgrading" ||
		status == "autoremove" ||
		status == "sudoers"
}

func findServerByNameLocked(name string) (Server, bool) {
	for _, s := range servers {
		if s.Name == name {
			return s, true
		}
	}
	return Server{}, false
}

func beginServerAction(name, newStatus string) (Server, error) {
	mu.Lock()
	defer mu.Unlock()
	status, exists := statusMap[name]
	if !exists || status == nil {
		return Server{}, sql.ErrNoRows
	}
	if statusInProgress(status.Status) {
		return Server{}, errActionInProgress
	}
	server, found := findServerByNameLocked(name)
	if !found {
		return Server{}, sql.ErrNoRows
	}
	status.Status = newStatus
	if strings.TrimSpace(status.Logs) == "" {
		status.Logs = "Starting Linux Updater..."
	}
	return server, nil
}

func readUploadedKeyData(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxUploadedKeyBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxUploadedKeyBytes {
		return "", errUploadedKeyTooLarge
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", errUploadedKeyEmpty
	}
	return key, nil
}

func readUploadedPrivateKey(file *multipart.FileHeader) (string, error) {
	if file.Size > maxUploadedKeyBytes {
		return "", errUploadedKeyTooLarge
	}
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()
	return readUploadedKeyData(src)
}

func stringsEqualConstantTime(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func basicAuthMiddleware(username, password string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok || !stringsEqualConstantTime(user, username) || !stringsEqualConstantTime(pass, password) {
			c.Header("WWW-Authenticate", `Basic realm="SimpleLinuxUpdater"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func basicAuthFromEnv() (string, string, bool, error) {
	username := strings.TrimSpace(os.Getenv(basicAuthUserEnv))
	password := os.Getenv(basicAuthPassEnv)
	if username == "" && password == "" {
		return "", "", false, nil
	}
	if username == "" || password == "" {
		return "", "", false, fmt.Errorf("%s and %s must both be set", basicAuthUserEnv, basicAuthPassEnv)
	}
	return username, password, true, nil
}

func init() {
	loadServers()
	for _, s := range servers {
		statusMap[s.Name] = &ServerStatus{
			Name:        s.Name,
			Host:        s.Host,
			Port:        normalizePort(s.Port),
			User:        s.User,
			Status:      "idle",
			Logs:        "",
			Upgradable:  []string{},
			HasPassword: s.Pass != "",
			HasKey:      s.Key != "",
			Tags:        s.Tags,
		}
	}
}

func runUpdate(server Server) {
	mu.Lock()
	status := statusMap[server.Name]
	if status == nil {
		mu.Unlock()
		return
	}
	status.Status = "updating"
	status.Logs = "Starting Linux Updater...\nRunning apt update..."
	mu.Unlock()

	authMethods, err := buildAuthMethods(server)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("Auth setup failed: %v", err)
		mu.Unlock()
		return
	}
	hostKeyCallback, err := getHostKeyCallback()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("Host key verification setup failed: %v", err)
		mu.Unlock()
		return
	}
	config := &ssh.ClientConfig{
		User:            server.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(server.Host, strconv.Itoa(normalizePort(server.Port))), config)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("SSH connection failed: %v", err)
		mu.Unlock()
		return
	}
	defer client.Close()

	// Run apt update
	session, err := client.NewSession()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("SSH session failed: %v", err)
		mu.Unlock()
		return
	}
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	err = session.Run("sudo apt update")
	session.Close()
	logs := stdout.String() + stderr.String()
	if err != nil {
		logs += fmt.Sprintf("\nError: %v", err)
		mu.Lock()
		status.Status = "error"
		status.Logs = logs
		mu.Unlock()
		return
	}

	// Get upgradable
	upgradable, err := getUpgradable(client)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = logs + fmt.Sprintf("\nError listing upgradable: %v", err)
		mu.Unlock()
		return
	}

	if len(upgradable) == 0 {
		mu.Lock()
		status.Status = "done"
		status.Logs = logs + "\nNo packages to upgrade."
		mu.Unlock()
		return
	}

	// Set pending approval
	mu.Lock()
	status.Status = "pending_approval"
	status.Upgradable = upgradable
	status.Logs = logs + "\nUpgradable packages:\n" + strings.Join(upgradable, "\n")
	mu.Unlock()

	// Wait for approval
	for {
		time.Sleep(1 * time.Second)
		mu.Lock()
		if status.Status == "approved" {
			mu.Unlock()
			break
		}
		if status.Status == "cancelled" {
			status.Status = "idle"
			mu.Unlock()
			return
		}
		mu.Unlock()
	}

	// Proceed with upgrade
	mu.Lock()
	status.Status = "upgrading"
	status.Logs += "\nRunning apt upgrade..."
	mu.Unlock()

	session, err = client.NewSession()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs += fmt.Sprintf("\nSSH session failed: %v", err)
		mu.Unlock()
		return
	}
	defer session.Close()

	stdout.Reset()
	stderr.Reset()
	session.Stdout = &stdout
	session.Stderr = &stderr
	err = session.Run("sudo apt upgrade -y")
	mu.Lock()
	currentLogs := status.Logs
	mu.Unlock()
	logs = currentLogs + "\n" + stdout.String() + stderr.String()
	if err != nil {
		logs += fmt.Sprintf("\nError: %v", err)
		mu.Lock()
		status.Status = "error"
		status.Logs = logs
		mu.Unlock()
		return
	}

	mu.Lock()
	status.Status = "done"
	status.Logs = logs + "\nUpgrade completed."
	mu.Unlock()
}

func runSudoersBootstrap(server Server, sudoPassword string) {
	mu.Lock()
	status := statusMap[server.Name]
	if status == nil {
		mu.Unlock()
		return
	}
	status.Status = "sudoers"
	if strings.TrimSpace(status.Logs) == "" {
		status.Logs = "Starting Linux Updater..."
	}
	status.Logs += "\nConfiguring passwordless apt sudoers..."
	mu.Unlock()

	authMethods, err := buildAuthMethods(server)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("Auth setup failed: %v", err)
		mu.Unlock()
		return
	}
	hostKeyCallback, err := getHostKeyCallback()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("Host key verification setup failed: %v", err)
		mu.Unlock()
		return
	}
	config := &ssh.ClientConfig{
		User:            server.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(server.Host, strconv.Itoa(normalizePort(server.Port))), config)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("SSH connection failed: %v", err)
		mu.Unlock()
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs += fmt.Sprintf("\nSSH session failed: %v", err)
		mu.Unlock()
		return
	}
	defer session.Close()

	line := fmt.Sprintf("%s ALL=(root) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get", server.User)
	escapedLine := shellEscapeSingleQuotes(line)
	cmd := fmt.Sprintf("sudo -S -p '' sh -c \"printf '%%s\\n' '%s' > /etc/sudoers.d/apt-nopasswd && chmod 440 /etc/sudoers.d/apt-nopasswd && /usr/sbin/visudo -cf /etc/sudoers.d/apt-nopasswd\"", escapedLine)

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	session.Stdin = strings.NewReader(sudoPassword + "\n")
	err = session.Run(cmd)
	mu.Lock()
	currentLogs := status.Logs
	mu.Unlock()
	logs := currentLogs + "\n" + stdout.String() + stderr.String()
	if err != nil {
		logs += fmt.Sprintf("\nError: %v", err)
		mu.Lock()
		status.Status = "error"
		status.Logs = logs
		mu.Unlock()
		return
	}

	mu.Lock()
	status.Status = "done"
	status.Logs = logs + "\nPasswordless apt sudoers enabled."
	mu.Unlock()
}

func runSudoersDisable(server Server, sudoPassword string) {
	mu.Lock()
	status := statusMap[server.Name]
	if status == nil {
		mu.Unlock()
		return
	}
	status.Status = "sudoers"
	if strings.TrimSpace(status.Logs) == "" {
		status.Logs = "Starting Linux Updater..."
	}
	status.Logs += "\nDisabling passwordless apt sudoers..."
	mu.Unlock()

	authMethods, err := buildAuthMethods(server)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("Auth setup failed: %v", err)
		mu.Unlock()
		return
	}
	hostKeyCallback, err := getHostKeyCallback()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("Host key verification setup failed: %v", err)
		mu.Unlock()
		return
	}
	config := &ssh.ClientConfig{
		User:            server.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(server.Host, strconv.Itoa(normalizePort(server.Port))), config)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("SSH connection failed: %v", err)
		mu.Unlock()
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs += fmt.Sprintf("\nSSH session failed: %v", err)
		mu.Unlock()
		return
	}
	defer session.Close()

	cmd := "sudo -S -p '' rm -f /etc/sudoers.d/apt-nopasswd"

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	session.Stdin = strings.NewReader(sudoPassword + "\n")
	err = session.Run(cmd)
	mu.Lock()
	currentLogs := status.Logs
	mu.Unlock()
	logs := currentLogs + "\n" + stdout.String() + stderr.String()
	if err != nil {
		logs += fmt.Sprintf("\nError: %v", err)
		mu.Lock()
		status.Status = "error"
		status.Logs = logs
		mu.Unlock()
		return
	}

	mu.Lock()
	status.Status = "done"
	status.Logs = logs + "\nPasswordless apt sudoers disabled."
	mu.Unlock()
}

func runAutoremove(server Server) {
	mu.Lock()
	status := statusMap[server.Name]
	if status == nil {
		mu.Unlock()
		return
	}
	status.Status = "autoremove"
	if strings.TrimSpace(status.Logs) == "" {
		status.Logs = "Starting Linux Updater..."
	}
	status.Logs += "\nRunning apt autoremove..."
	mu.Unlock()

	authMethods, err := buildAuthMethods(server)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("Auth setup failed: %v", err)
		mu.Unlock()
		return
	}
	hostKeyCallback, err := getHostKeyCallback()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("Host key verification setup failed: %v", err)
		mu.Unlock()
		return
	}
	config := &ssh.ClientConfig{
		User:            server.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(server.Host, strconv.Itoa(normalizePort(server.Port))), config)
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs = fmt.Sprintf("SSH connection failed: %v", err)
		mu.Unlock()
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		mu.Lock()
		status.Status = "error"
		status.Logs += fmt.Sprintf("\nSSH session failed: %v", err)
		mu.Unlock()
		return
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	err = session.Run("sudo apt autoremove -y")
	mu.Lock()
	currentLogs := status.Logs
	mu.Unlock()
	logs := currentLogs + "\n" + stdout.String() + stderr.String()
	if err != nil {
		logs += fmt.Sprintf("\nError: %v", err)
		mu.Lock()
		status.Status = "error"
		status.Logs = logs
		mu.Unlock()
		return
	}

	mu.Lock()
	status.Status = "done"
	status.Logs = logs + "\nAutoremove completed."
	mu.Unlock()
}

func getUpgradable(client *ssh.Client) ([]string, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	err = session.Run("apt list --upgradable")
	if err != nil {
		return nil, err
	}
	output := stdout.String()
	lines := strings.Split(output, "\n")
	var upgradable []string
	for _, line := range lines[1:] { // skip header
		if strings.TrimSpace(line) != "" {
			upgradable = append(upgradable, line)
		}
	}
	return upgradable, nil
}

func getGlobalKey() string {
	globalKeyOnce.Do(func() {
		db := getDB()
		var enc string
		err := db.QueryRow("SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&enc)
		if err == sql.ErrNoRows {
			globalKey = ""
			return
		}
		if err != nil {
			log.Printf("Failed to load global SSH key: %v", err)
			globalKey = ""
			return
		}
		key, err := decryptSecret(enc)
		if err != nil {
			log.Printf("Failed to decrypt global SSH key: %v", err)
			globalKey = ""
			return
		}
		globalKey = key
	})
	return globalKey
}

func setGlobalKey(key string) error {
	enc, err := encryptSecret(key)
	if err != nil {
		return err
	}
	db := getDB()
	_, err = db.Exec(
		"INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		globalKeySetting, enc,
	)
	if err != nil {
		return err
	}
	globalKeyOnce = sync.Once{}
	globalKey = key
	return nil
}

func clearGlobalKey() error {
	db := getDB()
	if _, err := db.Exec("DELETE FROM settings WHERE key = ?", globalKeySetting); err != nil {
		return err
	}
	globalKeyOnce = sync.Once{}
	globalKey = ""
	return nil
}

func updateServerKey(name, key string) error {
	enc, err := encryptSecret(key)
	if err != nil {
		return err
	}
	db := getDB()
	_, err = db.Exec("UPDATE servers SET key_enc = ? WHERE name = ?", enc, name)
	return err
}

func parseTags(raw string) []string {
	parts := strings.Split(raw, ",")
	var tags []string
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func joinTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	cleaned := make([]string, 0, len(tags))
	seen := make(map[string]struct{})
	for _, tag := range tags {
		clean := strings.TrimSpace(tag)
		if clean == "" {
			continue
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		cleaned = append(cleaned, clean)
	}
	return strings.Join(cleaned, ", ")
}

func normalizePort(port int) int {
	if port <= 0 || port > 65535 {
		return 22
	}
	return port
}

func normalizeServerName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeServerHost(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func serverNameExistsLocked(name string, skipIndex int) bool {
	normalized := normalizeServerName(name)
	for i, existing := range servers {
		if i == skipIndex {
			continue
		}
		if normalizeServerName(existing.Name) == normalized {
			return true
		}
	}
	return false
}

func serverHostExistsLocked(host string, skipIndex int) bool {
	normalized := normalizeServerHost(host)
	for i, existing := range servers {
		if i == skipIndex {
			continue
		}
		if normalizeServerHost(existing.Host) == normalized {
			return true
		}
	}
	return false
}

func knownHostsPaths() []string {
	if raw := strings.TrimSpace(os.Getenv("DEBIAN_UPDATER_KNOWN_HOSTS")); raw != "" {
		parts := strings.Split(raw, ":")
		paths := make([]string, 0, len(parts))
		for _, part := range parts {
			path := strings.TrimSpace(part)
			if path != "" {
				paths = append(paths, path)
			}
		}
		return paths
	}
	paths := []string{filepath.Join(filepath.Dir(dbPath()), "known_hosts")}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		paths = append(paths, filepath.Join(home, ".ssh", "known_hosts"))
	}
	paths = append(paths, "/etc/ssh/ssh_known_hosts")
	seen := make(map[string]struct{}, len(paths))
	unique := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		unique = append(unique, path)
	}
	return unique
}

func getHostKeyCallback() (ssh.HostKeyCallback, error) {
	candidates := knownHostsPaths()
	existing := make([]string, 0, len(candidates))
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	if len(existing) == 0 {
		return nil, errors.New("no known_hosts file found; set DEBIAN_UPDATER_KNOWN_HOSTS or create ~/.ssh/known_hosts")
	}
	cb, err := knownhosts.New(existing...)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return cb, nil
}

func knownHostsWritePath() (string, error) {
	paths := knownHostsPaths()
	if len(paths) == 0 {
		return "", errors.New("no known_hosts path configured")
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return paths[0], nil
}

func knownHostsHostToken(host string, port int) string {
	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	if normalizePort(port) == 22 {
		return cleanHost
	}
	return fmt.Sprintf("[%s]:%d", cleanHost, normalizePort(port))
}

func appendKnownHostLine(line string) error {
	cleanLine := strings.TrimSpace(line)
	if cleanLine == "" {
		return errors.New("empty known_hosts line")
	}
	path, err := knownHostsWritePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create known_hosts dir: %w", err)
	}

	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read known_hosts: %w", err)
	}
	if strings.Contains("\n"+string(data)+"\n", "\n"+cleanLine+"\n") {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open known_hosts for append: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(cleanLine + "\n"); err != nil {
		return fmt.Errorf("append known_hosts line: %w", err)
	}
	return nil
}

func scanHostKey(host string, port int) (ssh.PublicKey, error) {
	cleanHost := strings.TrimSpace(host)
	if cleanHost == "" {
		return nil, errors.New("host is required")
	}
	address := net.JoinHostPort(cleanHost, strconv.Itoa(normalizePort(port)))
	var scanned ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "hostkey-scan",
		Auth: []ssh.AuthMethod{
			ssh.Password("invalid"),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			scanned = key
			return nil
		},
		Timeout: sshConnectTimeout,
	}
	client, err := ssh.Dial("tcp", address, cfg)
	if client != nil {
		_ = client.Close()
	}
	if err != nil {
		msg := strings.ToLower(err.Error())
		isAuthErr := strings.Contains(msg, "unable to authenticate") ||
			strings.Contains(msg, "no auth") ||
			strings.Contains(msg, "permission denied") ||
			strings.Contains(msg, "authentication")
		if scanned != nil && isAuthErr {
			return scanned, nil
		}
		return nil, err
	}
	if scanned != nil {
		return scanned, nil
	}
	return nil, errors.New("unable to scan host key")
}

func buildKnownHostsLine(host string, port int, key ssh.PublicKey) string {
	return knownhosts.Line([]string{knownHostsHostToken(host, port)}, key)
}

func trustHostKey(host string, port int, expectedFingerprint string) (string, string, error) {
	key, err := scanHostKeyFunc(host, port)
	if err != nil {
		return "", "", err
	}
	fingerprint := ssh.FingerprintSHA256(key)
	if strings.TrimSpace(expectedFingerprint) != "" && !stringsEqualConstantTime(fingerprint, strings.TrimSpace(expectedFingerprint)) {
		return "", "", errFingerprintMismatch
	}
	line := buildKnownHostsLine(host, port, key)
	if err := appendKnownHostLine(line); err != nil {
		return "", "", err
	}
	return fingerprint, line, nil
}

func shellEscapeSingleQuotes(input string) string {
	return strings.ReplaceAll(input, "'", "'\"'\"'")
}

func buildAuthMethods(server Server) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	key := strings.TrimSpace(server.Key)
	if key == "" {
		key = strings.TrimSpace(getGlobalKey())
	}
	if key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if server.Pass != "" {
		methods = append(methods, ssh.Password(server.Pass))
	}
	if len(methods) == 0 {
		return nil, errors.New("missing password or SSH key")
	}
	return methods, nil
}

func main() {
	r := gin.Default()
	username, password, basicAuthEnabled, err := basicAuthFromEnv()
	if err != nil {
		log.Fatalf("Invalid basic auth configuration: %v", err)
	}
	if basicAuthEnabled {
		r.Use(basicAuthMiddleware(username, password))
		log.Printf("Basic auth enabled from %s/%s", basicAuthUserEnv, basicAuthPassEnv)
	} else {
		log.Printf("Basic auth is disabled (set %s and %s to enable it)", basicAuthUserEnv, basicAuthPassEnv)
	}
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.GET("/manage", func(c *gin.Context) {
		c.HTML(http.StatusOK, "manage.html", nil)
	})

	r.GET("/api/servers", func(c *gin.Context) {
		mu.Lock()
		var statuses []ServerStatus
		for _, s := range servers {
			status := statusMap[s.Name]
			if status == nil {
				continue
			}
			status.Host = s.Host
			status.Port = normalizePort(s.Port)
			status.User = s.User
			status.HasPassword = s.Pass != ""
			status.HasKey = s.Key != ""
			status.Tags = s.Tags
			statuses = append(statuses, *status)
		}
		mu.Unlock()
		c.JSON(http.StatusOK, statuses)
	})

	r.POST("/api/servers", func(c *gin.Context) {
		var newServer Server
		if err := c.ShouldBindJSON(&newServer); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		newServer.Name = strings.TrimSpace(newServer.Name)
		newServer.Host = strings.TrimSpace(newServer.Host)
		newServer.User = strings.TrimSpace(newServer.User)
		if newServer.Name == "" || newServer.Host == "" || newServer.User == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name, host, and user are required"})
			return
		}
		newServer.Port = normalizePort(newServer.Port)
		newServer.Tags = parseTags(joinTags(newServer.Tags))
		mu.Lock()
		prevServers := cloneServers(servers)
		prevStatusMap := cloneStatusMap(statusMap)
		if serverNameExistsLocked(newServer.Name, -1) {
			mu.Unlock()
			c.JSON(http.StatusConflict, gin.H{"error": "Server name already exists"})
			return
		}
		if serverHostExistsLocked(newServer.Host, -1) {
			mu.Unlock()
			c.JSON(http.StatusConflict, gin.H{"error": "Server host already exists"})
			return
		}
		servers = append(servers, newServer)
		statusMap[newServer.Name] = &ServerStatus{
			Name:        newServer.Name,
			Host:        newServer.Host,
			Port:        normalizePort(newServer.Port),
			User:        newServer.User,
			Status:      "idle",
			Logs:        "",
			Upgradable:  []string{},
			HasPassword: newServer.Pass != "",
			HasKey:      newServer.Key != "",
			Tags:        newServer.Tags,
		}
		if err := saveServersOrRollbackLocked(prevServers, prevStatusMap); err != nil {
			mu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save servers: %v", err)})
			return
		}
		mu.Unlock()
		c.JSON(http.StatusCreated, newServer)
	})

	r.PUT("/api/servers/:name", func(c *gin.Context) {
		name := c.Param("name")
		var updatedServer Server
		if err := c.ShouldBindJSON(&updatedServer); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updatedServer.Name = strings.TrimSpace(updatedServer.Name)
		updatedServer.Host = strings.TrimSpace(updatedServer.Host)
		updatedServer.User = strings.TrimSpace(updatedServer.User)
		if updatedServer.Name == "" || updatedServer.Host == "" || updatedServer.User == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name, host, and user are required"})
			return
		}
		mu.Lock()
		prevServers := cloneServers(servers)
		prevStatusMap := cloneStatusMap(statusMap)
		for i, s := range servers {
			if s.Name == name {
				if strings.TrimSpace(updatedServer.Pass) == "" {
					updatedServer.Pass = s.Pass
				}
				if strings.TrimSpace(updatedServer.Key) == "" {
					updatedServer.Key = s.Key
				}
				if updatedServer.Port == 0 {
					updatedServer.Port = s.Port
				}
				updatedServer.Port = normalizePort(updatedServer.Port)
				if updatedServer.Tags == nil {
					updatedServer.Tags = s.Tags
				}
				updatedServer.Tags = parseTags(joinTags(updatedServer.Tags))
				if serverNameExistsLocked(updatedServer.Name, i) {
					mu.Unlock()
					c.JSON(http.StatusConflict, gin.H{"error": "Server name already exists"})
					return
				}
				if serverHostExistsLocked(updatedServer.Host, i) {
					mu.Unlock()
					c.JSON(http.StatusConflict, gin.H{"error": "Server host already exists"})
					return
				}
				servers[i] = updatedServer
				if updatedServer.Name != name {
					delete(statusMap, name)
					statusMap[updatedServer.Name] = &ServerStatus{
						Name:        updatedServer.Name,
						Host:        updatedServer.Host,
						Port:        normalizePort(updatedServer.Port),
						User:        updatedServer.User,
						Status:      "idle",
						Logs:        "",
						Upgradable:  []string{},
						HasPassword: updatedServer.Pass != "",
						HasKey:      updatedServer.Key != "",
						Tags:        updatedServer.Tags,
					}
				} else {
					if statusMap[name] == nil {
						statusMap[name] = &ServerStatus{
							Name:       updatedServer.Name,
							Status:     "idle",
							Upgradable: []string{},
						}
					}
					statusMap[name].Host = updatedServer.Host
					statusMap[name].Port = normalizePort(updatedServer.Port)
					statusMap[name].User = updatedServer.User
					statusMap[name].HasPassword = updatedServer.Pass != ""
					statusMap[name].HasKey = updatedServer.Key != ""
					statusMap[name].Tags = updatedServer.Tags
				}
				if err := saveServersOrRollbackLocked(prevServers, prevStatusMap); err != nil {
					mu.Unlock()
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save servers: %v", err)})
					return
				}
				mu.Unlock()
				c.JSON(http.StatusOK, updatedServer)
				return
			}
		}
		mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.DELETE("/api/servers/:name", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		prevServers := cloneServers(servers)
		prevStatusMap := cloneStatusMap(statusMap)
		for i, s := range servers {
			if s.Name == name {
				servers = append(servers[:i], servers[i+1:]...)
				delete(statusMap, name)
				if err := saveServersOrRollbackLocked(prevServers, prevStatusMap); err != nil {
					mu.Unlock()
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save servers: %v", err)})
					return
				}
				mu.Unlock()
				c.JSON(http.StatusOK, gin.H{"message": "Server deleted"})
				return
			}
		}
		mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.DELETE("/api/servers/:name/password", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		defer mu.Unlock()
		prevServers := cloneServers(servers)
		prevStatusMap := cloneStatusMap(statusMap)
		for i, s := range servers {
			if s.Name == name {
				servers[i].Pass = ""
				if err := saveServersOrRollbackLocked(prevServers, prevStatusMap); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save servers: %v", err)})
					return
				}
				if status, ok := statusMap[name]; ok {
					status.HasPassword = false
				}
				c.JSON(http.StatusOK, gin.H{"message": "Password cleared"})
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.POST("/api/servers/:name/key", func(c *gin.Context) {
		name := c.Param("name")
		file, err := c.FormFile("key")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing key file"})
			return
		}
		key, err := readUploadedPrivateKey(file)
		if err != nil {
			if errors.Is(err, errUploadedKeyTooLarge) {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
				return
			}
			if errors.Is(err, errUploadedKeyEmpty) {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read key"})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for i, s := range servers {
			if s.Name == name {
				servers[i].Key = key
				if err := updateServerKey(name, key); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				if status, ok := statusMap[name]; ok {
					status.HasKey = key != ""
				}
				c.JSON(http.StatusOK, gin.H{"message": "Key uploaded"})
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.DELETE("/api/servers/:name/key", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		defer mu.Unlock()
		for i, s := range servers {
			if s.Name == name {
				servers[i].Key = ""
				if err := updateServerKey(name, ""); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				if status, ok := statusMap[name]; ok {
					status.HasKey = false
				}
				c.JSON(http.StatusOK, gin.H{"message": "Key cleared"})
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.POST("/api/keys/global", func(c *gin.Context) {
		file, err := c.FormFile("key")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing key file"})
			return
		}
		key, err := readUploadedPrivateKey(file)
		if err != nil {
			if errors.Is(err, errUploadedKeyTooLarge) {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
				return
			}
			if errors.Is(err, errUploadedKeyEmpty) {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read key"})
			return
		}
		if err := setGlobalKey(key); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Global key saved"})
	})

	r.DELETE("/api/keys/global", func(c *gin.Context) {
		if err := clearGlobalKey(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Global key cleared"})
	})

	r.GET("/api/keys/global", func(c *gin.Context) {
		db := getDB()
		var enc string
		err := db.QueryRow("SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&enc)
		if err == sql.ErrNoRows || strings.TrimSpace(enc) == "" {
			c.JSON(http.StatusOK, gin.H{"has_key": false})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read global key"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"has_key": true})
	})

	r.POST("/api/hostkeys/scan", func(c *gin.Context) {
		var req struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		host := strings.TrimSpace(req.Host)
		if host == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "host is required"})
			return
		}
		port := normalizePort(req.Port)
		key, err := scanHostKeyFunc(host, port)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("failed to scan host key: %v", err)})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"host":               host,
			"port":               port,
			"algorithm":          key.Type(),
			"fingerprint_sha256": ssh.FingerprintSHA256(key),
			"known_hosts_line":   buildKnownHostsLine(host, port, key),
		})
	})

	r.POST("/api/hostkeys/trust", func(c *gin.Context) {
		var req struct {
			Host              string `json:"host"`
			Port              int    `json:"port"`
			FingerprintSHA256 string `json:"fingerprint_sha256"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		host := strings.TrimSpace(req.Host)
		if host == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "host is required"})
			return
		}
		expectedFingerprint := strings.TrimSpace(req.FingerprintSHA256)
		if expectedFingerprint == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "fingerprint_sha256 is required"})
			return
		}
		port := normalizePort(req.Port)
		fingerprint, line, err := trustHostKey(host, port, expectedFingerprint)
		if err != nil {
			if errors.Is(err, errFingerprintMismatch) {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("failed to trust host key: %v", err)})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message":            "Host key trusted",
			"host":               host,
			"port":               port,
			"fingerprint_sha256": fingerprint,
			"known_hosts_line":   line,
		})
	})

	r.POST("/api/update/:name", func(c *gin.Context) {
		name := c.Param("name")
		server, err := beginServerAction(name, "updating")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
				return
			}
			if errors.Is(err, errActionInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": "Update already in progress"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start update"})
			return
		}
		go runUpdate(server)
		c.JSON(http.StatusOK, gin.H{"message": "Update started"})
	})

	r.POST("/api/autoremove/:name", func(c *gin.Context) {
		name := c.Param("name")
		server, err := beginServerAction(name, "autoremove")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
				return
			}
			if errors.Is(err, errActionInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": "Update already in progress"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start autoremove"})
			return
		}
		go runAutoremove(server)
		c.JSON(http.StatusOK, gin.H{"message": "Autoremove started"})
	})

	r.POST("/api/sudoers/:name", func(c *gin.Context) {
		name := c.Param("name")
		var req struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.Password) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing sudo password"})
			return
		}
		server, err := beginServerAction(name, "sudoers")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
				return
			}
			if errors.Is(err, errActionInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": "Update already in progress"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start sudoers setup"})
			return
		}
		go runSudoersBootstrap(server, req.Password)
		c.JSON(http.StatusOK, gin.H{"message": "Sudoers setup started"})
	})

	r.POST("/api/sudoers/disable/:name", func(c *gin.Context) {
		name := c.Param("name")
		var req struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.Password) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing sudo password"})
			return
		}
		server, err := beginServerAction(name, "sudoers")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
				return
			}
			if errors.Is(err, errActionInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": "Update already in progress"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start sudoers disable"})
			return
		}
		go runSudoersDisable(server, req.Password)
		c.JSON(http.StatusOK, gin.H{"message": "Sudoers disable started"})
	})

	r.POST("/api/approve/:name", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		status, exists := statusMap[name]
		if exists && status.Status == "pending_approval" {
			status.Status = "approved"
		}
		mu.Unlock()
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Upgrade approved"})
	})

	r.POST("/api/cancel/:name", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		status, exists := statusMap[name]
		if exists && status.Status == "pending_approval" {
			status.Status = "cancelled"
		}
		mu.Unlock()
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Upgrade cancelled"})
	})

	r.GET("/api/logs/:name", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		status, exists := statusMap[name]
		if !exists || status == nil {
			mu.Unlock()
			c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		logs := status.Logs
		mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"logs": logs})
	})

	log.Println("Starting web server on :8080")
	r.Run(":8080")
}
