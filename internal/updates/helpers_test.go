package updates

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"debian-updater/internal/servers"
)

func TestParseUpgradableEntriesAndPackageSelection(t *testing.T) {
	stdout := strings.Join([]string{
		"NOTE: noise",
		"Inst openssl [3.0.1] (3.0.2 Ubuntu:22.04/jammy-security [amd64])",
		"Inst curl [7.1] (7.2 Ubuntu:22.04/jammy-updates [amd64])",
	}, "\n")
	pending, upgradable, err := ParseUpgradableEntries(stdout)
	if err != nil {
		t.Fatalf("ParseUpgradableEntries() error = %v", err)
	}
	if len(upgradable) != 2 {
		t.Fatalf("upgradable count = %d, want 2", len(upgradable))
	}
	if pending[0].Package != "openssl" || !pending[0].Security || pending[0].CurrentVersion != "3.0.1" || pending[0].CandidateVersion != "3.0.2" {
		t.Fatalf("first pending update = %+v, want parsed security openssl", pending[0])
	}
	if got := SecurityPackagesFromPendingUpdates(pending); !reflect.DeepEqual(got, []string{"openssl"}) {
		t.Fatalf("SecurityPackagesFromPendingUpdates() = %#v, want openssl", got)
	}
}

func TestParseUpgradableEntriesAptSummaryBlock(t *testing.T) {
	stdout := strings.Join([]string{
		"Reading package lists... Done",
		"Building dependency tree... Done",
		"Reading state information... Done",
		"Calculating upgrade... Done",
		"The following packages will be upgraded:",
		"  apache2-utils base-files bash bind9-dnsutils bind9-host bind9-libs certbot",
		"  distro-info-data dpkg dpkg-dev e2fsprogs ifupdown inetutils-telnet jq",
		"  libpython3.13-stdlib sed sqv ssh sudo systemd",
		"73 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.",
	}, "\n")
	pending, upgradable, err := ParseUpgradableEntries(stdout)
	if err != nil {
		t.Fatalf("ParseUpgradableEntries() error = %v", err)
	}
	want := []string{
		"apache2-utils", "base-files", "bash", "bind9-dnsutils", "bind9-host", "bind9-libs", "certbot",
		"distro-info-data", "dpkg", "dpkg-dev", "e2fsprogs", "ifupdown", "inetutils-telnet", "jq",
		"libpython3.13-stdlib", "sed", "sqv", "ssh", "sudo", "systemd",
	}
	if !reflect.DeepEqual(upgradable, want) {
		t.Fatalf("upgradable = %#v, want %#v", upgradable, want)
	}
	if len(pending) != len(want) || pending[0].Package != "apache2-utils" || pending[len(pending)-1].Package != "systemd" {
		t.Fatalf("pending updates = %+v, want package entries from summary block", pending)
	}
}

func TestParseAptListMetadataEntriesKeepsSourceAndSecurity(t *testing.T) {
	stdout := strings.Join([]string{
		"Listing...",
		"bash/stable 5.2.15-2+b8 amd64 [upgradable from: 5.2.15-2+b7]",
		"openssl/stable-security 3.0.17-1~deb12u2 amd64 [upgradable from: 3.0.16-1~deb12u1]",
		"ignored/stable 1.0 amd64 [upgradable from: 0.9]",
	}, "\n")
	pending, upgradable := ParseAptListMetadataEntries(stdout, []string{"openssl", "bash"})
	if len(pending) != 2 || len(upgradable) != 2 {
		t.Fatalf("len(pending)=%d len(upgradable)=%d, want 2/2", len(pending), len(upgradable))
	}
	if pending[0].Package != "openssl" || pending[0].Source != "stable-security" || pending[0].CandidateVersion != "3.0.17-1~deb12u2" || pending[0].CurrentVersion != "3.0.16-1~deb12u1" || !pending[0].Security {
		t.Fatalf("first pending update = %+v, want security openssl with apt source metadata", pending[0])
	}
	if pending[1].Package != "bash" || pending[1].Source != "stable" || pending[1].Security {
		t.Fatalf("second pending update = %+v, want non-security bash with source metadata", pending[1])
	}
	if !strings.Contains(upgradable[0], "openssl/stable-security") || !strings.Contains(upgradable[1], "bash/stable") {
		t.Fatalf("upgradable = %#v, want raw apt-list metadata lines in package-filter order", upgradable)
	}
}

func TestParseAptListMetadataEntrySecurityFromCommaDelimitedSource(t *testing.T) {
	line := "openssl/jammy-updates,jammy-security 3.0.17-1~deb12u2 amd64 [upgradable from: 3.0.16-1~deb12u1]"
	update, ok := ParseAptListMetadataEntry(line)
	if !ok {
		t.Fatalf("ParseAptListMetadataEntry() ok = false, want true")
	}
	if update.Source != "jammy-updates,jammy-security" || !update.Security {
		t.Fatalf("parsed update = %+v, want comma-delimited source and security=true", update)
	}
}

func TestParseAptListMetadataEntriesMatchesArchQualifiedSummaryPackages(t *testing.T) {
	stdout := strings.Join([]string{
		"Listing...",
		"openssl/stable 3.0.17-1~deb12u2 amd64 [upgradable from: 3.0.16-1~deb12u1]",
		"openssl/stable-security 3.0.18-1~deb12u2 i386 [upgradable from: 3.0.16-1~deb12u1]",
		"bash/stable 5.2.15-2+b8 amd64 [upgradable from: 5.2.15-2+b7]",
	}, "\n")
	pending, upgradable := ParseAptListMetadataEntries(stdout, []string{"openssl:i386", "bash"})
	if len(pending) != 2 || len(upgradable) != 2 {
		t.Fatalf("len(pending)=%d len(upgradable)=%d, want 2/2", len(pending), len(upgradable))
	}
	if pending[0].Package != "openssl:i386" || pending[0].CandidateVersion != "3.0.18-1~deb12u2" || pending[0].Source != "stable-security" || !pending[0].Security {
		t.Fatalf("pending[0] = %+v, want exact i386 security metadata", pending[0])
	}
	if pending[1].Package != "bash" || pending[1].Source != "stable" {
		t.Fatalf("pending[1] = %+v, want bash package metadata", pending[1])
	}
	if strings.Contains(upgradable[0], "amd64") || !strings.Contains(upgradable[0], "i386") {
		t.Fatalf("upgradable[0] = %q, want exact i386 metadata line", upgradable[0])
	}
}

func TestParseAptListMetadataEntriesDoesNotOverwriteBaseWithForeignArch(t *testing.T) {
	stdout := strings.Join([]string{
		"Listing...",
		"openssl/stable 3.0.17-amd64 amd64 [upgradable from: 3.0.16-amd64]",
		"openssl/stable-security 3.0.18-i386 i386 [upgradable from: 3.0.16-i386]",
	}, "\n")
	pending, upgradable := ParseAptListMetadataEntries(stdout, []string{"openssl"})
	if len(pending) != 1 || len(upgradable) != 1 {
		t.Fatalf("len(pending)=%d len(upgradable)=%d, want 1/1", len(pending), len(upgradable))
	}
	if pending[0].Package != "openssl" || pending[0].CandidateVersion != "3.0.17-amd64" || pending[0].Security {
		t.Fatalf("pending[0] = %+v, want first base-package metadata without foreign-arch overwrite", pending[0])
	}
	if strings.Contains(upgradable[0], "i386") {
		t.Fatalf("upgradable[0] = %q, want base package metadata, not foreign-arch metadata", upgradable[0])
	}
}

func TestNeedsAptListMetadataOnlyForSummaryFallback(t *testing.T) {
	if !NeedsAptListMetadata([]servers.PendingUpdate{{Package: "openssl", Raw: "openssl", CVEs: []string{}}}) {
		t.Fatalf("NeedsAptListMetadata(summary fallback) = false, want true")
	}
	if NeedsAptListMetadata([]servers.PendingUpdate{{Package: "openssl", Source: "stable-security", Security: true}}) {
		t.Fatalf("NeedsAptListMetadata(enriched update) = true, want false")
	}
	if !NeedsAptListMetadata([]servers.PendingUpdate{{Package: "debian-security-support", Raw: "debian-security-support", Security: true, CVEs: []string{}}}) {
		t.Fatalf("NeedsAptListMetadata(summary package with security marker) = false, want true")
	}
}

func TestMergePendingUpdatesWithMetadataKeepsSummaryFallbackForMissingPackages(t *testing.T) {
	summaryPending := []servers.PendingUpdate{
		{Package: "openssl", Raw: "openssl", CVEs: []string{}},
		{Package: "bash", Raw: "bash", CVEs: []string{}},
	}
	metadataPending := []servers.PendingUpdate{
		{
			Package:          "openssl",
			CurrentVersion:   "3.0.16-1~deb12u1",
			CandidateVersion: "3.0.17-1~deb12u2",
			Source:           "stable-security",
			Security:         true,
			Raw:              "openssl/stable-security 3.0.17-1~deb12u2 amd64 [upgradable from: 3.0.16-1~deb12u1]",
			CVEs:             []string{},
		},
	}
	mergedPending, mergedUpgradable := MergePendingUpdatesWithMetadata(summaryPending, metadataPending)
	if len(mergedPending) != 2 || len(mergedUpgradable) != 2 {
		t.Fatalf("len(mergedPending)=%d len(mergedUpgradable)=%d, want 2/2", len(mergedPending), len(mergedUpgradable))
	}
	if mergedPending[0].Package != "openssl" || mergedPending[0].Source != "stable-security" || !mergedPending[0].Security {
		t.Fatalf("mergedPending[0] = %+v, want enriched openssl metadata", mergedPending[0])
	}
	if mergedPending[1].Package != "bash" || mergedPending[1].Source != "" || mergedPending[1].Security {
		t.Fatalf("mergedPending[1] = %+v, want summary fallback bash", mergedPending[1])
	}
	if !strings.Contains(mergedUpgradable[0], "openssl/stable-security") || mergedUpgradable[1] != "bash" {
		t.Fatalf("mergedUpgradable = %#v, want enriched openssl raw and fallback bash raw", mergedUpgradable)
	}
}

func TestMergePendingUpdatesWithMetadataKeepsArchSummaryWhenExactMetadataMissing(t *testing.T) {
	summaryPending := []servers.PendingUpdate{
		{Package: "openssl:i386", Raw: "openssl:i386", CVEs: []string{}},
		{Package: "bash", Raw: "bash", CVEs: []string{}},
	}
	metadataPending := []servers.PendingUpdate{
		{
			Package:          "openssl",
			CurrentVersion:   "3.0.16-1~deb12u1",
			CandidateVersion: "3.0.17-1~deb12u2",
			Source:           "stable-security",
			Security:         true,
			Raw:              "openssl/stable-security 3.0.17-1~deb12u2 amd64 [upgradable from: 3.0.16-1~deb12u1]",
			CVEs:             []string{},
		},
	}
	mergedPending, mergedUpgradable := MergePendingUpdatesWithMetadata(summaryPending, metadataPending)
	if len(mergedPending) != 2 || len(mergedUpgradable) != 2 {
		t.Fatalf("len(mergedPending)=%d len(mergedUpgradable)=%d, want 2/2", len(mergedPending), len(mergedUpgradable))
	}
	if mergedPending[0].Package != "openssl:i386" || mergedPending[0].Source != "" || mergedPending[0].Security {
		t.Fatalf("mergedPending[0] = %+v, want arch-qualified summary fallback without base metadata", mergedPending[0])
	}
	if mergedPending[1].Package != "bash" || mergedPending[1].Source != "" || mergedPending[1].Security {
		t.Fatalf("mergedPending[1] = %+v, want summary fallback bash", mergedPending[1])
	}
	if got := SecurityPackagesFromPendingUpdates(mergedPending); len(got) != 0 {
		t.Fatalf("SecurityPackagesFromPendingUpdates() = %#v, want no security packages without exact arch metadata", got)
	}
}

func TestMergePendingUpdatesWithMetadataPrefersExactArchMetadata(t *testing.T) {
	summaryPending := []servers.PendingUpdate{
		{Package: "openssl:i386", Raw: "openssl:i386", CVEs: []string{}},
		{Package: "openssl:amd64", Raw: "openssl:amd64", CVEs: []string{}},
	}
	metadataPending := []servers.PendingUpdate{
		{
			Package:          "openssl:amd64",
			CurrentVersion:   "3.0.16-amd64",
			CandidateVersion: "3.0.17-amd64",
			Source:           "stable",
			Raw:              "openssl/stable 3.0.17-amd64 amd64 [upgradable from: 3.0.16-amd64]",
			CVEs:             []string{},
		},
		{
			Package:          "openssl:i386",
			CurrentVersion:   "3.0.16-i386",
			CandidateVersion: "3.0.18-i386",
			Source:           "stable-security",
			Security:         true,
			Raw:              "openssl/stable-security 3.0.18-i386 i386 [upgradable from: 3.0.16-i386]",
			CVEs:             []string{},
		},
	}
	mergedPending, _ := MergePendingUpdatesWithMetadata(summaryPending, metadataPending)
	if len(mergedPending) != 2 {
		t.Fatalf("len(mergedPending)=%d, want 2", len(mergedPending))
	}
	if mergedPending[0].Package != "openssl:i386" || mergedPending[0].CandidateVersion != "3.0.18-i386" || !mergedPending[0].Security {
		t.Fatalf("mergedPending[0] = %+v, want exact i386 security metadata", mergedPending[0])
	}
	if mergedPending[1].Package != "openssl:amd64" || mergedPending[1].CandidateVersion != "3.0.17-amd64" || mergedPending[1].Security {
		t.Fatalf("mergedPending[1] = %+v, want exact amd64 non-security metadata", mergedPending[1])
	}
}

func TestAptListUpgradableCmdForcesCLocaleWithoutSudo(t *testing.T) {
	want := "LC_ALL=C apt-get -s upgrade"
	if AptListUpgradableCmd != want {
		t.Fatalf("AptListUpgradableCmd = %q, want %q", AptListUpgradableCmd, want)
	}
	if strings.Contains(AptListUpgradableCmd, "sudo") {
		t.Fatalf("AptListUpgradableCmd = %q, should not require sudo or sudo SETENV", AptListUpgradableCmd)
	}
}

func TestBuildSelectedUpgradeCmdEscapesPackages(t *testing.T) {
	got := BuildSelectedUpgradeCmd([]string{"openssl", "libfoo'bar"})
	want := RootOrSudoCommand(`apt-get -y install --only-upgrade -- 'openssl' 'libfoo'"'"'bar'`)
	if got != want {
		t.Fatalf("BuildSelectedUpgradeCmd() = %q, want %q", got, want)
	}
}

func TestRootOrSudoCommand(t *testing.T) {
	got := RootOrSudoCommand("apt-get update")
	want := `if [ "$(id -u)" -eq 0 ]; then apt-get update; else sudo -n apt-get update; fi`
	if got != want {
		t.Fatalf("RootOrSudoCommand() = %q, want %q", got, want)
	}
}

func TestRetryHelpersClassifyRetryableOutput(t *testing.T) {
	err := MarkRetryableFromOutput(errors.New("exit status 100"), "Could not get lock /var/lib/dpkg/lock-frontend")
	if !IsRetryableError(err) {
		t.Fatalf("MarkRetryableFromOutput() did not tag retryable lock output")
	}
	delay := ComputeRetryDelay(RetryPolicy{BaseDelay: time.Second, MaxDelay: 8 * time.Second, JitterPct: 0}, 3, 0)
	if delay != 4*time.Second {
		t.Fatalf("ComputeRetryDelay() = %s, want 4s", delay)
	}
}

func TestPreparePendingUpdatesForCVELimitsAndSorts(t *testing.T) {
	updates := make([]servers.PendingUpdate, 0, CVELookupMaxPackages+1)
	for i := 0; i < CVELookupMaxPackages+1; i++ {
		updates = append(updates, servers.PendingUpdate{Package: strings.Repeat("a", i+1), Security: i%2 == 0})
	}
	prepared := PreparePendingUpdatesForCVE(updates)
	if prepared[0].CVEState != "pending" {
		t.Fatalf("first CVE state = %q, want pending", prepared[0].CVEState)
	}
	if prepared[len(prepared)-1].CVEState != "skipped" {
		t.Fatalf("last CVE state = %q, want skipped", prepared[len(prepared)-1].CVEState)
	}
}
