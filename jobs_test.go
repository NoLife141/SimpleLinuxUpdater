package main

import (
	"path/filepath"
	"testing"
)

func TestJobRuntimeStatusSyncFromRecord(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "job-runtime-sync.db"))

	server := Server{Name: "srv-runtime-sync", Host: "example.org", Port: 22, User: "root"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle"},
	}
	mu.Unlock()
	if err := initializeJobManager(); err != nil {
		t.Fatalf("initializeJobManager() error = %v", err)
	}

	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "tester",
		Status:     jobStatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	status := jobStatusRunning
	phase := jobPhaseAptUpgrade
	if err := currentJobManager().UpdateJob(job.ID, JobUpdate{
		Status: &status,
		Phase:  &phase,
	}); err != nil {
		t.Fatalf("UpdateJob() error = %v", err)
	}

	snapshot := currentStatusSnapshot(server.Name)
	if snapshot == nil || snapshot.Status != "upgrading" {
		t.Fatalf("runtime status = %+v, want upgrading", snapshot)
	}
}
