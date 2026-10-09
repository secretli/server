package s3_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/secretli/server/internal/adapter/s3"
	"github.com/secretli/server/internal/domain"
	"github.com/secretli/server/internal/platform/config"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const testBucket = "test-bucket"

type seaweedFSTestEnv struct {
	client    *s3.Client
	container testcontainers.Container
	endpoint  string
}

var (
	seaweedDockerOnce sync.Once
	seaweedDockerErr  error

	seaweedOnce sync.Once
	seaweedEnv  seaweedFSTestEnv
	seaweedErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if seaweedEnv.container != nil {
		_ = seaweedEnv.container.Terminate(context.Background())
	}
	os.Exit(code)
}

func setupSeaweedFS(t *testing.T) *s3.Client {
	t.Helper()

	return setupSeaweedFSEnv(t).client
}

func setupSeaweedFSEnv(t *testing.T) seaweedFSTestEnv {
	t.Helper()
	requireDocker(t)
	seaweedOnce.Do(startSeaweedFS)
	if seaweedErr != nil {
		t.Fatalf("setup seaweedfs: %v", seaweedErr)
	}
	return seaweedEnv
}

func requireDocker(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	seaweedDockerOnce.Do(func() {
		if _, err := exec.LookPath("docker"); err != nil {
			seaweedDockerErr = err
			return
		}
		seaweedDockerErr = exec.Command("docker", "info").Run()
	})
	if seaweedDockerErr != nil {
		t.Skipf("skipping integration test: docker unavailable: %v", seaweedDockerErr)
	}
}

func startSeaweedFS() {
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			// The version docker/docker-compose.yml runs.
			Image:        "chrislusf/seaweedfs:4.48",
			ExposedPorts: []string{"8333/tcp"},
			Cmd:          []string{"server", "-s3", "-dir=/data"},
			WaitingFor: wait.ForListeningPort("8333/tcp").
				WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		seaweedErr = err
		return
	}
	seaweedEnv.container = container

	host, err := container.Host(ctx)
	if err != nil {
		seaweedErr = err
		return
	}
	port, err := container.MappedPort(ctx, "8333/tcp")
	if err != nil {
		seaweedErr = err
		return
	}
	endpoint := "http://" + net.JoinHostPort(host, port.Port())
	seaweedEnv.endpoint = endpoint

	if err := createBucket(endpoint, testBucket); err != nil {
		seaweedErr = err
		return
	}

	client, err := s3.NewClient(config.S3Config{
		Endpoint:  endpoint,
		Bucket:    testBucket,
		AccessKey: "admin",
		SecretKey: "admin",
		Region:    "us-east-1",
	})
	if err != nil {
		seaweedErr = err
		return
	}

	seaweedEnv.client = client
}

func createBucket(endpoint, bucket string) error {
	url := endpoint + "/" + bucket
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodPut, url, nil)
		if err != nil {
			return err
		}
		res, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode >= 200 && res.StatusCode < 300 {
				return nil
			}
			lastErr = io.ErrUnexpectedEOF
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return lastErr
}

// putTestObject writes an object the way production does: one multipart upload
// with a single final part. There is no whole-object put in the FileStore API.
func putTestObject(t *testing.T, client *s3.Client, key string, data []byte) {
	t.Helper()
	ctx := context.Background()
	uploadID, err := client.CreateMultipartUpload(ctx, key)
	if err != nil {
		t.Fatalf("CreateMultipartUpload %q: %v", key, err)
	}
	etag, err := client.UploadPart(ctx, key, uploadID, 1, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("UploadPart %q: %v", key, err)
	}
	if err := client.CompleteMultipartUpload(ctx, key, uploadID, []domain.CompletedPart{{PartNumber: 1, ETag: etag}}); err != nil {
		t.Fatalf("CompleteMultipartUpload %q: %v", key, err)
	}
}

// readTestObject reads a whole object back through the range API.
func readTestObject(t *testing.T, client *s3.Client, key string, size int) []byte {
	t.Helper()
	reader, err := client.GetRange(context.Background(), key, 0, int64(size-1))
	if err != nil {
		t.Fatalf("GetRange %q: %v", key, err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll %q: %v", key, err)
	}
	return got
}

// openUpload starts a multipart upload under key and uploads one part into it,
// so it holds data an abort has to drop. It returns the upload id and the
// part's etag, which completing the upload needs.
func openUpload(t *testing.T, client *s3.Client, key string, part []byte) (uploadID, etag string) {
	t.Helper()
	ctx := context.Background()
	uploadID, err := client.CreateMultipartUpload(ctx, key)
	if err != nil {
		t.Fatalf("CreateMultipartUpload %q: %v", key, err)
	}
	etag, err = client.UploadPart(ctx, key, uploadID, 1, bytes.NewReader(part), int64(len(part)))
	if err != nil {
		t.Fatalf("UploadPart %q: %v", key, err)
	}
	return uploadID, etag
}

// maxRelayedListings is how many listings the relay passes on before refusing
// them, so a client that never gets to the last page fails instead of hanging.
const maxRelayedListings = 20

// listingRelay stands between a client and SeaweedFS. It caps every listing of
// multipart uploads at a few per page, where SeaweedFS pages only after 10000
// uploads, more than a test can make, and it notes which uploads get aborted.
// The test SeaweedFS has no identities configured, so it does not check the
// request signatures that changing a query breaks.
type listingRelay struct {
	client *s3.Client

	mu       sync.Mutex
	listings int
	aborted  []string // the ids of the uploads the client aborted
}

func newListingRelay(t *testing.T, env seaweedFSTestEnv, perPage int) *listingRelay {
	t.Helper()
	target, err := url.Parse(env.endpoint)
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	relay := &listingRelay{}
	proxy := httputil.NewSingleHostReverseProxy(target)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		relay.mu.Lock()
		switch {
		case r.Method == http.MethodGet && query.Has("uploads"):
			relay.listings++
			if relay.listings > maxRelayedListings {
				relay.mu.Unlock()
				http.Error(w, "too many listings", http.StatusForbidden)
				return
			}
			query.Set("max-uploads", strconv.Itoa(perPage))
			r.URL.RawQuery = query.Encode()
		case r.Method == http.MethodDelete && query.Has("uploadId"):
			relay.aborted = append(relay.aborted, query.Get("uploadId"))
		}
		relay.mu.Unlock()
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	relay.client, err = s3.NewClient(config.S3Config{
		Endpoint:  server.URL,
		Bucket:    testBucket,
		AccessKey: "admin",
		SecretKey: "admin",
		Region:    "us-east-1",
	})
	if err != nil {
		t.Fatalf("client through the relay: %v", err)
	}
	return relay
}

func (r *listingRelay) seen() (listings int, aborted []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listings, slices.Clone(r.aborted)
}

// requireUploadAborted fails unless the upload is gone: it takes no more parts
// and cannot be completed.
func requireUploadAborted(t *testing.T, client *s3.Client, key, uploadID, etag string) {
	t.Helper()
	ctx := context.Background()
	if _, err := client.UploadPart(ctx, key, uploadID, 2, bytes.NewReader([]byte("more")), 4); err == nil {
		t.Errorf("UploadPart to upload %q of %q succeeded, want it aborted", uploadID, key)
	}
	err := client.CompleteMultipartUpload(ctx, key, uploadID, []domain.CompletedPart{{PartNumber: 1, ETag: etag}})
	if !errors.Is(err, domain.ErrUploadNotFound) {
		t.Errorf("CompleteMultipartUpload of upload %q of %q error = %v, want ErrUploadNotFound", uploadID, key, err)
	}
}

// requireUploadOpen fails unless the upload is still open: it completes it with
// the part's etag and checks the object that results.
func requireUploadOpen(t *testing.T, client *s3.Client, key, uploadID, etag string, part []byte) {
	t.Helper()
	err := client.CompleteMultipartUpload(context.Background(), key, uploadID, []domain.CompletedPart{{PartNumber: 1, ETag: etag}})
	if err != nil {
		t.Errorf("CompleteMultipartUpload of upload %q of %q: %v, want it still open", uploadID, key, err)
		return
	}
	if got := readTestObject(t, client, key, len(part)); !bytes.Equal(got, part) {
		t.Errorf("object %q = %q, want %q", key, got, part)
	}
}

func TestS3Client_WriteAndReadRange(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)

	data := []byte("hello, seaweedfs integration test!")
	putTestObject(t, client, "test-key", data)

	if got := readTestObject(t, client, "test-key", len(data)); !bytes.Equal(got, data) {
		t.Errorf("read %q, want %q", got, data)
	}
}

func TestS3Client_Delete(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	data := []byte("to be deleted")
	putTestObject(t, client, "del-key", data)

	if err := client.Delete(ctx, "del-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// A read after delete may fail when opening the object or when reading it,
	// depending on the S3-compatible server implementation.
	reader, err := client.GetRange(ctx, "del-key", 0, int64(len(data)-1))
	if err != nil {
		return
	}
	defer reader.Close()
	if _, err := io.ReadAll(reader); err == nil {
		t.Error("expected error reading deleted object, got nil")
	}
}

func TestS3Client_Overwrite(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)

	putTestObject(t, client, "overwrite-key", []byte("version 1"))
	data2 := []byte("version 2")
	putTestObject(t, client, "overwrite-key", data2)

	if got := readTestObject(t, client, "overwrite-key", len(data2)); !bytes.Equal(got, data2) {
		t.Errorf("read %q, want %q", got, data2)
	}
}

func TestS3Client_LargeFile(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)

	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i % 256)
	}
	putTestObject(t, client, "large-key", data)

	got := readTestObject(t, client, "large-key", len(data))
	if len(got) != len(data) {
		t.Errorf("got %d bytes, want %d", len(got), len(data))
	}
	if !bytes.Equal(got, data) {
		t.Error("large file content mismatch")
	}
}

func TestS3Client_GetRange(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i % 251)
	}

	putTestObject(t, client, "range-key", data)

	tests := []struct {
		name       string
		start, end int64
	}{
		{name: "first byte", start: 0, end: 0},
		{name: "prefix", start: 0, end: 1023},
		{name: "middle", start: 100_000, end: 101_000},
		{name: "last byte", start: int64(len(data) - 1), end: int64(len(data) - 1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := client.GetRange(ctx, "range-key", tt.start, tt.end)
			if err != nil {
				t.Fatalf("GetRange: %v", err)
			}
			defer reader.Close()

			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			want := data[tt.start : tt.end+1]
			if !bytes.Equal(got, want) {
				t.Fatalf("range bytes mismatch: got %d bytes, want %d bytes", len(got), len(want))
			}
		})
	}
}

func TestS3Client_GetRangeRejectsMalformedRange(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	_, err := client.GetRange(context.Background(), "range-key", 5, 4)
	if err == nil {
		t.Fatal("expected malformed range error")
	}
}

func TestNewS3Client_BucketNotFound(t *testing.T) {
	t.Parallel()
	env := setupSeaweedFSEnv(t)

	_, err := s3.NewClient(config.S3Config{
		Endpoint:  env.endpoint,
		Bucket:    "nonexistent-bucket",
		AccessKey: "admin",
		SecretKey: "admin",
		Region:    "us-east-1",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent bucket, got nil")
	}
}

func TestS3Client_MultipartRoundTrip(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	const key = "multipart/roundtrip"
	partOne := bytes.Repeat([]byte("a"), 5*1024*1024)
	partTwo := []byte("tail-bytes")

	uploadID, err := client.CreateMultipartUpload(ctx, key)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	etagOne, err := client.UploadPart(ctx, key, uploadID, 1, bytes.NewReader(partOne), int64(len(partOne)))
	if err != nil {
		t.Fatalf("UploadPart 1: %v", err)
	}
	etagTwo, err := client.UploadPart(ctx, key, uploadID, 2, bytes.NewReader(partTwo), int64(len(partTwo)))
	if err != nil {
		t.Fatalf("UploadPart 2: %v", err)
	}
	if err := client.CompleteMultipartUpload(ctx, key, uploadID, []domain.CompletedPart{
		{PartNumber: 1, ETag: etagOne},
		{PartNumber: 2, ETag: etagTwo},
	}); err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}

	want := append(append([]byte(nil), partOne...), partTwo...)
	if got := readTestObject(t, client, key, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("assembled object has %d bytes, want %d", len(got), len(want))
	}

	// Aborting a completed (no longer existing) upload is a no-op.
	if err := client.AbortMultipartUpload(ctx, key, uploadID); err != nil {
		t.Fatalf("AbortMultipartUpload after complete: %v", err)
	}
}

func TestS3Client_AbortMultipartUploadIsIdempotent(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	const key = "multipart/abort"
	uploadID, err := client.CreateMultipartUpload(ctx, key)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if _, err := client.UploadPart(ctx, key, uploadID, 1, bytes.NewReader([]byte("part")), 4); err != nil {
		t.Fatalf("UploadPart: %v", err)
	}

	if err := client.AbortMultipartUpload(ctx, key, uploadID); err != nil {
		t.Fatalf("first AbortMultipartUpload: %v", err)
	}
	if err := client.AbortMultipartUpload(ctx, key, uploadID); err != nil {
		t.Fatalf("second AbortMultipartUpload should succeed: %v", err)
	}
	if err := client.AbortMultipartUpload(ctx, key, "never-existed"); err != nil {
		t.Fatalf("AbortMultipartUpload of unknown upload should succeed: %v", err)
	}

	err = client.CompleteMultipartUpload(ctx, key, uploadID, []domain.CompletedPart{{PartNumber: 1, ETag: "x"}})
	if !errors.Is(err, domain.ErrUploadNotFound) {
		t.Fatalf("CompleteMultipartUpload after abort error = %v, want ErrUploadNotFound", err)
	}
}

func TestS3Client_AbortMultipartUploadsAbortsTheOpenUploadsOfAKey(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	// An upload is found by listing, so it needs no id: more than one can be
	// open under a key, and all of them go.
	key := domain.UploadStorageKey("abort-uploads-0123456789_abcdefghijklmnopqr")
	idOne, etagOne := openUpload(t, client, key, []byte("first upload"))
	idTwo, etagTwo := openUpload(t, client, key, []byte("second upload"))

	if err := client.AbortMultipartUploads(ctx, key); err != nil {
		t.Fatalf("AbortMultipartUploads: %v", err)
	}

	requireUploadAborted(t, client, key, idOne, etagOne)
	requireUploadAborted(t, client, key, idTwo, etagTwo)
	// Aborting assembles nothing.
	if reader, err := client.GetRange(ctx, key, 0, 3); err == nil {
		_ = reader.Close()
		t.Errorf("GetRange %q succeeded, want no object after the abort", key)
	}
}

func TestS3Client_AbortMultipartUploadsLeavesLongerKeysAlone(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	// A listing by prefix also returns keys that merely start with the key.
	const key = "abort-prefix/abc"
	target, targetETag := openUpload(t, client, key, []byte("target"))
	longerData, nestedData := []byte("longer key"), []byte("nested key")
	longerKey, nestedKey := key+"d", key+"/d"
	longer, longerETag := openUpload(t, client, longerKey, longerData)
	nested, nestedETag := openUpload(t, client, nestedKey, nestedData)

	if err := client.AbortMultipartUploads(ctx, key); err != nil {
		t.Fatalf("AbortMultipartUploads: %v", err)
	}

	requireUploadAborted(t, client, key, target, targetETag)
	// The others are untouched: they still take their parts' completion.
	requireUploadOpen(t, client, longerKey, longer, longerETag, longerData)
	requireUploadOpen(t, client, nestedKey, nested, nestedETag, nestedData)
}

func TestS3Client_AbortMultipartUploadsPagesThroughTheListing(t *testing.T) {
	t.Parallel()
	env := setupSeaweedFSEnv(t)
	ctx := context.Background()
	relay := newListingRelay(t, env, 2)
	client := relay.client

	// Three uploads of the key, and five of a longer key that the prefix finds
	// too. SeaweedFS lists the uploads of one key together, so at two to a page
	// one page holds nothing to abort: only the page markers get past it.
	const key = "abort-pages/abc"
	var ids, etags []string
	for i := range 3 {
		id, etag := openUpload(t, client, key, []byte("upload "+strconv.Itoa(i)))
		ids, etags = append(ids, id), append(etags, etag)
	}
	type upload struct{ id, etag string }
	var longer []upload
	longerKey := key + "d"
	longerData := []byte("longer key")
	for range 5 {
		id, etag := openUpload(t, client, longerKey, longerData)
		longer = append(longer, upload{id, etag})
	}

	if err := client.AbortMultipartUploads(ctx, key); err != nil {
		t.Fatalf("AbortMultipartUploads: %v", err)
	}

	listings, aborted := relay.seen()
	if listings < 4 {
		t.Errorf("listing requests = %d, want at least 4: no page holds more than 2 of the 8 uploads", listings)
	}
	for i, id := range ids {
		requireUploadAborted(t, client, key, id, etags[i])
	}
	for _, u := range longer {
		requireUploadOpen(t, client, longerKey, u.id, u.etag, longerData)
	}
	// Only the uploads of the key itself were asked to abort, not those the
	// prefix also found.
	slices.Sort(aborted)
	if want := slices.Sorted(slices.Values(ids)); !slices.Equal(aborted, want) {
		t.Errorf("aborted uploads = %v, want exactly the key's own: %v", aborted, want)
	}
}

func TestS3Client_AbortMultipartUploadsSucceedsWithoutAnUpload(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	if err := client.AbortMultipartUploads(ctx, "abort-none/never-used"); err != nil {
		t.Fatalf("AbortMultipartUploads of a key nobody uploaded to: %v", err)
	}

	// Nor is it an error to do it again, once everything is aborted.
	const key = "abort-none/aborted-before"
	openUpload(t, client, key, []byte("part"))
	for attempt := 1; attempt <= 2; attempt++ {
		if err := client.AbortMultipartUploads(ctx, key); err != nil {
			t.Fatalf("AbortMultipartUploads, attempt %d: %v", attempt, err)
		}
	}
}

func TestS3Client_AbortMultipartUploadsKeepsACompletedObject(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	// A completed upload is not listed any more, and the object it made stays:
	// removing that is the delete's business.
	const key = "abort-completed/object"
	data := []byte("assembled before the abort")
	putTestObject(t, client, key, data)

	if err := client.AbortMultipartUploads(ctx, key); err != nil {
		t.Fatalf("AbortMultipartUploads after CompleteMultipartUpload: %v", err)
	}

	if got := readTestObject(t, client, key, len(data)); !bytes.Equal(got, data) {
		t.Errorf("object = %q, want %q", got, data)
	}
}

func TestS3Client_AbortMultipartUploadsKeepsTheObjectWhileAbortingANewUpload(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	const key = "abort-completed/overwritten"
	data := []byte("the stored version")
	putTestObject(t, client, key, data)
	uploadID, etag := openUpload(t, client, key, []byte("an upload that would replace it"))

	if err := client.AbortMultipartUploads(ctx, key); err != nil {
		t.Fatalf("AbortMultipartUploads: %v", err)
	}

	requireUploadAborted(t, client, key, uploadID, etag)
	if got := readTestObject(t, client, key, len(data)); !bytes.Equal(got, data) {
		t.Errorf("object = %q, want %q", got, data)
	}
}

func TestS3Client_CompleteMultipartUploadRejectsStaleETag(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	const key = "multipart/stale-etag"
	uploadID, err := client.CreateMultipartUpload(ctx, key)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	t.Cleanup(func() { _ = client.AbortMultipartUpload(context.Background(), key, uploadID) })
	if _, err := client.UploadPart(ctx, key, uploadID, 1, bytes.NewReader([]byte("part")), 4); err != nil {
		t.Fatalf("UploadPart: %v", err)
	}

	err = client.CompleteMultipartUpload(ctx, key, uploadID, []domain.CompletedPart{{PartNumber: 1, ETag: "\"deadbeef\""}})
	if !errors.Is(err, domain.ErrInvalidParts) {
		t.Fatalf("CompleteMultipartUpload with stale etag error = %v, want ErrInvalidParts", err)
	}
}

func TestS3Client_MultipartSinglePart(t *testing.T) {
	t.Parallel()
	client := setupSeaweedFS(t)
	ctx := context.Background()

	// Small bundles are uploaded as one final part well below the S3 minimum
	// for non-final parts; the backend must accept that.
	const key = "multipart/single-part"
	payload := []byte("tiny single-part bundle")

	uploadID, err := client.CreateMultipartUpload(ctx, key)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	etag, err := client.UploadPart(ctx, key, uploadID, 1, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("UploadPart: %v", err)
	}
	if err := client.CompleteMultipartUpload(ctx, key, uploadID, []domain.CompletedPart{{PartNumber: 1, ETag: etag}}); err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}

	if got := readTestObject(t, client, key, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("object = %q, want %q", got, payload)
	}
}
