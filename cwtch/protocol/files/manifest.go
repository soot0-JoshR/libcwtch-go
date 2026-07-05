package files

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Chunk is a wrapper around a hash
type Chunk []byte

// DefaultChunkSize is the default value of a manifest chunk
const DefaultChunkSize = 4096

// MaxManifestSize is the maximum size of a manifest (in DefaultChunkSize)
// Because we reconstruct the manifest in memory we have to practically limit this size.
// 2622000 * 4096 ~= 10GB using 4096 byte chunks
// This makes the actual manifest size ~125Mb which seems reasonable for a 10Gb file.
// most file transfers are expected to have manifest that are much smaller.
const MaxManifestSize = 2622000

// Manifest is a collection of hashes and other metadata needed to reconstruct a file and verify contents given a root hash
type Manifest struct {
	Chunks           []Chunk
	FileName         string
	RootHash         []byte
	FileSizeInBytes  uint64
	ChunkSizeInBytes uint64
	TempFileName     string `json:"-"`
	Title            string `json:"-"`

	chunkComplete []bool
	openFd        *os.File
	progress      uint64
	lock          sync.Mutex
}

// CreateManifest takes in a file path and constructs a file sharing manifest of hashes along with
// other information necessary to download, reconstruct and verify the file.
func CreateManifest(path string) (*Manifest, error) {
	// Process file into Chunks
	f, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	reader := bufio.NewReader(f)
	buf := make([]byte, DefaultChunkSize)

	var chunks []Chunk
	fileSizeInBytes := uint64(0)

	rootHash := sha512.New()

	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
		hash := sha256.New()
		hash.Write(buf[0:n])
		rootHash.Write(buf[0:n])
		chunkHash := hash.Sum(nil)
		chunks = append(chunks, chunkHash)
		fileSizeInBytes += uint64(n)
	}

	return &Manifest{
		Chunks:           chunks,
		FileName:         path,
		RootHash:         rootHash.Sum(nil),
		ChunkSizeInBytes: DefaultChunkSize,
		FileSizeInBytes:  fileSizeInBytes,
		chunkComplete:    make([]bool, len(chunks)),
	}, nil
}

// GetChunkBytes takes in a chunk identifier and returns the bytes associated with that chunk
// it does not attempt to validate the chunk Hash.
func (m *Manifest) GetChunkBytes(id uint64) ([]byte, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if id >= uint64(len(m.Chunks)) {
		return nil, errors.New("chunk not found")
	}

	if err := m.getFileHandle(); err != nil {
		return nil, err
	}

	// Seek to Chunk
	offset, err := m.openFd.Seek(int64(id*m.ChunkSizeInBytes), 0)
	if (uint64(offset) != id*m.ChunkSizeInBytes) || err != nil {
		return nil, errors.New("chunk not found")
	}

	// Read chunk into memory and return...
	reader := bufio.NewReader(m.openFd)
	buf := make([]byte, m.ChunkSizeInBytes)
	n, err := reader.Read(buf)
	if err != nil {
		if err != io.EOF {
			return nil, err
		}
	}
	return buf[0:n], nil
}

// LoadManifest reads in a json serialized Manifest from a file
func LoadManifest(filename string) (*Manifest, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	manifest := new(Manifest)
	err = json.Unmarshal(bytes, manifest)
	if err != nil {
		return nil, err
	}
	manifest.chunkComplete = make([]bool, len(manifest.Chunks))
	return manifest, nil
}

// VerifyFile attempts to calculate the rootHash of a file and compare it to the expected rootHash stored in the
// manifest
func (m *Manifest) VerifyFile() error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if err := m.getFileHandle(); err != nil {
		return err
	}

	offset, err := m.openFd.Seek(0, 0)
	if offset != 0 || err != nil {
		return errors.New("chunk not found")
	}

	rootHash := sha512.New()
	reader := bufio.NewReader(m.openFd)
	buf := make([]byte, m.ChunkSizeInBytes)
	for {
		n, err := reader.Read(buf)
		rootHash.Write(buf[0:n])
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
	}

	calculatedRootHash := rootHash.Sum(nil)
	if subtle.ConstantTimeCompare(m.RootHash, calculatedRootHash) != 1 {
		return fmt.Errorf("hashes do not match %x %x", m.RootHash, calculatedRootHash)
	}
	return nil
}

// StoreChunk takes in a chunk id and contents, verifies the chunk has the expected hash and if so store the contents
// in the file.
func (m *Manifest) StoreChunk(id uint64, contents []byte) (uint64, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	// Check the chunk id
	if id >= uint64(len(m.Chunks)) {
		return 0, errors.New("invalid chunk id")
	}

	// Validate the chunk hash
	hash := sha256.New()
	hash.Write(contents)
	chunkHash := hash.Sum(nil)

	if subtle.ConstantTimeCompare(chunkHash, m.Chunks[id]) != 1 {
		return 0, fmt.Errorf("invalid chunk hash %x %x", chunkHash, m.Chunks[id])
	}

	if err := m.getFileHandle(); err != nil {
		return 0, err
	}

	offset, err := m.openFd.Seek(int64(id*m.ChunkSizeInBytes), 0)
	if (uint64(offset) != id*m.ChunkSizeInBytes) || err != nil {
		return 0, errors.New("chunk not found")
	}

	// Write the contents of the chunk to the file
	_, err = m.openFd.Write(contents)

	if err == nil && !m.chunkComplete[id] {
		m.chunkComplete[id] = true
		m.progress++
	}

	return m.progress, err
}

// private function to set the internal file handle
func (m *Manifest) getFileHandle() error {
	// Seek to the chunk in the file
	if m.openFd == nil {
		useFileName := m.FileName
		if m.TempFileName != "" {
			useFileName = m.TempFileName
		}
		fd, err := os.OpenFile(useFileName, os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		m.openFd = fd
	}
	return nil
}

// GetChunkRequest returns an uncompressed list of Chunks needed to complete the file described in the manifest
func (m *Manifest) GetChunkRequest() ChunkSpec {
	return CreateChunkSpec(m.chunkComplete)
}

// PrepareDownload creates an empty file of the expected size of the file described by the manifest
// If the file already exists it assume it is the correct file and that it is resuming from when it left off.
func (m *Manifest) PrepareDownload() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.chunkComplete = make([]bool, len(m.Chunks))

	if info, err := os.Stat(m.FileName); os.IsNotExist(err) {
		useFileName := m.FileName
		if m.TempFileName != "" {
			useFileName = m.TempFileName
		}

		fd, err := os.Create(useFileName)
		if err != nil {
			return err
		}
		m.openFd = fd

		writer := bufio.NewWriter(m.openFd)
		buf := make([]byte, m.ChunkSizeInBytes)
		for chunk := 0; chunk < len(m.Chunks)-1; chunk++ {
			_, err := writer.Write(buf)
			if err != nil {
				return err
			}
		}

		lastChunkSize := m.FileSizeInBytes % m.ChunkSizeInBytes
		if lastChunkSize > 0 {
			buf = make([]byte, lastChunkSize)
			_, err := writer.Write(buf)
			if err != nil {
				return err
			}
		}
		writer.Flush()
	} else {
		if err != nil {
			return err
		}

		if uint64(info.Size()) != m.FileSizeInBytes {
			return fmt.Errorf("file exists but is the wrong size")
		}

		if err := m.getFileHandle(); err != nil {
			return err
		}

		// Calculate Progress
		reader := bufio.NewReader(m.openFd)
		buf := make([]byte, m.ChunkSizeInBytes)
		chunkI := 0
		for {
			n, err := reader.Read(buf)
			if err != nil {
				if err != io.EOF {
					return err
				}
				break
			}
			hash := sha512.New()
			hash.Write(buf[0:n])
			chunkHash := hash.Sum(nil)
			m.progress = 0
			if subtle.ConstantTimeCompare(chunkHash, m.Chunks[chunkI]) == 1 {
				m.chunkComplete[chunkI] = true
				m.progress++
			}
			chunkI++
		}
	}
	return nil
}

// Close closes the underlying file descriptor
func (m *Manifest) Close() {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.openFd != nil {
		m.openFd.Close()
	}
}

// Save writes a JSON encoded byte array version of the manifest to path
func (m *Manifest) Save(path string) error {
	return os.WriteFile(path, m.Serialize(), 0600)
}

// Serialize returns the manifest as a JSON encoded byte array
func (m *Manifest) Serialize() []byte {
	data, _ := json.Marshal(m)
	return data
}
