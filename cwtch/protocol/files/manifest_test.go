package files

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"
)

func TestManifest(t *testing.T) {
	manifest, err := CreateManifest("testdata/example.txt")
	if err != nil {
		t.Fatalf("manifest create error: %v", err)
	}

	if len(manifest.Chunks) != 1 {
		t.Fatalf("manifest had unepxected Chunks : %v", manifest.Chunks)
	}

	if manifest.FileSizeInBytes != 12 {
		t.Fatalf("manifest had unepxected length : %v", manifest.FileSizeInBytes)
	}

	if hex.EncodeToString(manifest.RootHash) != "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8" {
		t.Fatalf("manifest had incorrect root Hash : %v", manifest.RootHash)
	}

	t.Logf("%v", manifest)

	// Try to read the chunk
	_, err = manifest.GetChunkBytes(1)
	if err == nil {
		t.Fatalf("chunk fetch should have thrown an error")
	}

	_, err = manifest.GetChunkBytes(0)
	if err != nil {
		t.Fatalf("chunk fetch error: %v", err)
	}
	_, err = manifest.GetChunkBytes(0)
	if err != nil {
		t.Fatalf("chunk fetch error: %v", err)
	}

	_, err = manifest.GetChunkBytes(0)
	if err != nil {
		t.Fatalf("chunk fetch error: %v", err)
	}

	json, _ := json.Marshal(manifest)
	t.Logf("%s", json)

}

func TestManifestLarge(t *testing.T) {
	manifest, err := CreateManifest("testdata/cwtch.png")
	if err != nil {
		t.Fatalf("manifest create error: %v", err)
	}

	if len(manifest.Chunks) != int(math.Ceil(float64(51791)/DefaultChunkSize)) {
		t.Fatalf("manifest had unexpected Chunks : %v", manifest.Chunks)
	}

	if manifest.FileSizeInBytes != 51791 {
		t.Fatalf("manifest had unepxected length : %v", manifest.FileSizeInBytes)
	}

	if hex.EncodeToString(manifest.RootHash) != "8f0ed73bbb30db45b6a740b1251cae02945f48e4f991464d5f3607685c45dcd136a325dab2e5f6429ce2b715e602b20b5b16bf7438fb6235fefe912adcedb5fd" {
		t.Fatalf("manifest had incorrect root Hash : %v", manifest.RootHash)
	}

	t.Logf("%v", len(manifest.Chunks))

	json, _ := json.Marshal(manifest)
	t.Logf("%v %s", len(json), json)

	// Pretend we downloaded the manifest
	os.WriteFile("testdata/cwtch.png.manifest", json, 0600)

	// Load the manifest from a file
	cwtchPngManifest, err := LoadManifest("testdata/cwtch.png.manifest")
	if err != nil {
		t.Fatalf("manifest create error: %v", err)
	}
	defer cwtchPngManifest.Close()
	t.Logf("%v", cwtchPngManifest)

	// Test verifying the hash
	if cwtchPngManifest.VerifyFile() != nil {
		t.Fatalf("hashes do not validate error: %v", err)
	}

	// Prepare Download
	cwtchPngOutManifest, _ := LoadManifest("testdata/cwtch.png.manifest")
	cwtchPngOutManifest.FileName = "testdata/cwtch.out.png"

	defer cwtchPngOutManifest.Close()
	err = cwtchPngOutManifest.PrepareDownload()
	if err != nil {
		t.Fatalf("could not prepare download %v", err)
	}

	for i := 0; i < len(cwtchPngManifest.Chunks); i++ {

		t.Logf("Sending Chunk %v %x from %v", i, cwtchPngManifest.Chunks[i], cwtchPngManifest.FileName)

		contents, err := cwtchPngManifest.GetChunkBytes(uint64(i))

		if err != nil {
			t.Fatalf("could not get chunk %v %v", i, err)
		}
		t.Logf("Progress: %v", cwtchPngOutManifest.chunkComplete)
		_, err = cwtchPngOutManifest.StoreChunk(uint64(i), contents)
		if err != nil {
			t.Fatalf("could not store chunk %v %v", i, err)
		}

		// Attempt to store the chunk in an invalid position...
		_, err = cwtchPngOutManifest.StoreChunk(uint64(i+1), contents)
		if err == nil {
			t.Fatalf("incorrect chunk store")
		}

	}

	// Attempt to store an invalid chunk...should trigger an error
	_, err = cwtchPngOutManifest.StoreChunk(uint64(len(cwtchPngManifest.Chunks)), []byte{0xff})
	if err == nil {
		t.Fatalf("incorrect chunk store")
	}

	err = cwtchPngOutManifest.VerifyFile()
	if err != nil {
		t.Fatalf("could not verify file %v", err)
	}

	// Test that changing the hash throws an error
	cwtchPngManifest.RootHash[3] = 0xFF
	if cwtchPngManifest.VerifyFile() == nil {
		t.Fatalf("hashes should not validate error")
	}

}
