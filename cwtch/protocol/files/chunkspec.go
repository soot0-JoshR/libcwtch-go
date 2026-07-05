package files

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ChunkSpec is a wrapper around an uncompressed array of chunk identifiers
type ChunkSpec []uint64

// CreateChunkSpec given a full list of chunks with their downloaded status (true for downloaded, false otherwise)
// derives a list of identifiers of chunks that have not been downloaded yet
func CreateChunkSpec(progress []bool) ChunkSpec {
	var chunks ChunkSpec
	for i, p := range progress {
		if !p {
			chunks = append(chunks, uint64(i))
		}
	}
	return chunks
}

// Deserialize takes in a compressed chunk spec and returns an uncompressed ChunkSpec or an error
// if the serialized chunk spec has format errors
func Deserialize(serialized string) (*ChunkSpec, error) {

	var chunkSpec ChunkSpec

	if len(serialized) == 0 {
		return &chunkSpec, nil
	}

	ranges := strings.Split(serialized, ",")
	for _, r := range ranges {
		parts := strings.Split(r, ":")
		if len(parts) == 1 {
			single, err := strconv.Atoi(r)
			if err != nil {
				return nil, errors.New("invalid chunk spec")
			}
			chunkSpec = append(chunkSpec, uint64(single))
		} else if len(parts) == 2 {
			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil {
				return nil, errors.New("invalid chunk spec")
			}
			for i := start; i <= end; i++ {
				chunkSpec = append(chunkSpec, uint64(i))
			}
		} else {
			return nil, errors.New("invalid chunk spec")
		}
	}
	return &chunkSpec, nil
}

// Serialize compresses the ChunkSpec into a list of inclusive ranges e.g. 1,2,3,5,6,7 becomes "1:3,5:7"
func (cs ChunkSpec) Serialize() string {
	result := ""

	i := 0

	for {
		if i >= len(cs) {
			break
		}
		j := i + 1
		for ; j < len(cs) && cs[j] == cs[j-1]+1; j++ {
		}

		if result != "" {
			result += ","
		}

		if j == i+1 {
			result += fmt.Sprintf("%d", cs[i])
		} else {
			result += fmt.Sprintf("%d:%d", cs[i], cs[j-1])
		}
		i = j
	}

	return result
}
