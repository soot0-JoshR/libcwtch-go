package utils

import "encoding/json"

// Image types we support
const (
	// TypeImageDistro is a reletive path to any of the distributed images in cwtch/ui in the assets folder
	TypeImageDistro = "distro"
	// TypeImageComposition will be an face image composed of a recipe of parts like faceType, eyeType, etc
	TypeImageComposition = "composition"
)

type image struct {
	Val string
	T   string
}

func NewImage(val, t string) *image {
	return &image{val, t}
}

func StringToImage(str string) (*image, error) {
	var img image
	err := json.Unmarshal([]byte(str), &img)
	if err != nil {
		return nil, err
	}
	return &img, nil
}

func ImageToString(img *image) string {
	bytes, _ := json.Marshal(img)
	return string(bytes)
}
