package constants

// FileSharingExperiment Allows file sharing
const FileSharingExperiment = "filesharing"

// ImagePreviewsExperiment Causes images (up to ImagePreviewMaxSizeInBytes, from accepted contacts) to auto-dl and preview
// requires FileSharingExperiment to be enabled
const ImagePreviewsExperiment = "filesharing-images"

// ImagePreviewMaxSizeInBytes Files up to this size will be autodownloaded using ImagePreviewsExperiment
const ImagePreviewMaxSizeInBytes = 20971520

// AutoDLFileExts Files with these extensions will be autodownloaded using ImagePreviewsExperiment
var AutoDLFileExts = [...]string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
