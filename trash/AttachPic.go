package NCMDump

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
)

type (
	BlockType   int
	PictureType int
)

const (
	BlockTypeStreamInfo BlockType = iota
	BlockTypePadding
	BlockTypeApplication
	BlockTypeSeekTable
	BlockTypeVorbisComment
	BlockTypeCueSheet
	BlockTypePicture
	BlockTypeReserved
	BlockTypeInvalid = 127
)

const (
	PictureTypeOthers PictureType = iota
	PictureType32x32PixelsFileIcon
	PictureTypeOtherFileIcon
	PictureTypeCoverFront
	PictureTypeCoverBack
	PictureTypeLeafletPage
	PictureTypeMedia
	PictureTypeLeadArtist
	PictureTypeArtist
	PictureTypeConductor
	PictureTypeBandOrchestra
	PictureTypeComposer
	PictureTypeLyricist
	PictureTypeRecordingLocation
	PictureTypeDuringRecording
	PictureTypeDuringPerformance
	PictureTypeMovieVideoScreenCapture
	PictureTypeBrightColouredFish
	PictureTypeIllustration
	PictureTypeBandArtistLogotype
	PictureTypePublisherStudioLogotype
)

// MetadataBlockHeader 表示每个Metadata Block的头部信息
type MetadataBlockHeader struct {
	IsLastBlock bool   // 是否是最后一个metadata block
	BlockType   byte   // Block类型
	Length      uint32 // Block的长度，不包括header
}

type Picture struct {
	Type              uint32
	MimeTypeLength    uint32
	MimeType          string
	DescriptorLength  uint32
	Descriptor        string
	Width             uint32
	Height            uint32
	ColorDepth        uint32
	IndexedColorCount uint32
	ImageDataLength   uint32
	ImageData         []byte
}

const (
	PNGMime     = "image/png"
	PNGMimeLen  = len(PNGMime)
	JPEGMine    = "image/jpeg"
	JPEGMineLen = len(JPEGMine)
)

func AttachPic(imageData []byte) (blockData []byte, err error) {
	pic, err := NewAttachPic(imageData)
	if err != nil {
		return nil, err
	}
	picData, err := pic.Build()
	if err != nil {
		return nil, err
	}
	block, err := NewMetadataBlockHeader(picData, BlockTypePicture, false)
	if err != nil {
		return nil, err
	}

	return block.Build(), nil
}

func NewMetadataBlockHeader(blockData []byte, blockType BlockType, isLastBlock bool) (*MetadataBlockHeader, error) {
	if len(blockData) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	return &MetadataBlockHeader{
		IsLastBlock: isLastBlock,
		BlockType:   byte(blockType),
		Length:      uint32(len(blockData)),
	}, nil
}

func (header *MetadataBlockHeader) Build() []byte {
	headerBytes := make([]byte, 4)
	headerBytes[0] = header.BlockType
	if header.IsLastBlock {
		headerBytes[0] |= 0x80 // 设置最高位为1
	}
	headerBytes[1] = byte((header.Length >> 16) & 0xFF)
	headerBytes[2] = byte((header.Length >> 8) & 0xFF)
	headerBytes[3] = byte(header.Length & 0xFF)

	return headerBytes
}

func NewAttachPic(imageData []byte) (*Picture, error) {
	if len(imageData) < 8 {
		return nil, fmt.Errorf("not a valid image")
	}

	p := &Picture{
		Type: uint32(PictureTypeCoverFront),
		// DescriptorLength: 0,
		// Descriptor: "",
		ColorDepth: 24,
		// IndexedColorCount: 0,
		ImageDataLength: uint32(len(imageData)),
		ImageData:       imageData,
	}

	r := bytes.NewReader(imageData)
	imageConfig, _, err := image.DecodeConfig(r)
	if err != nil {
		return nil, err
	}
	p.Width = uint32(imageConfig.Width)
	p.Height = uint32(imageConfig.Height)

	switch {
	case bytes.Equal(imageData[0:8], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}):
		p.MimeType = PNGMime
		p.MimeTypeLength = uint32(PNGMimeLen)
	case bytes.Equal(imageData[0:2], []byte{0xFF, 0xD8}):
		p.MimeType = JPEGMine
		p.MimeTypeLength = uint32(JPEGMineLen)
	default:
		return nil, fmt.Errorf("not a valid mime type")
	}

	return p, nil
}

func (p *Picture) Build() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, *p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
