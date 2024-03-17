package NCMDump

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"
)

type Dumper struct {
	CoreKey, MetaKey                                 string
	CoreCipher, MetaCipher                           cipher.Block
	outputDir                                        string
	isCoverOutput, isCoverEmbed, highDefinitionCover bool
}

type MetaData struct {
	MusicId       string     `json:"musicId"`
	MusicName     string     `json:"musicName"`
	Artist        [][]string `json:"artist"`
	AlbumId       string     `json:"albumId"`
	Album         string     `json:"album"`
	AlbumPicDocId string     `json:"albumPicDocId"`
	AlbumPic      string     `json:"albumPic"`
	Bitrate       int        `json:"bitrate"`
	Mp3DocId      string     `json:"mp3DocId"`
	Duration      int        `json:"duration"`
	MvId          string     `json:"mvId"`
	Alias         []string   `json:"alias"`
	TransNames    []string   `json:"transNames"`
	Format        string     `json:"format"`
	Fee           int        `json:"fee"`
	VolumeDelta   float64    `json:"volumeDelta"`
	Privilege     struct {
		Flag int `json:"flag"`
	} `json:"privilege"`
}

const (
	ncmHeader = "4354454e4644414d"
)

var (
	header, _ = hex.DecodeString(ncmHeader)
)

func New() *Dumper {
	return &Dumper{}
}

func (d *Dumper) SetKeys(coreKey, metaKey string) *Dumper {
	go func() {
		if err := d.setCoreKey(coreKey); err != nil {
			panic(err)
		}
	}()
	go func() {
		if err := d.setMetaKey(metaKey); err != nil {
			panic(err)
		}
	}()
	return d
}

func (d *Dumper) setCoreKey(k string) (err error) {
	ck, err := hex.DecodeString(k)
	if err != nil {
		return
	}
	coreCipher, err := aes.NewCipher(ck)
	if err != nil {
		return
	}
	if !testCoreKey(coreCipher) {
		return fmt.Errorf("not the right core key")
	}
	d.CoreCipher = coreCipher
	return
}

func (d *Dumper) setMetaKey(k string) (err error) {
	mk, err := hex.DecodeString(k)
	if err != nil {
		return
	}
	metaCipher, err := aes.NewCipher(mk)
	if err != nil {
		return
	}
	if !testMetaKey(metaCipher) {
		return fmt.Errorf("not the right meta key")
	}
	d.MetaCipher = metaCipher
	return
}

func (d *Dumper) SetOutputDir(dir string) *Dumper {
	d.outputDir = filepath.Join(dir)
	err := os.MkdirAll(d.outputDir, 0o755)
	if err != nil {
		panic(err)
	}
	return d
}

func (d *Dumper) SetCoverOutput(isOutput, isEmbed, HD bool) *Dumper {
	d.isCoverOutput = isOutput
	d.isCoverEmbed = isEmbed
	d.highDefinitionCover = HD
	return d
}

func testCoreKey(block cipher.Block) bool {
	// check
	return true
}

func testMetaKey(block cipher.Block) bool {
	// check
	return true
}

func unpad(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}

func decrypt(cb cipher.Block, input []byte) (output []byte, err error) {
	bs := cb.BlockSize()
	inputLen := len(input)
	if inputLen%bs != 0 {
		return nil, fmt.Errorf("input is not a multiple of the block size")
	}

	output = make([]byte, inputLen)
	for i := 0; i < inputLen; i += bs {
		cb.Decrypt(output[i:i+bs], input[i:i+bs])
	}

	return
}

func checkHeader(ncmHeader []byte) bool {
	return bytes.Equal(ncmHeader, header)
}

func (d *Dumper) decryptCore(raw []byte) (output []byte, err error) {
	for i := range len(raw) {
		raw[i] ^= 0x64
	}

	output, err = decrypt(d.CoreCipher, raw)
	if err != nil {
		return nil, err
	}

	output = unpad(output)[17:]

	return
}

func genKeyBox(keyData []byte) (keyBox []byte) {
	keyBox = make([]byte, 256)
	for i := range 256 {
		keyBox[i] = byte(i)
	}

	keyDataLen := len(keyData)
	c, lastByte, keyOffset := 0, 0, 0
	for i := range 256 {
		swap := keyBox[i]
		c = (int(swap) + lastByte + int(keyData[keyOffset])) & 0xff
		keyOffset++
		if keyOffset >= keyDataLen {
			keyOffset = 0
		}
		keyBox[i] = keyBox[c]
		keyBox[c] = swap
		lastByte = c
	}

	return
}

func (d *Dumper) decryptMeta(raw []byte) (output []byte, err error) {
	for i := range len(raw) {
		raw[i] ^= 0x63
	}

	output, err = base64.StdEncoding.DecodeString(b2s(raw[22:]))
	if err != nil {
		return nil, err
	}

	output, err = decrypt(d.MetaCipher, output)
	if err != nil {
		return nil, err
	}

	output = unpad(output)[6:] // remove "music:"

	return
}

func unmarshalMeta(data []byte) (meta MetaData, err error) {
	err = json.Unmarshal(data, &meta)
	return
}

func decryptMusic(data, keyBox []byte) {
	for i := range len(data) {
		i++
		j := i & 0xff
		(data)[i-1] ^=
			(keyBox)[((keyBox)[j]+(keyBox)[(int((keyBox)[j])+j)&0xff])&0xff]
	}
}

func (d *Dumper) Dump(src, dst *bytes.Buffer) (metaData *MetaData, err error) {
	ncmHeader := make([]byte, 8)
	src.Read(ncmHeader) // 43 54 45 4e 46 44 41 4d
	if !checkHeader(ncmHeader) {
		return nil, fmt.Errorf("unmatched header, not a NCM file")
	}

	src.Next(2)

	keyDataLengthRaw := make([]byte, 4)
	src.Read(keyDataLengthRaw)
	keyDataLength := int(binary.LittleEndian.Uint32(keyDataLengthRaw))
	keyDataRaw := make([]byte, keyDataLength)
	src.Read(keyDataRaw)
	keyData, err := d.decryptCore(keyDataRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key data: %v", err)
	}
	keyBox := genKeyBox(keyData)

	metaDataLengthRaw := make([]byte, 4)
	src.Read(metaDataLengthRaw)
	metaDataLength := int(binary.LittleEndian.Uint32(metaDataLengthRaw))
	metaDataRaw := make([]byte, metaDataLength)
	src.Read(metaDataRaw)
	metaDataBytes, err := d.decryptMeta(metaDataRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt meta data: %v", err)
	}
	md, err := unmarshalMeta(metaDataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal meta data: %v", err)
	}
	metaData = &md

	c32Raw := make([]byte, 4)
	src.Read(c32Raw)

	src.Next(5)

	coverLengthRaw := make([]byte, 4)
	src.Read(coverLengthRaw)
	coverLength := int(binary.LittleEndian.Uint32(coverLengthRaw))
	coverData := make([]byte, coverLength)
	src.Read(coverData)

	if d.highDefinitionCover {
		HDCoverUrl := metaData.AlbumPic
		resp, err := http.Get(HDCoverUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to download HD cover: %v", err)
		}
		defer resp.Body.Close()
		coverData, err = io.ReadAll(resp.Body)
	}

	music := src.Bytes()
	decryptMusic(music, keyBox)

	if len(coverData) != 0 && d.isCoverEmbed { // 嵌入失败中断导出
		music, err = ffmpegAttachPic(music, coverData, metaData.Format)
		if err != nil {
			return nil, fmt.Errorf("failed to embed cover: %v", err)
		}
	}

	_, err = dst.Write(music)
	if err != nil {
		return nil, fmt.Errorf("failed to write output: %v", err)
	}

	if len(coverData) != 0 && d.isCoverOutput { // 非嵌入不影响音频导出，但方法还是会返回错误
		if err = d.outputCoverLocal(coverData, metaData.Artist[0][0]+" - "+metaData.MusicName); err != nil {
			return nil, err
		}
	}

	return
}

func (d *Dumper) DumpFile(inputPath string) (err error) {
	musicName := strings.Split(filepath.Base(inputPath), ".ncm")[0]

	ncmF, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("(%v) failed to open file: %v",
			inputPath, err)
	}
	defer ncmF.Close()

	ncmHeader := make([]byte, 8)
	ncmF.Read(ncmHeader) // 43 54 45 4e 46 44 41 4d
	if !checkHeader(ncmHeader) {
		return fmt.Errorf("(%v) unmatched header, not a NCM file",
			inputPath)
	}

	ncmF.Seek(2, 1)

	keyDataLengthRaw := make([]byte, 4)
	ncmF.Read(keyDataLengthRaw)
	keyDataLength := binary.LittleEndian.Uint32(keyDataLengthRaw)
	keyDataRaw := make([]byte, keyDataLength)
	ncmF.Read(keyDataRaw)
	keyData, err := d.decryptCore(keyDataRaw)
	if err != nil {
		return fmt.Errorf("(%v) failed to decrypt key data: %v",
			inputPath, err)
	}
	keyBox := genKeyBox(keyData)

	metaDataLengthRaw := make([]byte, 4)
	ncmF.Read(metaDataLengthRaw)
	metaDataLength := binary.LittleEndian.Uint32(metaDataLengthRaw)
	metaDataRaw := make([]byte, metaDataLength)
	ncmF.Read(metaDataRaw)
	metaDataBytes, err := d.decryptMeta(metaDataRaw)
	if err != nil {
		return fmt.Errorf("(%v) failed to decrypt meta data: %v",
			inputPath, err)
	}
	metaData, err := unmarshalMeta(metaDataBytes)
	if err != nil {
		return fmt.Errorf("(%v) failed to unmarshal meta data: %v",
			inputPath, err)
	}

	c32Raw := make([]byte, 4)
	ncmF.Read(c32Raw)
	// c32 := int(binary.LittleEndian.Uint32(c32Raw))

	ncmF.Seek(5, 1)

	coverLengthRaw := make([]byte, 4)
	ncmF.Read(coverLengthRaw)
	coverLength := int(binary.LittleEndian.Uint32(coverLengthRaw))
	coverData := make([]byte, coverLength)
	ncmF.Read(coverData)

	if d.highDefinitionCover {
		HDCoverUrl := metaData.AlbumPic
		resp, err := http.Get(HDCoverUrl)
		if err != nil {
			return fmt.Errorf("failed to download HD cover: %v", err)
		}
		defer resp.Body.Close()
		coverData, err = io.ReadAll(resp.Body)
	}

	var outputDir string
	if d.outputDir == "" {
		outputDir = filepath.Dir(inputPath)
	} else {
		outputDir = d.outputDir
	}
	fileName := musicName + "." + metaData.Format
	outputPath := filepath.Join(outputDir, fileName)
	_, err = os.Stat(outputPath)
	if !os.IsNotExist(err) { // exist
		return fmt.Errorf("(%v) found existed output, skip",
			fileName)
	}
	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("(%v) failed to create file: %v",
			fileName, err)
	}
	defer output.Close()
	music, err := io.ReadAll(ncmF)
	if err != nil {
		return fmt.Errorf("(%v) failed to read music data: %v",
			fileName, err)
	}
	decryptMusic(music, keyBox)

	if len(coverData) != 0 && d.isCoverEmbed { // 嵌入失败中断导出
		music, err = ffmpegAttachPic(music, coverData, metaData.Format)
		if err != nil {
			return fmt.Errorf("(%v) failed to embed cover: %v",
				fileName, err)
		}
	}

	_, err = output.Write(music)
	if err != nil {
		return fmt.Errorf("(%v) failed to write output: %v",
			fileName, err)
	}

	if len(coverData) != 0 && d.isCoverOutput { // 非嵌入不影响音频导出
		if err = d.outputCoverLocal(coverData, musicName); err != nil {
			return err
		}
	}

	return
}

func (d *Dumper) outputCoverLocal(image []byte, musicName string) error {
	coverPath := filepath.Join(d.outputDir, musicName+
		func() string {
			switch {
			case bytes.Equal(image[0:8],
				[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}):
				return ".png"
			case bytes.Equal(image[0:2],
				[]byte{0xFF, 0xD8}):
				return ".jpg"
			default:
				return ""
			}
		}())
	cover, err := os.Create(coverPath)
	defer cover.Close()
	if err != nil {
		return fmt.Errorf("(%v) failed to output cover: %v",
			coverPath, err)
	}
	_, err = cover.Write(image)
	if err != nil {
		return fmt.Errorf("(%v) failed to write cover data: %v",
			coverPath, err)
	}
	return nil

}

func ffmpegAvailable() bool {
	_, err := exec.LookPath("ffmpeg")
	return err == nil
}

func ffmpegAttachPic(media, image []byte, mediaFormat string) ([]byte, error) {
	if !ffmpegAvailable() {
		return nil, fmt.Errorf("ffmpeg is not available")
	}

	err := os.MkdirAll("tmp", 0o755)
	if err != nil {
		return nil, err
	}
	coverTemp, err := os.CreateTemp("tmp", "cover")
	if err != nil {
		return nil, err
	}
	_, err = coverTemp.Write(image)
	if err != nil {
		return nil, err
	}
	coverTemp.Close()
	defer os.Remove(coverTemp.Name())

	cmd := exec.Command("ffmpeg",
		"-i", "pipe:0", "-i", coverTemp.Name(),
		"-map", "0", "-map", "1", "-c", "copy",
		"-disposition:v:0", "attached_pic", "-f", mediaFormat, "pipe:1")
	cmd.Stdin = bytes.NewReader(media)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func s2b(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
