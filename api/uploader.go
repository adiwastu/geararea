// srv/geararea/api/uploader.go
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png" // Register PNG decoder
	"log"
	"mime/multipart"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/image/draw"
)

// Config: Load these from Environment Variables in production
var (
	r2AccountID = os.Getenv("R2_ACCOUNT_ID")
	r2AccessKey = os.Getenv("R2_ACCESS_KEY")
	r2SecretKey = os.Getenv("R2_SECRET_KEY")
	r2Bucket    = os.Getenv("R2_BUCKET_NAME")
	r2PublicURL = os.Getenv("R2_PUBLIC_URL") // e.g. https://pub-xxx.r2.dev
)

// Global S3 Client
var r2Client *s3.Client

func initUploader() {
	if r2AccountID == "" || r2AccessKey == "" || r2SecretKey == "" {
		log.Println("WARNING: R2 Credentials not set. Uploads will fail.")
		return
	}

	r2Endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", r2AccountID)

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(r2AccessKey, r2SecretKey, "")),
		config.WithRegion("auto"),
	)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	r2Client = s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(r2Endpoint)
	})

	log.Println("R2 Uploader initialized")
}

// UploadImage processes the file: decode -> resize -> encode JPEG -> upload to R2
func processAndUpload(file multipart.File, fileHeader *multipart.FileHeader) (string, error) {
	// 1. Decode (Supports PNG/JPEG)
	src, _, err := image.Decode(file)
	if err != nil {
		return "", fmt.Errorf("decode failed: %v", err)
	}

	// 2. Resize Logic (Max 1600px)
	const maxDim = 1600
	bounds := src.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	var dst image.Image
	if w > maxDim || h > maxDim {
		// Calculate new aspect ratio
		ratio := float64(w) / float64(h)
		newW, newH := 0, 0
		if w > h {
			newW = maxDim
			newH = int(float64(maxDim) / ratio)
		} else {
			newH = maxDim
			newW = int(float64(maxDim) * ratio)
		}

		// High Quality Resizing (CatmullRom)
		tmp := image.NewRGBA(image.Rect(0, 0, newW, newH))
		draw.CatmullRom.Scale(tmp, tmp.Bounds(), src, bounds, draw.Over, nil)
		dst = tmp
	} else {
		dst = src // No resize needed
	}

	// 3. Encode to JPEG (Quality 80)
	buf := new(bytes.Buffer)
	err = jpeg.Encode(buf, dst, &jpeg.Options{Quality: 80})
	if err != nil {
		return "", fmt.Errorf("encode failed: %v", err)
	}

	// 4. Generate Random Filename
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	filename := hex.EncodeToString(randBytes) + ".jpg"
	key := fmt.Sprintf("uploads/%s", filename) // Folder structure

	// 5. Upload to R2
	_, err = r2Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(r2Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(buf.Bytes()),
		ContentType: aws.String("image/jpeg"),
	})
	if err != nil {
		return "", fmt.Errorf("r2 upload failed: %v", err)
	}

	// 6. Return Public URL
	// If r2PublicURL is not set, we return the relative path
	if r2PublicURL == "" {
		return key, nil
	}
	return fmt.Sprintf("%s/%s", r2PublicURL, key), nil
}
