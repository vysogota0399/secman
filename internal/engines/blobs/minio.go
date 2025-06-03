package blobs

import (
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/vysogota0399/secman/internal/logging"
)

var _ S3 = &Minio{}

type Minio struct {
	lg     *logging.ZapLogger
	client *minio.Client
	bucket string
}

func NewMinio(lg *logging.ZapLogger) *Minio {
	return &Minio{lg: lg}
}

func (s3 *Minio) Start(ba *Backend) error {
	secure := ba.blobParams.S3SSL == "true"

	client, err := minio.New(ba.blobParams.S3URL, &minio.Options{
		Creds:  credentials.NewStaticV4(ba.blobParams.S3User, ba.blobParams.S3Pass, ""),
		Secure: secure,
	})
	if err != nil {
		return fmt.Errorf("minio: failed to create client %w", err)
	}

	s3.client = client

	exists, err := s3.client.BucketExists(context.Background(), ba.blobParams.S3Bucket)
	if err != nil {
		return fmt.Errorf("minio: failed to check if bucket exists %s %w", ba.blobParams.S3Bucket, err)
	}

	if !exists {
		if err := s3.createBucket(context.Background(), ba.blobParams.S3Bucket); err != nil {
			return fmt.Errorf("minio: failed to create bucket %s %w", ba.blobParams.S3Bucket, err)
		}
	}

	s3.bucket = ba.blobParams.S3Bucket
	return nil
}

type Blob struct {
	Key   string
	Value io.ReadCloser
	Size  int64
}

func (m *Minio) Create(ctx context.Context, blob *Blob) error {
	_, err := m.client.PutObject(
		ctx,
		m.bucket,
		blob.Key,
		blob.Value,
		blob.Size,
		minio.PutObjectOptions{},
	)
	if err != nil {
		return fmt.Errorf("minio: failed to create object %s %w", blob.Key, err)
	}

	return nil
}

func (m *Minio) Get(ctx context.Context, key string) (*Blob, error) {
	obj, err := m.client.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("minio: failed to get object %s %w", key, err)
	}

	stat, err := obj.Stat()
	if err != nil {
		return nil, fmt.Errorf("minio: failed to get object stat %s %w", key, err)
	}

	return &Blob{
		Key:   key,
		Value: obj,
		Size:  stat.Size,
	}, nil
}

func (m *Minio) Delete(ctx context.Context, key string) error {
	return m.client.RemoveObject(ctx, m.bucket, key, minio.RemoveObjectOptions{})
}

func (m *Minio) createBucket(ctx context.Context, bucket string) error {
	return m.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
}
