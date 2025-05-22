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

func NewMinio(lg *logging.ZapLogger, ba *Backend) (*Minio, error) {
	s3 := &Minio{lg: lg}

	cfg := ba.blobParams.Adapter
	client, err := minio.New(cfg.URL, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.User, cfg.Password, ""),
		Secure: cfg.SSL,
	})
	if err != nil {
		return nil, fmt.Errorf("minio: failed to create client %w", err)
	}

	s3.client = client

	exists, err := s3.client.BucketExists(context.Background(), cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("minio: failed to check if bucket exists %s %w", cfg.Bucket, err)
	}

	if !exists {
		if err := s3.createBucket(context.Background(), cfg.Bucket); err != nil {
			return nil, fmt.Errorf("minio: failed to create bucket %s %w", cfg.Bucket, err)
		}
	}

	s3.bucket = cfg.Bucket

	return s3, nil
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
