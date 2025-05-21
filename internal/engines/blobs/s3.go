package blobs

import "context"

type S3 interface {
	Create(ctx context.Context, blob *Blob) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}
