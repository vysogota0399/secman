package blobs

import (
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/secman"
)

func NewTestBackend(t *testing.T) (*Backend, *secman.MockBarrierStorage, *secman.MockILogicalStorage) {
	lg := secman.NewLogger(t)
	cnt := gomock.NewController(t)
	barrier := secman.NewMockBarrierStorage(cnt)
	logicalStorage := secman.NewMockILogicalStorage(cnt)

	blobRepo := &Repository{
		storage: logicalStorage,
		lg:      lg,
	}
	metadataRepo := NewMetadataRepository(barrier)
	s3 := NewMockS3(cnt)
	be := NewBackend(lg, blobRepo, metadataRepo, s3)

	return be, barrier, logicalStorage
}
