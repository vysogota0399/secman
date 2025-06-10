package blobs

import (
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/server"
)

func NewTestBackend(t *testing.T) (*Backend, *server.MockBarrierStorage, *server.MockILogicalStorage) {
	lg := server.NewLogger(t)
	cnt := gomock.NewController(t)
	barrier := server.NewMockBarrierStorage(cnt)
	logicalStorage := server.NewMockILogicalStorage(cnt)

	blobRepo := &Repository{
		storage: logicalStorage,
		lg:      lg,
	}
	metadataRepo := NewMetadataRepository(barrier)
	s3 := NewMockS3(cnt)
	be := NewBackend(lg, blobRepo, metadataRepo, s3)

	return be, barrier, logicalStorage
}
