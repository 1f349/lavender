package server

import (
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/logger"
	"net/http"
)

// DbTx wraps a database transaction with http error messages and a simple action
// function. If the action function returns an error the transaction will be
// rolled back. If there is no error then the transaction is committed.
func (h *HttpServer) DbTx(rw http.ResponseWriter, action func(tx *database.Tx) error) bool {
	tx, err := h.db.Begin()
	if err != nil {
		http.Error(rw, "Failed to begin database transaction", http.StatusInternalServerError)
		return true
	}
	defer tx.Rollback()

	err = action(tx)
	if err != nil {
		http.Error(rw, "Database error", http.StatusInternalServerError)
		logger.Logger.Warn("Database action error", "er", err)
		return true
	}
	err = tx.Commit()
	if err != nil {
		http.Error(rw, "Database error", http.StatusInternalServerError)
		logger.Logger.Warn("Database commit error", "err", err)
	}

	return false
}

func (h *HttpServer) DbTxRaw(action func(tx *database.Tx) error) bool {
	return h.DbTx(&fakeRW{}, action)
}

type fakeRW struct{}

func (f *fakeRW) Header() http.Header         { return http.Header{} }
func (f *fakeRW) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeRW) WriteHeader(statusCode int)  {}
