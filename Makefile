SQL_SRC_DIR := database
SQL_FILES := $(wildcard $(SQL_SRC_DIR)/{migrations,queries}/*.sql)

all: sqlc

sqlc: $(SQL_FILES)
	sqlc generate

build: sqlc
	go build ./cmd/lavender
