SQL_SRC_DIR := database
SQL_FILES := $(wildcard $(SQL_SRC_DIR)/{migrations,queries}/*.sql)

.PHONY: all sqlc astro build

all: sqlc astro
	go generate ./...

sqlc: $(SQL_FILES)
	sqlc generate

astro:
	cd web && yarn build

build: sqlc astro
	go build ./cmd/lavender
